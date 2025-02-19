package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"text/template"
	"time"

	"github.com/gorilla/csrf"
	"github.com/jordan-wright/email"
	xmaps "golang.org/x/exp/maps"

	"github.com/andrew-d/homeauth/internal/buildtags"
	"github.com/andrew-d/homeauth/internal/db"
)

func (s *idpServer) queueEmail(e *db.PendingEmail) error {
	// Write to our pending emails list in the database.
	if err := s.db.Write(func(data *data) error {
		if data.PendingEmails == nil {
			data.PendingEmails = make(map[string]*db.PendingEmail)
		}

		id := randHex(32)
		data.PendingEmails[id] = &db.PendingEmail{
			ID:   id,
			To:   e.To,
			Text: e.Text,
			HTML: e.HTML,
		}
		return nil
	}); err != nil {
		return err
	}

	// Try to write something to the channel to wake up the email loop; if
	// we can't, it's because something else wrote there and the loop will
	// wake up imminently.
	select {
	case s.triggerEmailCh <- struct{}{}:
	default:
	}
	return nil
}

func (s *idpServer) runEmailLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	// Load something into the trigger channel to start the loop.
	select {
	case s.triggerEmailCh <- struct{}{}:
	default:
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.triggerEmailCh:
			if err := s.sendPendingEmails(ctx, time.Now()); err != nil {
				s.logger.Error("error sending pending emails", errAttr(err))
			}
		case now := <-ticker.C:
			if err := s.sendPendingEmails(ctx, now); err != nil {
				s.logger.Error("error sending pending emails", errAttr(err))
			}
		}
	}
}

func (s *idpServer) sendPendingEmails(ctx context.Context, now time.Time) error {
	// Start by loading our email configuration and all pending emails from
	// the database. We don't need to worry anything else reading these
	// concurrently, since there's only one thing (this function) sending emails.
	var (
		emailConfig *EmailConfig
		pending     []*db.PendingEmail
	)
	s.db.Read(func(data *data) {
		emailConfig = data.Config.Email
		pending = xmaps.Values(data.PendingEmails)
	})

	// If we have no pending emails, we're done.
	if len(pending) == 0 {
		return nil
	}

	// The "From" address is either explicitly set or the SMTP username.
	fromAddr := cmp.Or(emailConfig.FromAddress, emailConfig.SMTPUsername)

	// The subject is either a default or explicitly set.
	subject := fmt.Sprintf("Login to homeauth (%s)", s.serverHostname)
	subject = cmp.Or(emailConfig.Subject, subject)

	// Split the host and port from the address; we know this never fails
	// because initializeConfig checked.
	host, _, _ := net.SplitHostPort(emailConfig.SMTPServer)
	auth := smtp.PlainAuth(
		emailConfig.FromAddress,  // identity
		emailConfig.SMTPUsername, // user
		emailConfig.SMTPPassword, // password
		host,                     // host
	)

	var (
		errs      []error
		successes []string // of email IDs
	)
	for _, pendEmail := range pending {
		e := &email.Email{
			To:      []string{pendEmail.To},
			From:    fmt.Sprintf("homeauth <%s>", fromAddr),
			Subject: subject,
			Text:    []byte(pendEmail.Text),
			HTML:    []byte(pendEmail.HTML),
		}

		var err error
		if emailConfig.useTLS() {
			err = e.SendWithTLS(emailConfig.SMTPServer, auth, &tls.Config{
				ServerName: host,
			})
		} else if emailConfig.useStartTLS() {
			err = e.SendWithStartTLS(emailConfig.SMTPServer, auth, &tls.Config{
				ServerName: host,
			})
		} else {
			// No TLS; TODO: should we disable this?
			err = e.Send(emailConfig.SMTPServer, auth)
		}
		if err != nil {
			s.logger.Error("failed to send email", "to", pendEmail.To, "id", pendEmail.ID, errAttr(err))
			errs = append(errs, err)
			continue
		}

		// If we succeeded, remove this email from the pending list.
		s.logger.Debug("sent email", "to", pendEmail.To, "id", pendEmail.ID)
		successes = append(successes, pendEmail.ID)
	}

	// Remove all the emails that we successfully sent from our database.
	if err := s.db.Write(func(data *data) error {
		for _, id := range successes {
			delete(data.PendingEmails, id)
			s.logger.Debug("removing sent email from pending list", "id", id)
		}
		return nil
	}); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// servePostLoginEmail is called when the user logs in by selecting the "log in
// with magic link" option.
func (s *idpServer) servePostLoginEmail(w http.ResponseWriter, r *http.Request, user *db.User) {
	// Generate a magic login link for this user.
	magic := &db.MagicLoginLink{
		Token:    randHex(64),
		UserUUID: user.UUID,
		Expiry:   db.JSONTime{time.Now().Add(10 * time.Minute)},
		NextURL:  s.getNextURL(r),
	}

	if err := s.db.Write(func(data *data) error {
		if data.MagicLinks == nil {
			data.MagicLinks = make(map[string]*db.MagicLoginLink)
		}
		data.MagicLinks[magic.Token] = magic
		return nil
	}); err != nil {
		s.logger.Error("failed to save magic login", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	magicURL := s.serverURL + "/login/magic?token=" + magic.Token
	if buildtags.IsDev {
		s.logger.Info("generated magic login link",
			"user_uuid", user.UUID,
			"url", magicURL,
		)
	}

	// Send the user an email
	if err := s.queueEmail(&db.PendingEmail{
		To:   user.Email,
		Text: "Use this link to log in: " + magicURL,
		HTML: makeEmailBody(magicURL),
	}); err != nil {
		s.logger.Error("failed to queue email", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Redirect the user to a landing page that says "check your email"
	http.Redirect(w, r, "/login/check-email", http.StatusSeeOther)
}

// emailBodyTemplate is an HTML template for the email body we send to users
// for them to log in. Most email clients have a fairly restrictive set of
// allowed formatting for emails, so we keep this simple.
//
// TODO: this doesn't look too bad (borrowed from somewhere), but should
// ideally better match the styling and colour of the rest of the application
var emailBodyTemplate = template.Must(template.New("email").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login to Your Account</title>
</head>
<body style="margin: 0; padding: 0; background-color: #f6f9fc; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 40px 20px;">
        <div style="background-color: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h1 style="margin: 0 0 20px; color: #1a1a1a; font-size: 24px; font-weight: 600;">Log in to homeauth</h1>

            <p style="margin: 0 0 24px; color: #4a5568; font-size: 16px; line-height: 24px;">
                Click the button below to log in to your account. This link will expire in 10 minutes and can only be used once.
            </p>

            <div style="text-align: center; margin: 32px 0;">
                <a href="{{.MagicURL}}" style="display: inline-block; background-color: #4f46e5; color: white; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 500; font-size: 16px;">Log in to Your Account</a>
            </div>

            <p style="margin: 24px 0 0; color: #718096; font-size: 14px; line-height: 20px;">
                If you didn't request this login link, you can safely ignore this email.
            </p>

            <hr style="margin: 24px 0; border: none; border-top: 1px solid #e2e8f0;">

            <p style="margin: 0; color: #718096; font-size: 14px; line-height: 20px;">
                If the button above doesn't work, copy and paste this URL into your browser:<br>
                <span style="color: #4a5568; word-break: break-all;">{{.MagicURL}}</span>
            </p>
        </div>
    </div>
</body>
</html>
`))

func makeEmailBody(magicURL string) string {
	var buf bytes.Buffer
	if err := emailBodyTemplate.Execute(&buf, map[string]any{
		"MagicURL": magicURL,
	}); err != nil {
		panic(fmt.Sprintf("failed to execute email body template: %v", err))
	}
	return buf.String()
}

// serveGetMagicLogin is called when the user clicks on the magic login link in
// their email.
func (s *idpServer) serveGetMagicLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	// Even though we're not going to "claim" the token until the POST form
	// auto-submits, we can still do some sanity checks here.
	var (
		status int
		why    string
		ok     bool
	)
	s.db.Read(func(data *data) {
		status, why, ok = s.checkMagicLogin(data, token)
	})
	if !ok {
		http.Error(w, why, status)
		return
	}

	if err := s.templates.ExecuteTemplate(w, "login-magic.html.tmpl", map[string]any{
		"Token":          token,
		csrf.TemplateTag: csrf.TemplateField(r),
	}); err != nil {
		s.logger.Error("failed to render login-magic template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// servePostMagicLogin is called when the "/login/magic" endpoint is auto-submitted.
func (s *idpServer) servePostMagicLogin(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	// NOTE: because we want to ensure that a magic link is single-use, we
	// do the entire operation here inside a write transaction. This
	// ensures that nothing else can use the magic link while we're
	// processing it or after we've used it.
	//
	// Because of this, we shouldn't be writing to the client while holding
	// the lock; store any errors in an error variable and write them after
	// we're done.
	var (
		magic *db.MagicLoginLink
		user  *db.User

		status    int
		errString string
	)
	if err := s.db.Write(func(data *data) error {
		st, why, ok := s.checkMagicLogin(data, token)
		if !ok {
			status = st
			errString = why
			return nil // not an error, but we're done
		}

		// If we get here, we know this is valid
		magic = data.MagicLinks[token]
		user = data.Users[magic.UserUUID]

		// Remove the magic login link from the database, now that it's
		// been used.
		delete(data.MagicLinks, token)

		// TODO(andrew-d): should we remove all other magic links for
		// this user?

		// Update this user's EmailVerified field; now that they've
		// logged in via an email link, we know they control that email
		// address.
		data.Users[user.UUID].EmailVerified = true
		return nil
	}); err != nil {
		s.logger.Error("failed to update database after login", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// First check if we had an error during the write transaction.
	if status != 0 {
		http.Error(w, errString, status)
		return
	}
	if user == nil {
		s.logger.Error("no user found after magic login", "token", token)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Log the user in by creating a session.
	if err := s.loginUserSession(w, r, user, "magic_link"); err != nil {
		s.logger.Error("failed to log in user", errAttr(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logger.Debug("redirecting user after magic login",
		"user_uuid", user.UUID,
		"next_url", magic.NextURL,
	)

	// Redirect the user to the account page.
	if magic.NextURL != "" {
		http.Redirect(w, r, magic.NextURL, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	}
}

// checkMagicLogin centralizes checking whether a magic login link with the
// given token is valid.
//
// It returns a boolean "ok" that indicates whether the token is valid, and if
// not, a status code and informational message explaining why.
//
// If the code is not valid, this function will log.
func (s *idpServer) checkMagicLogin(data *data, token string) (status int, why string, ok bool) {
	magic := data.MagicLinks[token]
	if magic == nil {
		s.logger.Warn("no such magic login", "token", token)
		return http.StatusUnauthorized, "invalid token", false
	}

	user := data.Users[magic.UserUUID]
	if user == nil {
		s.logger.Error("no such user for magic login", "token", token, "user_uuid", magic.UserUUID)
		return http.StatusInternalServerError, "internal server error", false
	}

	// Check that the token hasn't expired.
	if time.Now().After(magic.Expiry.Time) {
		s.logger.Warn("magic login expired", "token", token, "expiry", magic.Expiry, "now", time.Now())
		return http.StatusUnauthorized, "expired token", false
	}

	return 0, "", true
}

// serveGetLoginCheckEmail serves a "check your email" page after the user
// initiates a log in with a magic link.
func (s *idpServer) serveGetLoginCheckEmail(w http.ResponseWriter, r *http.Request) {
	if err := s.templates.ExecuteTemplate(w, "login-email.html.tmpl", nil); err != nil {
		s.logger.Error("failed to render login-email template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
