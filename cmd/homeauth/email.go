package main

import (
	"bytes"
	"cmp"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"text/template"
	"time"

	"github.com/andrew-d/homeauth/internal/buildtags"
	"github.com/andrew-d/homeauth/internal/db"
	"github.com/andrew-d/homeauth/internal/templates"
	"github.com/jordan-wright/email"
)

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

	var emailConfig *EmailConfig
	if err := s.db.Write(func(data *data) error {
		emailConfig = data.Config.Email
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

	fromAddr := cmp.Or(emailConfig.FromAddress, emailConfig.SMTPUsername)
	subject := fmt.Sprintf("Login to homeauth (%s)", s.serverHostname)

	// Send the user an email
	e := &email.Email{
		To:      []string{user.Email},
		From:    fmt.Sprintf("homeauth <%s>", fromAddr),
		Subject: cmp.Or(emailConfig.Subject, subject),
		Text:    []byte("Use this link to log in: " + magicURL),
		HTML:    makeEmailBody(magicURL),
	}

	// Split the host and port from the address; we know this never fails
	// because initializeConfig checked.
	host, _, _ := net.SplitHostPort(emailConfig.SMTPServer)
	auth := smtp.PlainAuth(
		emailConfig.FromAddress,  // identity
		emailConfig.SMTPUsername, // user
		emailConfig.SMTPPassword, // password
		host,                     // host
	)

	// Use TLS if either explicitly set or no TLS options are set.
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
		s.logger.Error("failed to send email", errAttr(err))
		http.Error(w, "internal server error; failed to send email", http.StatusInternalServerError)
		return
	}

	// Redirect the user to a landing page that says "check your email"
	http.Redirect(w, r, "/login/check-email", http.StatusSeeOther)
}

// emailBodyTemplate is an HTML template for the email body we send to users
// for them to log in. Most email clients have a fairly restrictive set of
// allowed formatting for emails, so we keep this simple.
//
// TODO: make this look a bit nicer
var emailBodyTemplate = template.Must(template.New("email").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>homeauth login</title>
</head>
<body>
<p>Use this link to log in:</p>
<p><a href="{{ .MagicURL }}">click here</a></p>
</body>
</html>`))

func makeEmailBody(magicURL string) []byte {
	var buf bytes.Buffer
	if err := emailBodyTemplate.Execute(&buf, map[string]any{
		"MagicURL": magicURL,
	}); err != nil {
		panic(fmt.Sprintf("failed to execute email body template: %v", err))
	}
	return buf.Bytes()
}

// serveGetMagicLogin is called when the user clicks on the magic login link in
// their email.
func (s *idpServer) serveGetMagicLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	// TODO; there's a race here where multiple uses of the same magic link
	// can happen at once; need to fix that.
	var (
		magic *db.MagicLoginLink
		user  *db.User
	)
	s.db.Read(func(data *data) {
		magic = data.MagicLinks[token]
		if magic != nil {
			user = data.Users[magic.UserUUID]
		}
	})
	if magic == nil {
		s.logger.Warn("no such magic login", "token", token)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if user == nil {
		s.logger.Error("no such user for magic login", "token", token, "user_uuid", magic.UserUUID)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Check that the token hasn't expired.
	if time.Now().After(magic.Expiry.Time) {
		s.logger.Warn("magic login expired", "token", token, "expiry", magic.Expiry, "now", time.Now())
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Log the user in by creating a session.
	if err := s.loginUserSession(w, r, user, "magic_link"); err != nil {
		s.logger.Error("failed to log in user", errAttr(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.db.Write(func(data *data) error {
		// Remove the magic login link from the database, now that it's
		// been used; TODO see above with a race
		delete(data.MagicLinks, token)

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

// serveGetLoginCheckEmail serves a "check your email" page after the user
// initiates a log in with a magic link.
func (s *idpServer) serveGetLoginCheckEmail(w http.ResponseWriter, r *http.Request) {
	if err := templates.All().ExecuteTemplate(w, "login-email.html.tmpl", nil); err != nil {
		s.logger.Error("failed to render login-email template", errAttr(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
