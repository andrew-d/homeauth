package main

import (
	"cmp"
	"net/http"
	"net/url"

	"github.com/andrew-d/homeauth/internal/db"
)

const (
	apiBehaviourDeny     = "deny"
	apiBehaviourRedirect = "redirect"
)

// serveAPIVerify is the handler for the /api/verify endpoint. It implements
// the nginx subrequest authentication protocol.
func (s *idpServer) serveAPIVerify(w http.ResponseWriter, r *http.Request) {
	// Figure out what the 'behaviour' of the request is. This defines how
	// we respond when access is denied.
	//
	// The default behaviour is to deny access.
	//
	// Prefer the HTTP header over the query parameter, but support both.
	headerOrQuery := cmp.Or(
		r.Header.Get("X-Homeauth-Behaviour"),
		r.URL.Query().Get("behaviour"),
	)

	var behaviour string
	switch headerOrQuery {
	case apiBehaviourDeny, apiBehaviourRedirect:
		behaviour = headerOrQuery
	default:
		behaviour = apiBehaviourDeny
	}

	// Get the original method and URI, which is rewritten by the proxy.
	originalMethod := r.Header.Get("X-Forwarded-Method")
	originalProto := r.Header.Get("X-Forwarded-Proto")
	originalHost := r.Header.Get("X-Forwarded-Host")
	originalURI := r.Header.Get("X-Forwarded-URI")
	s.logger.Debug("verifying access for forwarded request",
		"method", originalMethod,
		"proto", originalProto,
		"host", originalHost,
		"uri", originalURI,
	)

	// Helper to return the appropriate response based on the behaviour.
	deny := func(reason string) {
		s.logger.Debug("access denied for forwarded request",
			"method", originalMethod,
			"host", originalHost,
			"uri", originalURI,
			"reason", reason,
			"behaviour", behaviour,
		)
		switch behaviour {
		case apiBehaviourDeny:
			http.Error(w, reason, http.StatusForbidden)
		case apiBehaviourRedirect:
			uri := url.URL{
				Scheme: originalProto,
				Host:   originalHost,
				Path:   originalURI,
			}

			vals := url.Values{}
			vals.Set("next", uri.String())
			http.Redirect(w, r, s.serverURL+"/login?"+vals.Encode(), http.StatusSeeOther)
		}
	}

	// See if the user has a session set on the request.
	userUUID := s.smgr.GetString(r.Context(), skeyUserUUID)
	if userUUID == "" {
		deny("no session found")
		return
	}

	var user *db.User
	s.db.Read(func(d *data) {
		user = d.Users[userUUID]
	})
	if user == nil {
		// Don't return or redirect; this is an error.
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}

	// If the session is authenticated, return a 200 OK to the client and
	// set a header stating who the user is.
	w.Header().Set("X-Homeauth-User-UUID", user.UUID)
	w.Header().Set("X-Homeauth-User-Email", user.Email)
	w.WriteHeader(http.StatusOK)
}
