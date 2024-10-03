package securecookie

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"

	"golang.org/x/net/publicsuffix"
)

func ExampleSecureCookie() {
	key := make([]byte, 32)
	must(rand.Read(key))

	type cookieData struct {
		UserID  int  `json:"user_id"`
		IsAdmin bool `json:"is_admin"`
	}

	s := must(New[cookieData](key))

	const cookieName = "user"
	mux := http.NewServeMux()
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		// Set a cookie.
		cookie := &cookieData{
			UserID:  123,
			IsAdmin: true,
		}
		if encoded, err := s.Encode(cookieName, cookie); err == nil {
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    encoded,
				Path:     "/",
				HttpOnly: true,
			})
		}
	})
	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		// Get the cookie.
		if cookie, err := r.Cookie(cookieName); err == nil {
			var decoded cookieData
			if err := s.Decode(cookieName, cookie.Value, &decoded); err == nil {
				fmt.Fprintf(w, "UserID: %d, IsAdmin: %t", decoded.UserID, decoded.IsAdmin)
			} else {
				fmt.Fprintf(w, "Error decoding cookie: %v", err)
			}
		} else {
			fmt.Fprintf(w, "Error getting cookie: %v", err)
		}
	})

	// Use httptest to launch a test server; in the real world, you would
	// use (*http.Server).ListenAndServe.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := srv.Client()
	client.Jar = newCookieJar()

	// Make a request to set the cookie.
	resp := must(client.Get(srv.URL + "/set"))
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("unexpected status code: %d", resp.StatusCode))
	}
	resp.Body.Close()

	// Make a request to get the cookie.
	resp = must(client.Get(srv.URL + "/get"))
	if resp.StatusCode != http.StatusOK {
		panic(fmt.Sprintf("unexpected status code: %d", resp.StatusCode))
	}
	defer resp.Body.Close()
	body := must(io.ReadAll(resp.Body))

	// Print it!
	fmt.Println(string(body))

	// Output: UserID: 123, IsAdmin: true
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func newCookieJar() http.CookieJar {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create cookie jar: %v", err))
	}
	return jar
}
