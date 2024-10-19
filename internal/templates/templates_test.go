package templates

import (
	"io"
	"strings"
	"testing"

	"github.com/neilotoole/slogt"
)

func allPageTemplates() []string {
	return []string{
		"account.html.tmpl",
		"index.html.tmpl",
		"login.html.tmpl",
		"webauthn.html.tmpl",
	}
}

// TestDevTemplatesDontPanic verifies that every page template can be executed
// without errors in development mode
func TestDevTemplatesDontPanic(t *testing.T) {
	te, err := newDevEngine(slogt.New(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, template := range allPageTemplates() {
		t.Run(template, func(t *testing.T) {
			t.Parallel()

			err := te.ExecuteTemplate(io.Discard, template, nil)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestProdTemplatesDontPanic verifies that every page template can be executed
// without errors in production mode
func TestProdTemplatesDontPanic(t *testing.T) {
	te, err := newProdEngine(slogt.New(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, template := range allPageTemplates() {
		t.Run(template, func(t *testing.T) {
			t.Parallel()

			err := te.ExecuteTemplate(io.Discard, template, nil)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestPageData is a smoke test to verify that some data is passed in to page
// templates correctly.
func TestPageData(t *testing.T) {
	te, err := newProdEngine(slogt.New(t))
	if err != nil {
		t.Fatal(err)
	}

	const sigil = "SIGIL_UNLIKELY_TO_APPEAR_IN_HTML_OTHERWISE"

	// Login page needs the CSRF token field in the login form.
	// This verifies that data is passed through to the page template.
	t.Run("login.html.tmpl", func(t *testing.T) {
		var output strings.Builder
		data := map[string]string{"csrfTokenValue": sigil}

		err := te.ExecuteTemplate(&output, "login.html.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(output.String(), sigil) {
			t.Errorf("Expected to find %q in output given %q as input but did not", sigil, "csrfField")
		}
	})

	// Webauthn page needs the CSRF token meta tag.
	// This verifies that data is passed through to the layout template.
	t.Run("webauthn.html.tmpl", func(t *testing.T) {
		var output strings.Builder
		data := map[string]string{"CSRFToken": sigil}

		err := te.ExecuteTemplate(&output, "webauthn.html.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(output.String(), sigil) {
			t.Errorf("Expected to find %q in output given %q as input but did not", sigil, "CSRFToken")
		}
	})
}
