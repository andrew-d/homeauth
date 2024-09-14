package templates

import (
	"embed"
	"html/template"
	"sync"
)

//go:embed *.html.tmpl
var templates embed.FS

var (
	all     *template.Template
	allErr  error
	allOnce sync.Once

	// If this is non-nil, it's called before calling allEmbedded.
	allDev func() *template.Template
)

func All() *template.Template {
	if allDev != nil {
		if t := allDev(); t != nil {
			return t
		}
	}
	return allEmbedded()
}

func allEmbedded() *template.Template {
	allOnce.Do(func() {
		all, allErr = template.New("").ParseFS(templates, "*.html.tmpl")
	})

	if allErr != nil {
		// Parsing should never fail, so panic here.
		panic(allErr)
	}
	return all
}
