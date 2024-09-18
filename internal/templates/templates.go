package templates

import (
	"embed"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/andrew-d/homeauth/internal/buildtags"
	"github.com/andrew-d/homeauth/internal/repodir"
)

//go:embed *.html.tmpl
var templates embed.FS

var (
	all     *template.Template
	allErr  error
	allOnce sync.Once
)

func All() *template.Template {
	if buildtags.IsDev {
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

func allDev() *template.Template {
	root, err := repodir.Root()
	if err != nil {
		wd, _ := os.Getwd()
		log.Printf("could not find templates directory on disk; working directory is %s", wd)
		return nil
	}

	// Load the templates from disk.
	templateDir := filepath.Join(root, "internal", "templates")
	return template.Must(template.ParseGlob(filepath.Join(templateDir, "*.html.tmpl")))
}
