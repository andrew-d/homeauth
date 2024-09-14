//go:build dev

package templates

import (
	"go/build"
	"html/template"
	"log"
	"os"
	"path/filepath"
)

func allFromDisk() *template.Template {
	candidatePaths := []string{
		"internal/templates/templates_dev.go",
	}

	gopathDir := filepath.Join("src", "github.com", "andrew-d", "homeauth", "internal", "templates")
	if gp := build.Default.GOPATH; gp != "" {
		for _, gopath := range filepath.SplitList(gp) {
			candidatePaths = append(candidatePaths, filepath.Join(gopath, gopathDir, "templates_dev.go"))
		}
	}
	if gp := os.Getenv("GOPATH"); gp != "" {
		for _, gopath := range filepath.SplitList(gp) {
			candidatePaths = append(candidatePaths, filepath.Join(gopath, gopathDir, "templates_dev.go"))
		}
	}

	// Try to find our templates on disk by looking for this filename.
	var templateDir string
	for _, path := range candidatePaths {
		if _, err := os.Stat(path); err == nil {
			templateDir = filepath.Dir(path)
			break
		}
	}
	if templateDir == "" {
		// If we can't find the templates, print an error and return nil.
		wd, _ := os.Getwd()
		log.Printf("could not find templates directory on disk; working directory is %s", wd)
		return nil
	}

	// Load the templates from disk.
	return template.Must(template.ParseGlob(filepath.Join(templateDir, "*.html.tmpl")))
}

func init() {
	allDev = allFromDisk
}
