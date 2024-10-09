package templates

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/andrew-d/homeauth/internal/buildtags"
	"github.com/andrew-d/homeauth/internal/repodir"
)

//go:embed *.html.tmpl
var templates embed.FS

type TemplateEngine interface {
	ExecuteTemplate(wr io.Writer, name string, data any) error
}

// New returns a TemplateEngine, either a prodEngine or a devEngine depending on
// build tags. prodEngine builds templates into the binary at compile time, and
// parses them once at initialisation for speed. devEngine loads templates from
// disk on every call to ExecuteTemplate, so changes show up immediately.
func New(log *slog.Logger) (TemplateEngine, error) {
	if buildtags.IsDev {
		log.Debug("development mode, using devEngine")
		return newDevEngine(log)
	} else {
		log.Debug("production mode, using prodEngine")
		return newProdEngine(log)
	}
}

type prodEngine struct {
	templates map[string]template.Template
	log       *slog.Logger
}

func newProdEngine(log *slog.Logger) (TemplateEngine, error) {
	ts := make(map[string]template.Template)

	layout, err := template.ParseFS(templates, "_*.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("loading layout templates _*.html.tmpl: %w", err)
	}

	names, err := fs.Glob(templates, "[^_]*.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("loading page templates [^_]*.html.tmpl: %w", err)
	}

	for _, name := range names {
		log.Debug("loading page template", "templateName", name)
		baseCopy, err := layout.Clone()
		if err != nil {
			return nil, fmt.Errorf("cloning base template (should never happen): %w", err)
		}
		t, err := baseCopy.ParseFS(templates, name)
		if err != nil {
			return nil, fmt.Errorf("parsing template %q: %w", name, err)
		}
		ts[name] = *t
	}

	return &prodEngine{log: log, templates: ts}, nil
}

func (e prodEngine) ExecuteTemplate(wr io.Writer, name string, data any) error {
	e.log.Debug("rendering template", "templateName", name, "data", data)

	t, ok := e.templates[name]
	if !ok {
		return fmt.Errorf("did not find %q in template set", name)
	}

	err := t.ExecuteTemplate(wr, name, data)
	if err != nil {
		return fmt.Errorf("executing template %q: %w", name, err)
	}
	return nil
}

type devEngine struct {
	log *slog.Logger
}

func newDevEngine(log *slog.Logger) (*devEngine, error) {
	return &devEngine{log: log}, nil
}

func (e devEngine) ExecuteTemplate(wr io.Writer, name string, data any) error {
	e.log.Debug("rendering template", "templateName", name, "data", data)

	root, err := repodir.Root()
	if err != nil {
		wd, _ := os.Getwd()
		return fmt.Errorf("finding templates directory on disk (cwd is %q): %w", wd, err)
	}
	templatesDir := filepath.Join(root, "internal", "templates")
	layoutsPath := filepath.Join(templatesDir, "_*.html.tmpl")

	layouts, err := template.ParseGlob(layoutsPath)
	if err != nil {
		fmt.Fprintf(wr, "Error parsing layout templates from %q: %s", layoutsPath, err)
		return fmt.Errorf("loading parsing templates from %q: %w", layoutsPath, err)
	}

	templatePath := filepath.Join(templatesDir, name)
	template, err := layouts.ParseFiles(templatePath)
	if err != nil {
		// fmt.Fprintf(wr, "Error parsing page template %q: %s", templatePath, err)
		return fmt.Errorf("loading parsing page template %q: %w", templatePath, err)
	}

	if err := template.ExecuteTemplate(wr, name, data); err != nil {
		// fmt.Fprintf(wr, "Error executing page template %q: %s", name, err)
		return fmt.Errorf("loading executing page template %q: %w", name, err)
	}
	return nil
}
