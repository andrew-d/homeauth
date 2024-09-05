package static

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed css/* js/*
var assets embed.FS

// RegisterOnMux will register the static assets on the provided http.ServeMux.
func RegisterOnMux(mux *http.ServeMux) {
	mux.Handle("/css/", http.FileServer(http.FS(assets)))
	mux.Handle("/js/", http.FileServer(http.FS(assets)))
}

// Iter will iterate through all the files in the static assets, along with a
// http.Handler that will serve the file's contents. This is helpful for
// serving the assets with a non-standard router.
func Iter(cb func(path string, handler http.Handler)) error {
	return fs.WalkDir(assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}

		// Get the mod time of the file up-front.
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("getting file info: %w", err)
		}
		modtime := info.ModTime()

		// Read the file's contents into memory so we can serve it
		// later. This isn't amazingly optimized, but it's fine since
		// most of our static assets are small.
		content, err := fs.ReadFile(assets, path)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeContent(w, r, path, modtime, bytes.NewReader(content))
		})

		cb(path, handler)
		return nil
	})
}
