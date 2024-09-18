package static

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/andrew-d/homeauth/internal/buildtags"
	"github.com/andrew-d/homeauth/internal/repodir"
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
	// If we're in dev mode, use the local filesystem instead of the embed.FS.
	var assetFS fs.FS = assets
	if buildtags.IsDev {
		if root, err := repodir.Root(); err == nil {
			assetFS = os.DirFS(filepath.Join(root, "static"))
		}
	}

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

		// If we're in dev mode, return a http.Handler that reads the
		// file when it's called, so that we reload the file on every
		// request.
		var handler http.Handler
		if buildtags.IsDev {
			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// NOTE: intentionally not setting an ETag here
				http.ServeFileFS(w, r, assetFS, path)
			})
		} else {
			// Read the file's contents into memory so we can serve it
			// later. This isn't amazingly optimized, but it's fine since
			// most of our static assets are small.
			content, err := fs.ReadFile(assets, path)
			if err != nil {
				return fmt.Errorf("reading file: %w", err)
			}

			// Create an ETag for the file based on a sha256 hash of the content.
			etag := fmt.Sprintf("%q", sha256.Sum256(content))

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", etag)
				http.ServeContent(w, r, path, modtime, bytes.NewReader(content))
			})
		}

		cb(path, handler)
		return nil
	})
}
