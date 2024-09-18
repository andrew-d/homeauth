// Package repodir contains a helper function for finding the root of this
// project's Git repository. This is used to assist in hot-reloading static
// assets and templates.
package repodir

import (
	"go/build"
	"os"
	"path/filepath"
	"sync"
)

var (
	rootDir  string
	rootErr  error
	rootOnce sync.Once
)

// Root returns the root directory of this project's Git repository.
func Root() (string, error) {
	rootOnce.Do(func() {
		rootDir, rootErr = findRoot()
	})
	return rootDir, rootErr
}

func findRoot() (string, error) {
	// Look through a few directories to find this filename.
	candidatePaths := []string{
		"internal/repodir/repodir.go",
	}

	gopathDir := filepath.Join("src", "github.com", "andrew-d", "homeauth", "internal", "repodir")
	if gp := build.Default.GOPATH; gp != "" {
		for _, gopath := range filepath.SplitList(gp) {
			candidatePaths = append(candidatePaths, filepath.Join(gopath, gopathDir, "repodir.go"))
		}
	}
	if gp := os.Getenv("GOPATH"); gp != "" {
		for _, gopath := range filepath.SplitList(gp) {
			candidatePaths = append(candidatePaths, filepath.Join(gopath, gopathDir, "repodir.go"))
		}
	}

	var pkgDir string
	for _, path := range candidatePaths {
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
			pkgDir = filepath.Dir(path)
			break
		}
	}
	if pkgDir == "" {
		return "", os.ErrNotExist
	}

	// If we found the package directory, look for the root of the
	// repository by moving up two directories.
	rootDir := filepath.Dir(filepath.Dir(pkgDir))
	return filepath.Abs(rootDir)
}
