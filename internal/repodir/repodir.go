// Package repodir contains a helper function for finding the root of this
// project's Git repository. This is used to assist in hot-reloading static
// assets and templates.
package repodir

import (
	"fmt"
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
	lookFor := filepath.Join("internal/repodir/repodir.go") // look for this file, as we can guarantee it exists

	var candidatePaths []string

	// Attempt to find the root dir by starting in CWD and going up the tree one
	// dir at a time
	path, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting CWD: %w", err)
	}
	for path != "/" {
		candidatePaths = append(candidatePaths, path)
		path = filepath.Join(path, "..")
	}

	// Also check potential GOPATHs
	gopathDir := filepath.Join("src", "github.com", "andrew-d", "homeauth")
	if gp := build.Default.GOPATH; gp != "" {
		for _, gopath := range filepath.SplitList(gp) {
			candidatePaths = append(candidatePaths, filepath.Join(gopath, gopathDir))
		}
	}
	if gp := os.Getenv("GOPATH"); gp != "" {
		for _, gopath := range filepath.SplitList(gp) {
			candidatePaths = append(candidatePaths, filepath.Join(gopath, gopathDir))
		}
	}

	for _, path := range candidatePaths {
		check := filepath.Join(path, lookFor)
		if st, err := os.Stat(check); err == nil && st.Mode().IsRegular() {
			return filepath.Abs(path)
		}
	}

	return "", fmt.Errorf("finding package path, %q not found in any of %v", lookFor, candidatePaths)
}
