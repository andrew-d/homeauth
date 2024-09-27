// Copyright (c) David Crawshaw
// SPDX-License-Identifier: BSD-3-Clause

// NOTE: modifications by Andrew Dunham include:
//
//   - Using the 'buildtags' package to prettify the written JSON if in dev
//     mode.
//   - Applying the suggestion from https://github.com/crawshaw/jsonfile/issues/1

// Package jsonfile persists a Go value to a JSON file.
package jsonfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/andrew-d/homeauth/internal/buildtags"
)

// JSONFile holds a Go value of type Data and persists it to a JSON file.
// Data is accessed and modified using the Read and Write methods.
// Create a JSONFile using the New or Load functions.
type JSONFile[Data any] struct {
	path string

	mu    sync.RWMutex
	bytes []byte
	data  *Data
}

// New creates a new empty JSONFile at the given path.
func New[Data any](path string) (*JSONFile[Data], error) {
	p := &JSONFile[Data]{path: path, bytes: []byte("{}"), data: new(Data)}
	if err := p.Write(func(*Data) error { return nil }); err != nil {
		return nil, fmt.Errorf("jsonfile.New: %w", err)
	}
	return p, nil
}

// Load loads an existing JSONFileData from the given path.
//
// If the file does not exist, Load returns an error that can be
// checked with os.IsNotExist.
//
// Load and New are separate to avoid creating a new file when
// starting a service, which could lead to data loss. To both load an
// existing file or create it (which you may want to do in a development
// environment), combine Load with New, like this:
//
//	db, err := jsonfile.Load[Data](path)
//	if os.IsNotExist(err) {
//		db, err = jsonfile.New[Data](path)
//	}
func Load[Data any](path string) (*JSONFile[Data], error) {
	p := &JSONFile[Data]{path: path, data: new(Data)}
	var err error
	p.bytes, err = os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("jsonfile.Load: %w", err)
	}

	// In dev mode, disallow unknown fields so that we don't overwrite anything unexpectedly.
	if buildtags.IsDev {
		dec := json.NewDecoder(bytes.NewReader(p.bytes))
		dec.DisallowUnknownFields()
		err = dec.Decode(p.data)
	} else {
		err = json.Unmarshal(p.bytes, p.data)
	}
	if err != nil {
		return nil, fmt.Errorf("jsonfile.Load: %w", err)
	}
	return p, nil
}

// Read calls fn with the current copy of the data.
func (p *JSONFile[Data]) Read(fn func(data *Data)) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	fn(p.data)
}

// Write calls fn with a copy of the data, then writes the changes to the file.
// If fn returns an error, Write does not change the file and returns the error.
func (p *JSONFile[Data]) Write(fn func(*Data) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	data := new(Data) // operate on copy to allow concurrent reads and rollback
	if err := json.Unmarshal(p.bytes, data); err != nil {
		return fmt.Errorf("JSONFile.Write: %w", err)
	}
	if err := fn(data); err != nil {
		return err
	}
	var (
		b   []byte
		err error
	)
	if buildtags.IsDev {
		b, err = json.MarshalIndent(data, "", "  ")
	} else {
		b, err = json.Marshal(data)
	}
	if err != nil {
		return fmt.Errorf("JSONFile.Write: %w", err)
	}
	if bytes.Equal(b, p.bytes) {
		return nil // no change
	}

	f, err := os.CreateTemp(filepath.Dir(p.path), filepath.Base(p.path)+".tmp")
	if err != nil {
		return fmt.Errorf("JSONFile.Write: temp: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("JSONFile.Write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("JSONFile.Write: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("JSONFile.Write: %w", err)
	}
	if err := os.Rename(f.Name(), p.path); err != nil {
		return fmt.Errorf("JSONFile.Write: rename: %w", err)
	}

	data = new(Data) // avoid any aliased memory
	if err := json.Unmarshal(b, data); err != nil {
		return fmt.Errorf("JSONFile.Write: %w", err)
	}

	p.data = data
	p.bytes = b
	return nil
}
