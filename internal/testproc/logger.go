package testproc

import (
	"bytes"
)

type lineWriter struct {
	buffer    bytes.Buffer
	writeFunc func(string) error
}

// newLineWriter creates a new lineWriter that will call the given function
// with each complete line.
func newLineWriter(fn func(string) error) *lineWriter {
	return &lineWriter{
		writeFunc: fn,
	}
}

// Write implements the io.Writer interface. It writes data to the buffer and
// calls the provided function for each complete line.
func (lw *lineWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	start := 0

	for i, b := range p {
		if b == '\n' {
			// Write up to and including the newline to the buffer.
			lw.buffer.Write(p[start : i+1])

			// Flush the buffer, including this newline-ended line.
			if err := lw.flush(true); err != nil {
				return n, err
			}

			// Move the start index to the next byte after the newline.
			start = i + 1
		}
	}

	// Write any remaining bytes to the buffer that don't include a newline.
	if start < len(p) {
		lw.buffer.Write(p[start:])
	}

	return n, nil
}

// flush flushes the buffer. If `hasNewline` is true, removes the newline.
func (lw *lineWriter) flush(hasNewline bool) error {
	line := lw.buffer.String()
	lw.buffer.Reset()
	if hasNewline && len(line) > 0 {
		line = line[:len(line)-1] // Remove newline character
	}
	return lw.writeFunc(line)
}

// Close flushes any remaining buffered data that hasn't been flushed yet.
func (lw *lineWriter) Close() error {
	if lw.buffer.Len() > 0 {
		return lw.flush(false)
	}
	return nil
}
