// Package testproc contains a helper for launching a subprocess in a test,
// monitoring it during the lifetime of the test, and ensuring it's terminated
// gracefully when then test is done.
package testproc

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type Options struct {
	// ShutdownSignal, if non-zero, will be sent to the process when the
	// test finishes to allow it to gracefully shut down. If not specified,
	// the process will be killed.
	ShutdownSignal syscall.Signal

	// ShutdownTimeout is the timeout between when ShutdownSignal is sent
	// (if any) and when the process is killed.
	//
	// If zero, a default value of 2 seconds is used.
	ShutdownTimeout time.Duration

	// LogStdout and LogStderr, if set, will capture and log stdout or
	// stderr (respectively) from the subprocess to the test's logger,
	// prefixed with the name of the binary.
	//
	// They override the Stdout/Stderr options, below.
	LogStdout bool
	LogStderr bool

	// The following fields are copied to the *exec.Cmd's fields of the
	// same name without modification.
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	Env        []string
	Dir        string
	ExtraFiles []*os.File
}

type Proc struct {
	tb  testing.TB
	ctx context.Context
	cmd *exec.Cmd
}

func New(tb testing.TB, name string, args []string, opts *Options) *Proc {
	// ctx tracks the lifetime of the process, and is canceled when the
	// process exits.
	ctx, cancel := context.WithCancel(context.Background())
	procBase := filepath.Base(name)
	cmd := exec.Command(name, args...)
	if opts != nil {
		cmd.Stdin = opts.Stdin
		cmd.Dir = opts.Dir
		cmd.Env = opts.Env
		cmd.ExtraFiles = opts.ExtraFiles

		if opts.LogStdout {
			cmd.Stdout = newLineWriter(func(line string) error {
				tb.Logf("%s: stdout: %s", procBase, line)
				return nil
			})
		} else {
			cmd.Stdout = opts.Stdout
		}

		if opts.LogStderr {
			cmd.Stderr = newLineWriter(func(line string) error {
				tb.Logf("%s: stderr: %s", procBase, line)
				return nil
			})
		} else {
			cmd.Stderr = opts.Stderr
		}
	}
	if err := cmd.Start(); err != nil {
		cancel() // free resources
		tb.Fatalf("failed to start %s: %v", name, err)
	}

	// Watch the process and cancel our context when it finishes.
	var killed atomic.Bool
	exitErr := make(chan error, 1)
	go func() {
		defer cancel()
		err := cmd.Wait()
		if err == nil || killed.Load() {
			exitErr <- nil
		} else {
			exitErr <- err
		}
	}()

	// Create a channel that we cancel when the test finishes, and use this
	// to shut down our process.
	testDone := make(chan struct{})
	tb.Cleanup(func() {
		close(testDone)

		// Wait for the process to finish before letting the test exit.
		<-ctx.Done()

		// Read the exit error
		if err := <-exitErr; err != nil {
			tb.Errorf("process exited with error: %v", err)
		}
	})

	if opts != nil && opts.ShutdownSignal != 0 {
		shutdownTimeout := cmp.Or(opts.ShutdownTimeout, 2*time.Second)
		go func() {
			// Wait for the test to finish.
			<-testDone

			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-ctx.Done():
				return
			case <-time.After(shutdownTimeout):
			}
			killed.Store(true)
			cmd.Process.Kill()
		}()
	} else {
		go func() {
			<-testDone
			killed.Store(true)
			cmd.Process.Kill()
		}()
	}

	return &Proc{
		tb:  tb,
		ctx: ctx,
		cmd: cmd,
	}
}

// Context returns a [context.Context] that is canceled when the monitored
// process exits.
func (p *Proc) Context() context.Context {
	return p.ctx
}

// Wait runs the given function any number of times until either the timeout
// elapses, the monitored process exits, or it returns a nil error.
//
// If the timeout elapses, the test will error.
func (p *Proc) Wait(dur time.Duration, f func(context.Context) error) {
	var lastErr error

	remain := dur
	for remain > 0 {
		if err := p.ctx.Err(); err != nil {
			// process done
			return
		}
		if lastErr = f(p.ctx); lastErr == nil {
			return
		}

		// TODO: nicer backoff than this
		select {
		case <-p.ctx.Done():
			return // process done
		case <-time.After(10 * time.Millisecond):
		}
		remain -= 10 * time.Millisecond
	}

	p.tb.Errorf("Wait did not succeed in %v; last error: %v", dur, lastErr)
}

// WaitForFiles will wait for the given files to exist on disk, using the Wait
// function.
func (p *Proc) WaitForFiles(dur time.Duration, files ...string) {
	p.Wait(dur, func(_ context.Context) error {
		var errs []error
		for _, path := range files {
			if _, err := os.Stat(path); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	})
}

// WaitForHttpOK will wait until a HTTP request to the provided address (using
// the provided HTTP client) returns a 200 OK response. No further checking is
// done; if anything more complicated is necessary, then a custom Wait function
// can be used.
func (p *Proc) WaitForHttpOK(dur time.Duration, client *http.Client, addr string) {
	p.Wait(dur, func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, "GET", addr, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("bad status: %d", resp.StatusCode)
		}

		return nil
	})
}
