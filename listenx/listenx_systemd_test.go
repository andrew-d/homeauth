//go:build unix
// +build unix

package listenx

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

func TestListenSystemd(t *testing.T) {
	if isInChild() {
		// This is a bit of a hack, but... we set LISTEN_PID to our
		// PID, to mimic how systemd would set it.
		os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))

		// We're the child process; try to listen on the inherited FD.
		const addr = "systemd://0"
		l, err := Listen(addr)
		if err != nil {
			t.Fatalf("Listen(%q) failed: %v", addr, err)
		}
		defer l.Close()

		verifyListenerAccepts(t, l, "tcp", l.Addr().String())
		return
	}

	// Create a listener to inherit.
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	file, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("listener.File failed: %v", err)
	}

	runSelf(t, func(cmd *exec.Cmd) {
		cmd.ExtraFiles = []*os.File{file}
		cmd.Env = append(cmd.Env, "LISTEN_FDS=1")
	})
}

func TestListenSystemd_Named(t *testing.T) {
	if isInChild() {
		// This is a bit of a hack, but... we set LISTEN_PID to our
		// PID, to mimic how systemd would set it.
		os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))

		// We're the child process; listen on the named FD.
		const addr = "systemd://bar"
		l, err := Listen(addr)
		if err != nil {
			t.Fatalf("Listen(%q) failed: %v", addr, err)
		}
		defer l.Close()

		verifyListenerAccepts(t, l, "tcp", l.Addr().String())
		return
	}

	// Create a listener to inherit.
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	file, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("listener.File failed: %v", err)
	}

	runSelf(t, func(cmd *exec.Cmd) {
		cmd.ExtraFiles = []*os.File{file, file}
		cmd.Env = append(cmd.Env,
			"LISTEN_FDS=2",
			"LISTEN_FDNAMES=foo:bar",
		)
	})
}
