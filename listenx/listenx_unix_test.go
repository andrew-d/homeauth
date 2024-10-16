package listenx

import (
	"bytes"
	"flag"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestListen_InheritFD(t *testing.T) {
	// If we have our magic environment variable set, then we're actually
	// the test process; otherwise, we're the parent and we execute
	// ourselves with the magic variable set and an inherited FD.
	if isInChild() {
		testListenInheritFDChild(t)
		return
	}

	// Create a listener to inherit.
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}

	// Get the file to inherit
	file, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatalf("listener.File failed: %v", err)
	}

	runSelf(t, func(cmd *exec.Cmd) {
		cmd.ExtraFiles = []*os.File{file}
	})
}

func testListenInheritFDChild(t *testing.T) {
	// We're the child process; try to listen on the inherited FD.
	const addr = "fd://3"
	l, err := Listen(addr)
	if err != nil {
		t.Fatalf("Listen(%q) failed: %v", addr, err)
	}
	defer l.Close()

	t.Logf("got listener: %v", l.Addr())
	verifyListenerAccepts(t, l, "tcp", l.Addr().String())
}

func isVerboseTest() bool {
	ff := flag.Lookup("test.v")
	return ff.Value.String() == "true"
}

const isChildEnv = "LISTENX_IS_CHILD"

func isInChild() bool {
	// If we have our magic environment variable set, then we're actually
	// the test process; otherwise, we're the parent and we (in runSelf)
	// execute ourselves with the magic variable set and an inherited FD.
	return os.Getenv(isChildEnv) != ""
}

func runSelf(t *testing.T, modify func(*exec.Cmd)) {
	t.Helper()

	// We're the parent; re-run ourselves with the magic variable set.
	cmd := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$")
	if isVerboseTest() {
		cmd.Args = append(cmd.Args, "-test.v")
	}
	cmd.Env = append(os.Environ(), isChildEnv+"=1")
	modify(cmd)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Errorf("subprocess failed: %v", err)
	}

	// Print the output of the child process, prefixed with the kind of
	// output.
	if trimmed := strings.TrimSpace(stdout.String()); trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			t.Logf("child stdout: %s", line)
		}
	}
	if trimmed := strings.TrimSpace(stderr.String()); trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			t.Logf("child stderr: %s", line)
		}
	}
}
