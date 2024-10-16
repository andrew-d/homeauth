package listenx

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
)

func TestListen(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		ln, err := Listen("tcp://localhost:0")
		if err != nil {
			t.Fatalf("Listen failed: %v", err)
		}
		defer ln.Close()

		verifyListenerAccepts(t, ln, "tcp", ln.Addr().String())
	})
	t.Run("unix", func(t *testing.T) {
		sockPath := filepath.Join(t.TempDir(), "test.sock")
		ln, err := Listen("unix://" + sockPath)
		if err != nil {
			t.Fatalf("Listen failed: %v", err)
		}
		defer ln.Close()

		verifyListenerAccepts(t, ln, "unix", sockPath)
	})
	t.Run("unsupported", func(t *testing.T) {
		_, err := Listen("unsupported://localhost:0")
		if err == nil {
			t.Fatalf("Listen succeeded for unsupported scheme")
		}
	})
}

func verifyListenerAccepts(t *testing.T, ln net.Listener, network, addr string) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Launch a goroutine to accept connections.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() == nil {
					t.Logf("Accept failed: %v", err)
				}
				return
			}
			t.Logf("accepted connection from %q", conn.RemoteAddr())
			conn.Close()
		}
	}()

	// Launch another to close the listener when the context is done.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		ln.Close()
	}()

	// Verify that we can connect to the listener.
	conn, err := net.Dial(network, addr)
	if err != nil {
		t.Fatalf("net.Dial(%q, %q) failed: %v", network, addr, err)
	}
	conn.Close()

	// Cancel the context to stop the listener.
	cancel()

	// Wait for the listener to close.
	wg.Wait()
}
