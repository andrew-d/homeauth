//go:build go1.20
// +build go1.20

package sessions

import (
	"fmt"
	"net/http"
	"testing"
)

// NOTE: test file is Go 1.20+ so we can use [http.ResponseController].

func TestResponseWriterImplementsFlush(t *testing.T) {
	mgr := newTestManager(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/flush", func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		fmt.Fprint(w, "initial\n")
		if err := rc.Flush(); err != nil {
			t.Errorf("Flush failed: %v", err)
			return
		}
		fmt.Fprint(w, "flushed")
	})

	testSrv := runTestServer(t, mgr, mux)
	testSrv.assertResponse("/flush", http.StatusOK, "initial\nflushed")
}
