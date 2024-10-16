//go:build darwin && cgo
// +build darwin,cgo

package listenx

import "testing"

func TestListenLaunchd(t *testing.T) {
	t.Run("NotLaunchd", func(t *testing.T) {
		// Test that we get an error when launchd is not managing the process.
		_, err := listenLaunchd("com.example.notlaunchd")
		if err == nil {
			t.Error("expected error when launchd is not managing the process")
		}

		const wantErr = "this process is not managed by launchd"
		if err != nil && err.Error() != wantErr {
			t.Errorf("got error %q, want %q", err, wantErr)
		}
	})
}
