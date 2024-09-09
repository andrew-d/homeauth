package pwhash

import "testing"

func TestPasswordHash(t *testing.T) {
	h := New(1, 64*1024, 4)
	password := []byte("password")
	hash := h.Hash(password)
	if !h.Verify(password, hash) {
		t.Error("password does not match hash")
	}

	t.Logf("hash of %q = %q", password, hash)
}

func TestVerifyWithDifferentParams(t *testing.T) {
	h1 := New(1, 64*1024, 4)
	h2 := New(2, 32*1024, 4)

	password := []byte("password")

	// A hash should verify with any Hasher, regardless of that Hasher's
	// params, since it describes its own parameters.
	hash1 := h1.Hash(password)
	if !h2.Verify(password, hash1) {
		t.Error("password should match hash")
	}
}
