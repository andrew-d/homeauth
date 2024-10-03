package securecookie

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testValue struct {
	Name    string `json:"name"`
	Age     int    `json:"age"`
	IsAdmin bool   `json:"is_admin,omitempty"`
}

func TestSecureCookie(t *testing.T) {
	key := NewKey()
	s, err := New[testValue](key)
	if err != nil {
		t.Fatal(err)
	}

	// Encode and then decode.
	tv := &testValue{
		Name:    "Andrew Dunham",
		Age:     99,
		IsAdmin: true,
	}

	cv, err := s.Encode("test", tv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("encoded: %s", cv)

	var got testValue
	if err := s.Decode("test", cv, &got); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(&got, tv) {
		t.Fatalf("got %#v, want %#v", &got, tv)
	}
}

func TestSecureCookie_Expiry(t *testing.T) {
	key := NewKey()
	s, err := New[testValue](key)
	if err != nil {
		t.Fatal(err)
	}

	currTime := time.Date(2024, 10, 2, 19, 0, 0, 0, time.UTC)
	s.now = func() time.Time {
		return currTime
	}

	// Encode a value at the current time.
	tv := &testValue{
		Name:    "Andrew Dunham",
		Age:     99,
		IsAdmin: true,
	}

	cv, err := s.Encode("test", tv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("encoded: %s", cv)

	// Move the "current time" forward by a second longer than our maxAge.
	currTime = currTime.Add(s.maxAge + time.Second)

	// Decode the now-expired cookie
	var got testValue
	err = s.Decode("test", cv, &got)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	var expErr *ExpiredError
	if !errors.As(err, &expErr) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

// TestSecureCookie_Modification verifies that if we modify any single byte of
// the encoded cookie, the Decode function will return an error.
func TestSecureCookie_Modification(t *testing.T) {
	key := NewKey()
	s, err := New[testValue](key)
	if err != nil {
		t.Fatal(err)
	}

	// Encode and then decode.
	tv := &testValue{
		Name:    "Andrew Dunham",
		Age:     99,
		IsAdmin: true,
	}

	cv, err := s.Encode("test", tv)
	if err != nil {
		t.Fatal(err)
	}

	// Decode the cookie as base64 (since that's what it's encoded as) and
	// then modify each single byte. We do this after decoding so that we
	// aren't testing the base64 encoding/decoding.
	dec, err := base64.URLEncoding.DecodeString(cv)
	if err != nil {
		t.Fatal(err)
	}
	for i := range dec {
		// Copy the original data.
		mod := make([]byte, len(dec))
		copy(mod, dec)

		// Modify a single byte.
		mod[i] = byte((int(mod[i]) + 1) % 256)

		// Encode the modified data.
		modEnc := base64.URLEncoding.EncodeToString(mod)

		// Decode the modified data.
		var got testValue
		err := s.Decode("test", modEnc, &got)
		assertErrorContains(t, err, "message authentication failed")
	}
}

type sliceKeyProvider struct {
	primary  []byte
	decrypts [][]byte
}

func (s *sliceKeyProvider) PrimaryKey() []byte    { return s.primary }
func (s *sliceKeyProvider) DecryptKeys() [][]byte { return s.decrypts }

func TestSecureCookie_DecryptKeys(t *testing.T) {
	key := NewKey()
	decryptKey1 := NewKey()
	decryptKey2 := NewKey()

	// Start with a key provider that has an encrypt key and one decrypt key.
	kp := &sliceKeyProvider{
		primary:  decryptKey1,
		decrypts: [][]byte{decryptKey2},
	}

	s, err := NewWith[testValue](kp, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Encode the value with decryptKey1.
	tv := &testValue{
		Name:    "Andrew Dunham",
		Age:     99,
		IsAdmin: true,
	}

	cv, err := s.Encode("test", tv)
	if err != nil {
		t.Fatal(err)
	}

	// Now, move decryptKey1 to the decrypt key list and use key as the
	// primary key.
	kp.primary = key
	kp.decrypts = [][]byte{decryptKey1, decryptKey2}

	// The decode should still work, because we have the decrypt key.
	var got testValue
	if err := s.Decode("test", cv, &got); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(&got, tv) {
		t.Fatalf("got %#v, want %#v", &got, tv)
	}
}

func TestMaxLength(t *testing.T) {
	key := NewKey()
	s, err := New[string](key)
	if err != nil {
		t.Fatal(err)
	}

	data := strings.Repeat("A", base64.URLEncoding.DecodedLen(s.maxLength))
	_, err = s.Encode("test", &data)
	assertErrorContains(t, err, "longer than MaxLength")

	// Ensure that decoding a string that's too long also doesn't work.
	tooLong := base64.URLEncoding.EncodeToString([]byte(data + "A"))
	err = s.Decode("test", tooLong, new(string))
	assertErrorContains(t, err, "longer than MaxLength")
}

func TestInvalidDecode(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "empty",
			input:   "",
			wantErr: "encrypted value too short",
		},
		{
			name:    "invalid base64",
			input:   "invalid base64",
			wantErr: "illegal base64 data",
		},
		{
			name:    "encrypted value too short",
			input:   base64.URLEncoding.EncodeToString([]byte("short")),
			wantErr: "encrypted value too short",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := NewKey()
			s, err := New[string](key)
			if err != nil {
				t.Fatal(err)
			}

			err = s.Decode("test", tc.input, new(string))
			assertErrorContains(t, err, tc.wantErr)
		})
	}
}

func assertErrorContains(tb testing.TB, err error, contains string) {
	tb.Helper()
	if err == nil {
		tb.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), contains) {
		tb.Fatalf("unexpected error: %v", err)
	}
}
