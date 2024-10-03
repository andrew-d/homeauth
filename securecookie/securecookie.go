// Package securecookie is a very basic package for creating and reading secure
// cookies.
package securecookie

import (
	"cmp"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Options defines the options when creating a new SecureCookie.
type Options struct {
	// MaxAge is the maximum age of the cookie. If MaxAge is 0, then
	// DefaultMaxAge is used.
	//
	// To disable the MaxAge, set it to a negative value.
	//
	// The resolution of MaxAge is measured in milliseconds; any fractional
	// milliseconds are truncated.
	MaxAge time.Duration

	// MaxLength is the maximum length of an encoded value. If MaxLength is 0,
	// then DefaultMaxLength is used.
	//
	// Cookies that are longer than MaxLength will not be encoded and
	// Encode will return an error.
	MaxLength int
}

const (
	// DefaultMaxAge is the default maximum age of a cookie in seconds.
	DefaultMaxAge = 30 * 24 * time.Hour
	// DefaultMaxLength is the default maximum length of an encoded value.
	//
	// 4093 bytes is chosen as a safe default based on the following:
	//	- http://browsercookielimits.iain.guru/
	//	- https://chromestatus.com/feature/4946713618939904
	DefaultMaxLength = 4093
)

// SecureCookie encodes and decodes authenticated and encrypted cookie values.
//
// The generic type T is the type of the value that will be stored in the
// cookie. It must be JSON-serializable.
type SecureCookie[T any] struct {
	kp        KeyProvider
	maxAge    time.Duration
	maxLength int
	now       func() time.Time
}

type cookieData struct {
	Value           json.RawMessage `json:"v"`
	TimestampMillis int64           `json:"t"`
}

// New returns a new SecureCookie, created using default options and a single
// key that will be used for both encryption and decryption.
func New[T any](key []byte) (*SecureCookie[T], error) {
	return NewWith[T](SingleKey(key), Options{})
}

// NewWith returns a new SecureCookie with the given KeyProvider and options.
func NewWith[T any](keys KeyProvider, opts Options) (*SecureCookie[T], error) {
	// Ensure that the keys are valid.
	if _, err := chacha20poly1305.NewX(keys.PrimaryKey()); err != nil {
		return nil, fmt.Errorf("invalid primary key: %w", err)
	}
	for _, key := range keys.DecryptKeys() {
		if _, err := chacha20poly1305.NewX(key); err != nil {
			return nil, fmt.Errorf("invalid decrypt key: %w", err)
		}
	}

	var maxAge time.Duration
	if opts.MaxAge > 0 {
		maxAge = opts.MaxAge.Truncate(time.Millisecond)
	} else if opts.MaxAge == 0 {
		maxAge = DefaultMaxAge
	}

	ret := &SecureCookie[T]{
		kp:        keys,
		maxAge:    maxAge,
		maxLength: cmp.Or(opts.MaxLength, DefaultMaxLength),
		now:       time.Now,
	}
	return ret, nil
}

func (s *SecureCookie[T]) primaryKey() cipher.AEAD {
	key := s.kp.PrimaryKey()
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		// This only fails if the key length is invalid, which
		// indicates misuse.
		panic(err)
	}
	return aead
}

func (s *SecureCookie[T]) decryptKeys() []cipher.AEAD {
	keys := s.kp.DecryptKeys()
	if len(keys) == 0 {
		return nil
	}

	ret := make([]cipher.AEAD, 0, len(keys))
	for _, key := range keys {
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			// This only fails if the key length is invalid, which
			// indicates misuse.
			panic(err)
		}
		ret = append(ret, aead)
	}
	return ret
}

// Decode decodes a cookie value.
//
// It decodes, verifies, decrypts and finally deserializes the value.
//
// The name argument is the cookie name. It must be the same name used when it
// was stored. The value argument is the encoded cookie value. The dst argument
// is where the cookie will be decoded.
func (s *SecureCookie[T]) Decode(name, value string, dst *T) error {
	// Check max length before we do anything else.
	if s.maxLength != 0 && len(value) > s.maxLength {
		return fmt.Errorf("encoded value longer than MaxLength (%d > %d)", len(value), s.maxLength)
	}

	// De-base64
	encBytes, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	// Remove nonce from the end of the data.
	if len(encBytes) < chacha20poly1305.NonceSizeX+1 {
		return fmt.Errorf("encrypted value too short")
	}
	ix := len(encBytes) - chacha20poly1305.NonceSizeX
	nonce := encBytes[ix:]
	encBytes = encBytes[:ix]

	// Get a decrypt buffer; because we need to try decrypting multiple
	// times, we can't overwrite the input buffer.
	plaintextBuf := make([]byte, 0, len(encBytes))

	// Unseal the data
	plaintextBytes, err := s.primaryKey().Open(plaintextBuf, nonce, encBytes, []byte(name))
	if err != nil {
		// Try all decrypt keys
		var err2 error
		for _, aead := range s.decryptKeys() {
			plaintextBytes, err2 = aead.Open(plaintextBuf, nonce, encBytes, []byte(name))
			if err2 == nil {
				err = nil // signal that we successfully decrypted
				break
			}
		}
	}
	if err != nil {
		return err
	}

	// Unmarshal into a cookieData, which contains the actual value (as a
	// json.RawMessage) and a timestamp that we can use to verify expiry.
	var cd cookieData
	if err := json.Unmarshal(plaintextBytes, &cd); err != nil {
		return err
	}

	now := s.now()
	if s.maxAge > 0 {
		cookieTimestamp := time.UnixMilli(cd.TimestampMillis)
		if now.Before(cookieTimestamp) {
			return fmt.Errorf("cookie timestamp in the future")
		}

		cookieExpiry := cookieTimestamp.Add(s.maxAge)
		if now.After(cookieExpiry) {
			return &ExpiredError{CookieExpiry: cookieExpiry}
		}
	}

	// Now, use the json.RawMessage to unmarshal the actual value into our
	// output variable.
	if err := json.Unmarshal(cd.Value, dst); err != nil {
		return err
	}
	return nil
}

// Encode encodes a cookie value.
//
// It serializes, encrypts, and then encodes the value.
//
// The name argument is the cookie name. It is stored with the encoded value.
// The value argument is the value to be encoded.
//
// It is the client's responsibility to ensure that value, when encrypted and
// then base64-encoded, is shorter than the maximum permissible length.
func (s *SecureCookie[T]) Encode(name string, value *T) (string, error) {
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshaling value: %w", err)
	}

	serBytes, err := json.Marshal(cookieData{
		Value:           json.RawMessage(valueBytes),
		TimestampMillis: s.now().UnixMilli(),
	})
	if err != nil {
		return "", err
	}

	// Generate random nonce; should never fail because rand.Read doesn't
	// return an error on modern systems / with modern Go.
	var nonce [chacha20poly1305.NonceSizeX]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}

	// Encrypt
	encBytes := s.primaryKey().Seal(serBytes[:0], nonce[:], serBytes, []byte(name))

	// Append nonce to the encrypted bytes
	encBytes = append(encBytes, nonce[:]...)

	// Encode to base64
	b64 := base64.URLEncoding.EncodeToString(encBytes)

	// Verify length
	if s.maxLength != 0 && len(b64) > s.maxLength {
		return "", fmt.Errorf("encoded value longer than MaxLength (%d > %d)", len(b64), s.maxLength)
	}

	return string(b64), nil
}

// ExpiredError is the error type returned when a cookie is expired.
type ExpiredError struct {
	// CookieExpiry is the time at which the cookie expired.
	CookieExpiry time.Time
}

// Error implements the error interface.
func (e *ExpiredError) Error() string {
	return fmt.Sprintf("cookie expired at %v", e.CookieExpiry)
}

// KeyProvider is an interface for types that can provide key(s) to be used
// when encrypting and decrypting cookies.
//
// All keys returned by a KeyProvider must random byte slices of length
// KeyLength.
//
// All methods on a KeyProvider must be safe for concurrent use.
type KeyProvider interface {
	// PrimaryKey returns the primary key to be used for encryption and that
	// will be tried first for decryption.
	PrimaryKey() []byte

	// DecryptKeys returns a slice of keys that will be tried when
	// decrypting a cookie.
	//
	// This allows for key rotation, where old keys can still be used to
	// decrypt cookies that were encrypted with them while new cookies are
	// encrypted with the primary key.
	DecryptKeys() [][]byte
}

// KeyLength is the length of a key in bytes.
const KeyLength = chacha20poly1305.KeySize

// SingleKey is a KeyProvider that returns a single key as the PrimaryKey and
// no DecryptKeys.
type SingleKey []byte

// PrimaryKey implements the KeyProvider interface.
func (sk SingleKey) PrimaryKey() []byte {
	return sk
}

// DecryptKeys implements the KeyProvider interface.
func (sk SingleKey) DecryptKeys() [][]byte {
	return nil
}

// NewKey generates a new random key of the correct length.
func NewKey() []byte {
	key := make([]byte, KeyLength)
	if _, err := rand.Read(key); err != nil {
		panic(err) // rand.Read should never fail
	}
	return key
}
