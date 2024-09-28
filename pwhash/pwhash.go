// Package pwhash provides a nice wrapper around the golang.org/x/crypto/argon2
// package, controlling concurrency and providing a simple API.
package pwhash

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strconv"

	"golang.org/x/crypto/argon2"
)

// params represents the argon2id parameters used to hash a password.
type params struct {
	time    uint32
	memory  uint32
	threads uint8
}

type Hasher struct {
	sema   chan struct{}
	params params
}

const (
	keyLen        = 16
	maxConcurrent = 2
)

func New(time, memory uint32, threads uint8) *Hasher {
	return &Hasher{
		sema: make(chan struct{}, maxConcurrent),
		params: params{
			time:    time,
			memory:  memory,
			threads: threads,
		},
	}
}

// Hash will hash the given password using the argon2id algorithm with this
// hasher's parameters, and return the encoded password hash.
func (h *Hasher) Hash(password []byte) []byte {
	// Acquire our semaphore by putting a token into the channel; this
	// blocks if the channel is full. Remove the token when we're done.
	h.sema <- struct{}{}
	defer func() { <-h.sema }()

	// Generate a nice random salt for each password.
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		panic(err) // should never happen
	}

	hash := argon2.IDKey(password, salt[:], h.params.time, h.params.memory, h.params.threads, keyLen)
	return h.formatHash(salt[:], hash)
}

// HashString is the same as Hash but it takes and returns a string.
func (h *Hasher) HashString(password string) string {
	return string(h.Hash([]byte(password)))
}

// Verify will verify that the given password matches the given hash.
func (h *Hasher) Verify(password, hash []byte) bool {
	// Parse the input hash into its components first.
	params, salt, hash := splitHash(hash)
	if salt == nil {
		return false // invalid
	}

	// TODO: verify the params; not too large, etc. to avoid a DoS from too
	// much memory/etc.

	// Acquire our semaphore; see above.
	h.sema <- struct{}{}
	defer func() { <-h.sema }()

	// Hash the password with the given salt and the parameters from the hash.
	got := argon2.IDKey(password, salt, params.time, params.memory, params.threads, uint32(len(hash)))

	// Verify that it matches the hash we got.
	if subtle.ConstantTimeCompare(hash, got) != 1 {
		return false
	}

	return true
}

func (h *Hasher) formatHash(salt, hash []byte) []byte {
	// The format of the password hash is chosen to match that of passlib:
	//
	//	https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html
	//	"$argon2id$v=<version>$m=<memory>,t=<time>,p=<threads>$<base64(salt)>$<base64(hash)>"
	//      "$argon2i$v=19$m=512,t=2,p=2$aI2R0hpDyLm3ltLa+1/rvQ$LqPKjd6n8yniKtAithoR7A"
	buf := make([]byte, 0, 75)
	buf = append(buf, "$argon2id$v=19$m="...)
	buf = strconv.AppendInt(buf, int64(h.params.memory), 10)
	buf = append(buf, ",t="...)
	buf = strconv.AppendInt(buf, int64(h.params.time), 10)
	buf = append(buf, ",p="...)
	buf = strconv.AppendInt(buf, int64(h.params.threads), 10)
	buf = append(buf, '$')
	buf = base64.RawStdEncoding.AppendEncode(buf, salt)
	buf = append(buf, '$')
	buf = base64.RawStdEncoding.AppendEncode(buf, hash)
	return buf
}

// splitHash splits a password hash into its components: the parameters, the
// salt, and the hash.
//
// It will return nil slices if anything is invalid.
func splitHash(input []byte) (params, []byte, []byte) {
	// Split into fields separated by '$'.
	fields := bytes.Split(input, []byte{'$'})
	if len(fields) != 6 {
		return params{}, nil, nil
	}

	if !bytes.Equal(fields[1], []byte("argon2id")) {
		return params{}, nil, nil
	}

	// We only support a single version of the hash.
	if !bytes.Equal(fields[2], []byte("v=19")) {
		return params{}, nil, nil
	}

	// Parse the parameters. We don't support them in arbitrary order, so
	// just split and cut them.
	mv, second, ok := bytes.Cut(fields[3], []byte{','})
	tv, pv, ok2 := bytes.Cut(second, []byte{','})
	if !ok || !ok2 {
		return params{}, nil, nil
	}
	if !bytes.HasPrefix(mv, []byte("m=")) || !bytes.HasPrefix(tv, []byte("t=")) || !bytes.HasPrefix(pv, []byte("p=")) {
		return params{}, nil, nil
	}

	memory, err := strconv.ParseUint(string(mv[2:]), 10, 32)
	if err != nil {
		return params{}, nil, nil
	}
	time, err := strconv.ParseUint(string(tv[2:]), 10, 32)
	if err != nil {
		return params{}, nil, nil
	}
	threads, err := strconv.ParseUint(string(pv[2:]), 10, 8)
	if err != nil {
		return params{}, nil, nil
	}

	p := params{uint32(time), uint32(memory), uint8(threads)}

	// Decode the salt and hash.
	salt, err := base64.RawStdEncoding.DecodeString(string(fields[4]))
	if err != nil {
		return params{}, nil, nil
	}
	hash, err := base64.RawStdEncoding.DecodeString(string(fields[5]))
	if err != nil {
		return params{}, nil, nil
	}

	return p, salt, hash
}
