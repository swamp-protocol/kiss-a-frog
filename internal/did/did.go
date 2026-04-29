// Package did encodes and decodes did:key identifiers for Ed25519 keys.
//
// did:key format for Ed25519:
//
//	did:key:z<multibase-base58btc(0xed 0x01 || pubkey32)>
//
// 0xed is the multicodec for ed25519-pub; the trailing 0x01 is the second byte
// of its unsigned varint encoding. The "z" is the multibase prefix for
// base58btc. See https://w3c-ccg.github.io/did-method-key/.
package did

import (
	"crypto/ed25519"
	"errors"
	"strings"

	"github.com/peterkaminski-ai/kiss-a-frog/internal/base58"
)

// Prefix bytes for ed25519-pub multicodec (0xed, varint-encoded).
var ed25519Prefix = []byte{0xed, 0x01}

// Encode returns the did:key string for an Ed25519 public key.
func Encode(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", errors.New("did: ed25519 public key must be 32 bytes")
	}
	buf := make([]byte, 0, len(ed25519Prefix)+len(pub))
	buf = append(buf, ed25519Prefix...)
	buf = append(buf, pub...)
	return "did:key:z" + base58.Encode(buf), nil
}

// Decode parses a did:key string and returns the embedded Ed25519 public key.
// It only accepts the ed25519-pub multicodec; other key types return an error.
func Decode(did string) (ed25519.PublicKey, error) {
	const methodPrefix = "did:key:z"
	if !strings.HasPrefix(did, methodPrefix) {
		return nil, errors.New("did: not a did:key with multibase-z body")
	}
	body, err := base58.Decode(did[len(methodPrefix):])
	if err != nil {
		return nil, err
	}
	if len(body) != len(ed25519Prefix)+ed25519.PublicKeySize {
		return nil, errors.New("did: unexpected body length for ed25519-pub")
	}
	if body[0] != ed25519Prefix[0] || body[1] != ed25519Prefix[1] {
		return nil, errors.New("did: not an ed25519-pub multicodec")
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, body[len(ed25519Prefix):])
	return pub, nil
}

// Short returns a short fingerprint of a did:key suitable for filesystem paths.
// Uses the characters after "did:key:z" truncated to n runes.
func Short(did string, n int) string {
	const methodPrefix = "did:key:z"
	if !strings.HasPrefix(did, methodPrefix) {
		return did
	}
	body := did[len(methodPrefix):]
	if len(body) <= n {
		return body
	}
	return body[:n]
}
