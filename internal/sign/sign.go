// Package sign handles signing and verifying Swamp posts per SPEC §4.6 Signature.
//
// A signed post looks like:
//
//	<headers>
//
//	<body>
//
//	-----BEGIN SIGNATURE-----
//	<base64(signature)>
//	-----END SIGNATURE-----
//
// The signature covers the canonical bytes from the first character of
// `From:` through the trailing newline of the blank line separating body
// from signature block.
package sign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/peterkaminski-ai/kiss-a-frog/internal/canonical"
	"github.com/peterkaminski-ai/kiss-a-frog/internal/did"
)

const (
	beginMarker = "-----BEGIN SIGNATURE-----"
	endMarker   = "-----END SIGNATURE-----"
)

// Sign canonicalizes the unsigned post bytes, appends a signature block, and
// returns the full signed-post bytes.
//
// `unsigned` must be the post headers + blank line + body, without a
// signature block. If a signature block is present, Sign returns an error —
// callers should strip it first (Strip) or resign by explicit intent.
func Sign(unsigned []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if bytes.Contains(unsigned, []byte(beginMarker)) {
		return nil, errors.New("sign: input already contains a signature block")
	}
	canon, err := canonical.Canonicalize(unsigned)
	if err != nil {
		return nil, err
	}
	canon = ensureBlankLineTerminator(canon)

	sig := ed25519.Sign(priv, canon)
	block := beginMarker + "\n" + base64.StdEncoding.EncodeToString(sig) + "\n" + endMarker + "\n"

	out := make([]byte, 0, len(canon)+len(block))
	out = append(out, canon...)
	out = append(out, []byte(block)...)
	return out, nil
}

// Verify parses a signed post, looks up its DID header, and verifies the
// Ed25519 signature over the canonicalized signed range.
func Verify(signed []byte) error {
	signedPart, sigBytes, err := split(signed)
	if err != nil {
		return err
	}
	canon, err := canonical.Canonicalize(signedPart)
	if err != nil {
		return err
	}
	canon = ensureBlankLineTerminator(canon)

	d, err := findDID(canon)
	if err != nil {
		return err
	}
	pub, err := did.Decode(d)
	if err != nil {
		return fmt.Errorf("verify: bad DID header: %w", err)
	}
	if !ed25519.Verify(pub, canon, sigBytes) {
		return errors.New("verify: signature does not match")
	}
	return nil
}

// Strip removes any signature block from bytes and returns the signed-range
// portion. Useful for re-signing.
func Strip(b []byte) []byte {
	idx := bytes.Index(b, []byte(beginMarker))
	if idx < 0 {
		return b
	}
	return bytes.TrimRight(b[:idx], "\n") // caller re-canonicalizes
}

// split separates a signed post into (signed range, raw signature bytes).
func split(b []byte) ([]byte, []byte, error) {
	beginIdx := bytes.Index(b, []byte(beginMarker))
	if beginIdx < 0 {
		return nil, nil, errors.New("verify: no signature block found")
	}
	endIdx := bytes.Index(b, []byte(endMarker))
	if endIdx < 0 || endIdx < beginIdx {
		return nil, nil, errors.New("verify: truncated signature block")
	}
	// signed range = everything before the begin marker, trimmed so that
	// canonicalization collapses trailing blank lines to one.
	signedRange := b[:beginIdx]

	// extract base64 payload between the two markers.
	inner := b[beginIdx+len(beginMarker) : endIdx]
	inner = bytes.TrimSpace(inner)
	sig, err := base64.StdEncoding.DecodeString(string(inner))
	if err != nil {
		return nil, nil, fmt.Errorf("verify: bad base64 signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("verify: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return signedRange, sig, nil
}

// findDID pulls the DID: header value out of canonical post bytes.
func findDID(canon []byte) (string, error) {
	for _, line := range strings.Split(string(canon), "\n") {
		if line == "" {
			break // end of headers
		}
		if strings.HasPrefix(line, "DID:") {
			return strings.TrimSpace(line[len("DID:"):]), nil
		}
	}
	return "", errors.New("verify: no DID header found")
}

// ensureBlankLineTerminator ensures the byte slice ends with "\n\n" — body
// final newline + one blank line separator — matching SPEC §4.6 Signature's
// "trailing newline of the final blank line between body and signature block".
func ensureBlankLineTerminator(b []byte) []byte {
	b = bytes.TrimRight(b, "\n")
	return append(b, '\n', '\n')
}
