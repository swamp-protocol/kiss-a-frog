package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/swamp-protocol/kiss-a-frog/did"
)

// buildPost assembles a minimal valid-looking Swamp post using the provided DID.
//
// The Swamp-Version and Content-Type v= values are header text the
// canonicalizer treats as opaque; these tests don't depend on them. They
// track the current spec version as a courtesy. RELEASE.md notes a
// reminder to bump them when the spec moves.
func buildPost(d string) string {
	return strings.Join([]string{
		"Swamp-Version: 0.7.0",
		"From: Test",
		"DID: " + d,
		"Message-ID: 2026-04-24-test-abcd",
		"Date: 2026-04-24T10:00-0700",
		"Content-Type: application/swamp; kind=post; v=0.7.0",
		"",
		"Hello, Swamp.",
		"",
	}, "\n")
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d, err := did.Encode(pub)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign([]byte(buildPost(d)), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.Contains(string(signed), "-----BEGIN SIGNATURE-----") {
		t.Fatal("signed output missing signature block")
	}
	if err := Verify(signed); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := did.Encode(pub)
	signed, err := Sign([]byte(buildPost(d)), priv)
	if err != nil {
		t.Fatal(err)
	}
	// flip a byte in the body
	tampered := []byte(strings.Replace(string(signed), "Hello, Swamp.", "Hello, Wamp!", 1))
	if err := Verify(tampered); err == nil {
		t.Error("expected verification to fail on tampered body")
	}
}

func TestSignIsCanonicalization(t *testing.T) {
	// Two cosmetically different inputs (CRLF + trailing whitespace) must
	// sign to the same bytes.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	d, _ := did.Encode(pub)
	base := buildPost(d)

	a, err := Sign([]byte(base), priv)
	if err != nil {
		t.Fatal(err)
	}
	// reformat with CRLF and trailing spaces
	bumpy := strings.ReplaceAll(base, "\n", "  \r\n")
	b, err := Sign([]byte(bumpy), priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("canonicalization failed: whitespace variant produced different signed bytes\n a: %q\n b: %q", a, b)
	}
}

func TestSignRejectsInputWithSignatureBlock(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	already := "From: x\nDID: did:key:zxxx\n\nbody\n\n-----BEGIN SIGNATURE-----\nAAAA\n-----END SIGNATURE-----\n"
	if _, err := Sign([]byte(already), priv); err == nil {
		t.Error("expected Sign to reject input that already has a signature block")
	}
}
