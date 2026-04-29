package did

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Encode(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(d) < 20 || d[:9] != "did:key:z" {
		t.Fatalf("unexpected did: %q", d)
	}
	got, err := Decode(d)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(got) {
		t.Errorf("round-trip pubkey mismatch")
	}
}

func TestDecodeRejectsNonKey(t *testing.T) {
	if _, err := Decode("did:web:example.com"); err == nil {
		t.Error("expected error for did:web")
	}
	if _, err := Decode("not-a-did"); err == nil {
		t.Error("expected error for non-did string")
	}
}

func TestDecodeKnownDid(t *testing.T) {
	const d = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
	pub, err := Decode(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pubkey size %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	// re-encode and confirm we reproduce the input
	got, err := Encode(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got != d {
		t.Errorf("re-encode mismatch: got %s, want %s", got, d)
	}
}
