package base58

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00, 0x01},
		{0xff, 0xff, 0xff, 0xff},
		bytes.Repeat([]byte{0xab}, 34),
	}
	for _, c := range cases {
		enc := Encode(c)
		got, err := Decode(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if !bytes.Equal(got, c) {
			t.Errorf("round-trip mismatch: in=%x enc=%s out=%x", c, enc, got)
		}
	}
}

// A real Ed25519 did:key from the W3C did-method-key spec.
// Decode the multibase-z body, confirm the 0xed 0x01 multicodec prefix and
// 32-byte payload, then re-encode and confirm we reproduce the input.
// This exercises base58btc decode + encode symmetry on a known artifact
// without relying on a pubkey literal typed from memory.
func TestDidKeyRoundTrip(t *testing.T) {
	const did = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
	if did[0] != 'z' {
		t.Fatalf("expected multibase z prefix")
	}
	body, err := Decode(did[1:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 34 {
		t.Fatalf("expected 34 bytes (2 prefix + 32 key), got %d", len(body))
	}
	if body[0] != 0xed || body[1] != 0x01 {
		t.Fatalf("expected ed25519-pub multicodec prefix 0xed 0x01, got %x %x", body[0], body[1])
	}
	reenc := "z" + Encode(body)
	if reenc != did {
		t.Errorf("re-encode mismatch:\n got:  %s\n want: %s", reenc, did)
	}
}
