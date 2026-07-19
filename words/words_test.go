// Words -> DID derivation tests: BIP-39 mnemonic encoding and SLIP-0010
// Ed25519 derivation against the OFFICIAL test vectors, then the composed
// words -> did:key pins from Swamp SPEC §3.3.
//
// Vector sources (cited so implementers can self-check):
//
//	BIP-39:    https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//	           (the reference vectors linked from the BIP-39 spec; all use
//	           passphrase "TREZOR")
//	SLIP-0010: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
//	           (test vectors 1 and 2 for Ed25519)
//	Swamp:     SPEC §3.3 self-check vectors (the composition pins)
package words

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/swamp-protocol/kiss-a-frog/did"
)

const abandonMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestWordlistIntegrity(t *testing.T) {
	if len(wordlist) != 2048 {
		t.Fatalf("wordlist has %d words, want 2048", len(wordlist))
	}
	if wordlist[0] != "abandon" || wordlist[2047] != "zoo" {
		t.Errorf("first/last = %q/%q, want abandon/zoo", wordlist[0], wordlist[2047])
	}
	for i := 1; i < len(wordlist); i++ {
		if wordlist[i-1] >= wordlist[i] {
			t.Errorf("wordlist not strictly sorted at %d: %q >= %q", i, wordlist[i-1], wordlist[i])
		}
	}
	// SHA-256 of the canonical english.txt serialization (one word per line,
	// trailing newline) — pins the array to the upstream file byte-for-byte.
	h := sha256.Sum256([]byte(strings.Join(wordlist[:], "\n") + "\n"))
	const want = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	if got := hex.EncodeToString(h[:]); got != want {
		t.Errorf("wordlist hash = %s, want %s", got, want)
	}
}

func TestBIP39OfficialVectors(t *testing.T) {
	// [entropy, mnemonic, seed-with-TREZOR-passphrase]
	vectors := [][3]string{
		{"00000000000000000000000000000000",
			abandonMnemonic,
			"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"},
		{"9e885d952ad362caeb4efe34a8e91bd2",
			"ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
			"274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028"},
		{"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
			"void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
			"01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"},
	}
	for _, v := range vectors {
		entropy, wantMnemonic, wantSeed := unhex(t, v[0]), v[1], v[2]
		n := len(strings.Fields(wantMnemonic))
		m, err := FromEntropy(entropy)
		if err != nil {
			t.Fatalf("%dw FromEntropy: %v", n, err)
		}
		if m != wantMnemonic {
			t.Errorf("%dw entropy -> mnemonic = %q, want %q", n, m, wantMnemonic)
		}
		got, err := Validate(wantMnemonic)
		if err != nil {
			t.Fatalf("%dw Validate: %v", n, err)
		}
		if hex.EncodeToString(got) != v[0] {
			t.Errorf("%dw Validate entropy = %x, want %s", got, n, v[0])
		}
		seed, err := Seed(wantMnemonic, "TREZOR")
		if err != nil {
			t.Fatalf("%dw Seed: %v", n, err)
		}
		if hex.EncodeToString(seed) != wantSeed {
			t.Errorf("%dw seed = %x, want %s", n, seed, wantSeed)
		}
	}
	// Empty-passphrase seed for the all-"abandon" mnemonic — the classic
	// BIP-39 reference seed, used again below in the SPEC §3.3 pins.
	seed, err := Seed(abandonMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	const wantEmpty = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	if hex.EncodeToString(seed) != wantEmpty {
		t.Errorf("empty-passphrase seed = %x, want %s", seed, wantEmpty)
	}
}

func TestValidation(t *testing.T) {
	if _, err := Validate("abandon abandon abandon"); err == nil {
		t.Error("accepted wrong word count")
	}
	if _, err := Validate(strings.Replace(abandonMnemonic, "about", "lilypad", 1)); err == nil {
		t.Error("accepted unknown word")
	}
	if _, err := Validate(strings.TrimSuffix(abandonMnemonic, "about") + "abandon"); err == nil {
		t.Error("accepted bad checksum (last word changed)")
	}
	if _, err := Validate("about " + strings.TrimSuffix(abandonMnemonic, " about")); err == nil {
		t.Error("accepted reordered words (checksum should catch)")
	}
	// Case + arbitrary whitespace normalize away.
	messy := "  Abandon\nabandon abandon abandon abandon abandon\tabandon abandon abandon abandon abandon ABOUT "
	got, err := Validate(messy)
	if err != nil {
		t.Fatalf("messy input rejected: %v", err)
	}
	if hex.EncodeToString(got) != "00000000000000000000000000000000" {
		t.Errorf("messy input entropy = %x", got)
	}
	// 15-word round trip.
	m, err := FromEntropy(make([]byte, 20))
	if err != nil {
		t.Fatal(err)
	}
	if ent, err := Validate(m); err != nil || len(ent) != 20 {
		t.Errorf("15-word round trip: ent=%d err=%v", len(ent), err)
	}
}

func TestNew(t *testing.T) {
	m1, err := New()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(strings.Fields(m1)); n != 12 {
		t.Errorf("New minted %d words, want 12", n)
	}
	if _, err := Validate(m1); err != nil {
		t.Errorf("fresh mnemonic fails own checksum: %v", err)
	}
	if m1 == m2 {
		t.Error("two mints produced identical words")
	}
}

func TestNonASCIIPassphraseRejected(t *testing.T) {
	if _, err := Seed(abandonMnemonic, "passé"); err == nil {
		t.Error("non-ASCII passphrase accepted; NFKD is not implemented, must reject")
	}
}

func TestSLIP10OfficialVectors(t *testing.T) {
	pub := func(seed []byte) string {
		return hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	// Test vector 1, seed 000102...0f.
	{
		seed := unhex(t, "000102030405060708090a0b0c0d0e0f")
		m := masterFromSeed(seed)
		if hex.EncodeToString(m.chainCode) != "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb" {
			t.Errorf("v1 master chain code = %x", m.chainCode)
		}
		if hex.EncodeToString(m.key) != "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7" {
			t.Errorf("v1 master key = %x", m.key)
		}
		if pub(m.key) != "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed" {
			t.Errorf("v1 master pub = %s", pub(m.key))
		}
		m0, err := deriveHardened(m, 0)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(m0.chainCode) != "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69" {
			t.Errorf("v1 m/0' chain code = %x", m0.chainCode)
		}
		if hex.EncodeToString(m0.key) != "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3" {
			t.Errorf("v1 m/0' key = %x", m0.key)
		}
		if pub(m0.key) != "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c" {
			t.Errorf("v1 m/0' pub = %s", pub(m0.key))
		}
		m01, err := deriveHardened(m0, 1)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(m01.key) != "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2" {
			t.Errorf("v1 m/0'/1' key = %x", m01.key)
		}
		path, err := DerivePath(seed, []uint32{0})
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(path) != hex.EncodeToString(m0.key) {
			t.Error("DerivePath([0]) disagrees with step-by-step")
		}
	}
	// Test vector 2, the 64-byte fffcf9... seed.
	{
		seed := unhex(t, "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
		m := masterFromSeed(seed)
		if hex.EncodeToString(m.chainCode) != "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b" {
			t.Errorf("v2 master chain code = %x", m.chainCode)
		}
		if hex.EncodeToString(m.key) != "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012" {
			t.Errorf("v2 master key = %x", m.key)
		}
		m0, err := deriveHardened(m, 0)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(m0.key) != "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635" {
			t.Errorf("v2 m/0' key = %x", m0.key)
		}
	}
}

// TestSpecCompositionPins freezes the full words -> did:key pipeline against
// the Swamp SPEC §3.3 self-check vectors. The two stages are proven against
// official vectors above; these pins freeze the COMPOSITION so every
// conforming Swamp tool derives the same DID from the same words.
func TestSpecCompositionPins(t *testing.T) {
	didFor := func(passphrase string, index uint32) string {
		t.Helper()
		priv, err := DeriveIdentity(abandonMnemonic, passphrase, index)
		if err != nil {
			t.Fatalf("DeriveIdentity(%q, %d): %v", passphrase, index, err)
		}
		d, err := did.Encode(priv.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if got := didFor("", 0); got != "did:key:z6MkrTgzDs6XmRgSKZZhMLvmPm1obfjazbpZ8so3FzchHJhL" {
		t.Errorf("m/0' empty passphrase = %s", got)
	}
	if got := didFor("", 1); got != "did:key:z6Mkj4WAyvo3EZ6q9E7Zn8sBcpddUGQGvtKfDWRAxvduEXYy" {
		t.Errorf("m/1' empty passphrase = %s", got)
	}
	if got := didFor("TREZOR", 0); got != "did:key:z6MkkcTTSPfLk5Ary3xcS3pNxX6roAZczJfUAYiBpk61TcN5" {
		t.Errorf("m/0' TREZOR passphrase = %s", got)
	}
	// The intermediate Ed25519 seed for the first pin, from Lilypad's test
	// suite — a second implementation agreeing on the value.
	seed, err := Seed(abandonMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	edSeed, err := DerivePath(seed, []uint32{0})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(edSeed) != "56d8f4c43bce7186c171808633ba5ce4712b51cedffaa426611c8d7362a82a0c" {
		t.Errorf("m/0' ed25519 seed = %x", edSeed)
	}
	if _, err := DeriveIdentity(strings.TrimSuffix(abandonMnemonic, "about")+"abandon", "", 0); err == nil {
		t.Error("DeriveIdentity accepted checksum-invalid words")
	}
}
