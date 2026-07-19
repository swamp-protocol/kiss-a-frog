// BIP-39 mnemonic encoding: entropy <-> words, checksum validation, and the
// PBKDF2 stretch from mnemonic to seed. Stdlib only, like the rest of kiss.
//
// Spec: https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039.mediawiki
// Swamp binding: SPEC §3.3 — new identities are minted as 12 words (128-bit
// entropy); recovery accepts 12/15/18/21/24 words and rejects a failed
// checksum. The full words -> DID pinning (SLIP-0010 m/i′) is in slip10.go.
package words

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
)

// word -> index, built once. Lookup is on lowercased input; the English
// wordlist is ASCII, so any word needing further NFKD normalization simply
// won't be found and validation fails safely.
var wordIndex = func() map[string]int {
	m := make(map[string]int, len(wordlist))
	for i, w := range wordlist {
		m[w] = i
	}
	return m
}()

// Valid word counts and their entropy sizes: CS = ENT/32, MS = (ENT+CS)/11.
var wordsToEntropyBytes = map[int]int{12: 16, 15: 20, 18: 24, 21: 28, 24: 32}

// FromEntropy encodes entropy as a mnemonic sentence: append the first ENT/32
// bits of SHA-256(entropy) as checksum, then read 11-bit groups as wordlist
// indices. Entropy must be 16/20/24/28/32 bytes.
func FromEntropy(entropy []byte) (string, error) {
	switch len(entropy) {
	case 16, 20, 24, 28, 32:
	default:
		return "", fmt.Errorf("words: entropy must be 16/20/24/28/32 bytes, got %d", len(entropy))
	}
	csBits := len(entropy) / 4 // ENT/32
	hash := sha256.Sum256(entropy)
	entBits := len(entropy) * 8
	totalBits := entBits + csBits
	bit := func(i int) int {
		if i < entBits {
			return int(entropy[i>>3]>>(7-(i&7))) & 1
		}
		i -= entBits
		return int(hash[i>>3]>>(7-(i&7))) & 1
	}
	out := make([]string, 0, totalBits/11)
	for start := 0; start < totalBits; start += 11 {
		idx := 0
		for b := start; b < start+11; b++ {
			idx = idx<<1 | bit(b)
		}
		out = append(out, wordlist[idx])
	}
	return strings.Join(out, " "), nil
}

// New generates a fresh 12-word mnemonic from 128 bits of CSPRNG entropy.
func New() (string, error) {
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("words: entropy: %w", err)
	}
	return FromEntropy(entropy)
}

// Normalize splits user input into normalized words: lowercase, any
// whitespace (including newlines from a pasted numbered list) as separator.
func Normalize(mnemonic string) []string {
	return strings.Fields(strings.ToLower(mnemonic))
}

// Validate checks a mnemonic — word count in {12,15,18,21,24}, every word on
// the list, checksum bits match — and returns the entropy it encodes.
// SPEC §3.3: a failed checksum MUST be rejected; deriving from a mis-copied
// word would silently mint a stranger.
func Validate(mnemonic string) ([]byte, error) {
	ws := Normalize(mnemonic)
	entBytes, ok := wordsToEntropyBytes[len(ws)]
	if !ok {
		return nil, fmt.Errorf("words: expected 12, 15, 18, 21, or 24 words, got %d", len(ws))
	}
	var unknown []string
	bits := make([]int, 0, len(ws)*11)
	for _, w := range ws {
		idx, ok := wordIndex[w]
		if !ok {
			unknown = append(unknown, w)
			continue
		}
		for b := 10; b >= 0; b-- {
			bits = append(bits, (idx>>b)&1)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("words: not on the BIP-39 English wordlist: %s", strings.Join(unknown, ", "))
	}
	entropy := make([]byte, entBytes)
	for i := 0; i < entBytes*8; i++ {
		entropy[i>>3] = entropy[i>>3]<<1 | byte(bits[i])
	}
	hash := sha256.Sum256(entropy)
	for i := 0; i < entBytes/4; i++ {
		if bits[entBytes*8+i] != int(hash[i>>3]>>(7-(i&7)))&1 {
			return nil, fmt.Errorf("words: checksum mismatch — a word is wrong, missing, or out of order")
		}
	}
	return entropy, nil
}

// Seed stretches a mnemonic into the 64-byte BIP-39 seed:
// PBKDF2-HMAC-SHA512, 2048 iterations, password = mnemonic, salt =
// "mnemonic" || passphrase. It does NOT validate the checksum — call Validate
// first; BIP-39 deliberately lets any string stretch, but kiss only ever
// seeds identities from checksum-valid words.
//
// BIP-39 specifies NFKD normalization of both inputs. The mnemonic side is
// covered: Normalize'd English-wordlist words are ASCII, where NFKD is the
// identity. Passphrases are required to be ASCII for the same reason —
// a non-ASCII passphrase returns an error rather than risking a derivation
// other tools would disagree with.
func Seed(mnemonic, passphrase string) ([]byte, error) {
	for _, r := range passphrase {
		if r > unicode.MaxASCII {
			return nil, fmt.Errorf("words: non-ASCII passphrase not supported (BIP-39 requires NFKD normalization; use ASCII to stay portable across tools)")
		}
	}
	password := strings.Join(Normalize(mnemonic), " ")
	return pbkdf2SHA512([]byte(password), []byte("mnemonic"+passphrase), 2048, 64), nil
}

// DeriveIdentity runs the whole SPEC §3.3 pipeline: validate the words,
// stretch to a seed, derive SLIP-0010 m/index′, and return the Ed25519
// private key. Nothing downstream of the returned key knows words were
// involved.
func DeriveIdentity(mnemonic, passphrase string, index uint32) (ed25519.PrivateKey, error) {
	if _, err := Validate(mnemonic); err != nil {
		return nil, err
	}
	seed, err := Seed(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	edSeed, err := DerivePath(seed, []uint32{index})
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(edSeed), nil
}

// pbkdf2SHA512 is PBKDF2 (RFC 8018 §5.2) with HMAC-SHA512, inlined to keep
// kiss dependency-free (crypto/pbkdf2 arrived in the stdlib after our
// baseline Go version).
func pbkdf2SHA512(password, salt []byte, iterations, keyLen int) []byte {
	out := make([]byte, 0, keyLen)
	var block uint32
	for len(out) < keyLen {
		block++
		mac := hmac.New(sha512.New, password)
		mac.Write(salt)
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], block)
		mac.Write(ctr[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha512.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
