// Package base58 implements Bitcoin-flavored base58 (base58btc) encoding
// as used in multibase "z" and did:key.
package base58

import (
	"errors"
	"math/big"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var decodeMap [256]int8

func init() {
	for i := range decodeMap {
		decodeMap[i] = -1
	}
	for i, c := range alphabet {
		decodeMap[byte(c)] = int8(i)
	}
}

// Encode returns the base58btc encoding of b.
// Leading zero bytes are preserved as leading '1' characters.
func Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(b)
	div := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, div, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, alphabet[0])
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// Decode returns the bytes represented by the base58btc string s.
func Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == alphabet[0] {
		zeros++
	}
	n := new(big.Int)
	base := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		v := decodeMap[s[i]]
		if v < 0 {
			return nil, errors.New("base58: invalid character")
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(v)))
	}
	raw := n.Bytes()
	out := make([]byte, zeros+len(raw))
	copy(out[zeros:], raw)
	return out, nil
}
