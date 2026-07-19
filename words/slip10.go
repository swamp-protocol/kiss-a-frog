// SLIP-0010 key derivation for Ed25519: BIP-39 seed -> master key -> hardened
// children. Stdlib HMAC-SHA512 only.
//
// Spec: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// Ed25519 has hardened derivation only — every index is offset by 2^31, and
// there is no public-parent derivation. The 32-byte key that falls out is a
// standard Ed25519 private-key seed, which feeds crypto/ed25519 exactly like
// a randomly minted one.
//
// Swamp's path convention (SPEC §3.3): identity i lives at m/i′, default
// m/0′. No BIP-44 coin-type ceremony.
package words

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
)

const hardenedOffset = 0x80000000

type slip10Node struct {
	key       []byte // 32-byte Ed25519 private-key seed
	chainCode []byte // 32 bytes
}

// masterFromSeed computes the SLIP-0010 master node:
// I = HMAC-SHA512(key = "ed25519 seed", seed); IL is the key, IR the chain code.
func masterFromSeed(seed []byte) slip10Node {
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(seed)
	i := mac.Sum(nil)
	return slip10Node{key: i[:32], chainCode: i[32:]}
}

// deriveHardened computes the hardened child:
// I = HMAC-SHA512(chainCode, 0x00 || key || ser32(index + 2^31)).
// index is the UNhardened index (0 for m/0′); must be < 2^31.
func deriveHardened(parent slip10Node, index uint32) (slip10Node, error) {
	if index >= hardenedOffset {
		return slip10Node{}, fmt.Errorf("words: hardened index must be < 2^31, got %d", index)
	}
	data := make([]byte, 0, 1+32+4)
	data = append(data, 0x00)
	data = append(data, parent.key...)
	var ser [4]byte
	binary.BigEndian.PutUint32(ser[:], hardenedOffset+index)
	data = append(data, ser[:]...)
	mac := hmac.New(sha512.New, parent.chainCode)
	mac.Write(data)
	i := mac.Sum(nil)
	return slip10Node{key: i[:32], chainCode: i[32:]}, nil
}

// DerivePath derives the Ed25519 private-key seed at path m/i0′/i1′/... from
// a BIP-39 seed. Indices are given unhardened; hardening is implied
// (Ed25519-only). Returns the 32-byte seed.
func DerivePath(seed []byte, indices []uint32) ([]byte, error) {
	node := masterFromSeed(seed)
	for _, i := range indices {
		var err error
		node, err = deriveHardened(node, i)
		if err != nil {
			return nil, err
		}
	}
	return node.key, nil
}
