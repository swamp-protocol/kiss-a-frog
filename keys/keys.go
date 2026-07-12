// Package keys generates Ed25519 keypairs and stores them on disk under the
// Swamp keystore layout: ~/.swamp/keys/<did-short>/ with private.pem,
// public.pem, and meta.json.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/swamp-protocol/kiss-a-frog/did"
)

const (
	privatePEM = "private.pem"
	publicPEM  = "public.pem"
	metaJSON   = "meta.json"
	didShortN  = 12
)

// Meta is the sidecar JSON stored next to each key.
type Meta struct {
	DID         string    `json:"did"`
	DisplayName string    `json:"display_name,omitempty"`
	AuthoredBy  string    `json:"authored_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Key is a loaded or freshly generated keypair with its did:key and on-disk
// location.
type Key struct {
	DID     string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
	Dir     string
	Meta    Meta
}

// Root returns the Swamp keystore root directory. It does not create it.
func Root() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".swamp", "keys"), nil
}

// New generates a fresh Ed25519 keypair, encodes its did:key, and writes the
// PEM + meta files to ~/.swamp/keys/<did-short>/. Returns the loaded Key.
func New(displayName, authoredBy string) (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	d, err := did.Encode(pub)
	if err != nil {
		return nil, err
	}
	root, err := Root()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, did.Short(d, didShortN))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, privatePEM)); err == nil {
		return nil, fmt.Errorf("refusing to overwrite existing key at %s", dir)
	}

	privPKCS8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privPKCS8}
	if err := writePrivateFile(filepath.Join(dir, privatePEM), pem.EncodeToMemory(privBlock)); err != nil {
		return nil, err
	}

	pubPKIX, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubPKIX}
	if err := os.WriteFile(filepath.Join(dir, publicPEM), pem.EncodeToMemory(pubBlock), 0o644); err != nil {
		return nil, err
	}

	meta := Meta{
		DID:         d,
		DisplayName: displayName,
		AuthoredBy:  authoredBy,
		CreatedAt:   time.Now().UTC(),
	}
	if err := writeMeta(dir, meta); err != nil {
		return nil, err
	}

	return &Key{DID: d, Public: pub, Private: priv, Dir: dir, Meta: meta}, nil
}

// List returns all keys under the keystore root.
func List() ([]*Key, error) {
	root, err := Root()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Key
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		k, err := Load(filepath.Join(root, e.Name()))
		if err != nil {
			continue // skip malformed entries silently in list
		}
		out = append(out, k)
	}
	return out, nil
}

// Load reads a key directory (containing private.pem, public.pem, meta.json).
func Load(dir string) (*Key, error) {
	privBytes, err := os.ReadFile(filepath.Join(dir, privatePEM))
	if err != nil {
		return nil, err
	}
	privBlock, _ := pem.Decode(privBytes)
	if privBlock == nil {
		return nil, errors.New("keys: private.pem is not valid PEM")
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("keys: private.pem is not an Ed25519 key")
	}
	pub := priv.Public().(ed25519.PublicKey)

	var meta Meta
	metaBytes, err := os.ReadFile(filepath.Join(dir, metaJSON))
	if err == nil {
		_ = json.Unmarshal(metaBytes, &meta)
	}
	if meta.DID == "" {
		d, err := did.Encode(pub)
		if err != nil {
			return nil, err
		}
		meta.DID = d
	}
	return &Key{DID: meta.DID, Public: pub, Private: priv, Dir: dir, Meta: meta}, nil
}

func writeMeta(dir string, m Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, metaJSON), append(b, '\n'), 0o644)
}

// writePrivateFile writes data with mode 0600 on Unix. On Windows, Go's file
// mode bits are ignored for ACL purposes; tightening ACLs there is tracked
// separately.
func writePrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
	}
	return nil
}
