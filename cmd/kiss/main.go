// Command kiss is the kiss-a-frog CLI — a Swamp identity minter.
//
//	kiss new     generate a new Ed25519 keypair and did:key
//	kiss list    list local keys
//	kiss sign    sign a Swamp post (canonicalize + append signature block)
//	kiss verify  verify a signed Swamp post
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"

	"github.com/swamp-protocol/kiss-a-frog/keys"
	"github.com/swamp-protocol/kiss-a-frog/sign"
)

// Populated by goreleaser via -ldflags at release build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "new":
		err = cmdNew(args)
	case "list":
		err = cmdList(args)
	case "sign":
		err = cmdSign(args)
	case "verify":
		err = cmdVerify(args)
	case "version", "--version", "-v":
		fmt.Printf("kiss %s (commit %s, built %s)\n", version, commit, date)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "kiss: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "kiss %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `kiss — a Swamp identity minter

Usage:
  kiss new [--name NAME] [--authored-by DID]   mint a fresh did:key keypair
  kiss list                                    list local keys
  kiss sign   --key DID  <file>                sign a Swamp post in place
  kiss verify            <file>                verify a signed Swamp post
  kiss version                                 print version info

Keys are stored at ~/.swamp/keys/<did-short>/.
`)
}

func cmdNew(args []string) error {
	fs := flag.NewFlagSet("new", flag.ExitOnError)
	name := fs.String("name", "", "display name for this key (optional)")
	authoredBy := fs.String("authored-by", "", "DID of the principal this key speaks for (optional)")
	fs.Parse(args)

	k, err := keys.New(*name, *authoredBy)
	if err != nil {
		return err
	}
	fmt.Printf("Minted %s\n", k.DID)
	fmt.Printf("  stored at %s\n", k.Dir)
	if k.Meta.DisplayName != "" {
		fmt.Printf("  display: %s\n", k.Meta.DisplayName)
	}
	if k.Meta.AuthoredBy != "" {
		fmt.Printf("  authored_by: %s\n", k.Meta.AuthoredBy)
	}
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.Parse(args)

	ks, err := keys.List()
	if err != nil {
		return err
	}
	if len(ks) == 0 {
		fmt.Println("No keys yet. Try: kiss new")
		return nil
	}
	for _, k := range ks {
		name := k.Meta.DisplayName
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Printf("%s  %s\n", k.DID, name)
	}
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyDID := fs.String("key", "", "DID of the key to sign with (required)")
	fs.Parse(args)
	if *keyDID == "" {
		return errors.New("--key DID is required")
	}
	if fs.NArg() != 1 {
		return errors.New("expected exactly one file argument")
	}
	file := fs.Arg(0)

	k, err := findKey(*keyDID)
	if err != nil {
		return err
	}
	in, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	out, err := sign.Sign(in, k.Private)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, out, 0o644); err != nil {
		return err
	}
	fmt.Printf("Signed %s with %s\n", file, k.DID)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("expected exactly one file argument")
	}
	file := fs.Arg(0)

	in, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if err := sign.Verify(in); err != nil {
		return err
	}
	fmt.Printf("OK %s\n", file)
	return nil
}

// findKey returns the key whose full DID matches, or whose directory name
// (the short fingerprint) matches the provided string.
func findKey(idOrDID string) (*keys.Key, error) {
	ks, err := keys.List()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.New("no keys found; run `kiss new` first")
		}
		return nil, err
	}
	for _, k := range ks {
		if k.DID == idOrDID {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no key matching %q (try `kiss list`)", idOrDID)
}
