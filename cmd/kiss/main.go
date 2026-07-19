// Command kiss is the kiss-a-frog CLI — a Swamp identity minter.
//
//	kiss new     mint an Ed25519 did:key identity from BIP-39 words (SPEC §3.3)
//	kiss list    list local keys
//	kiss sign    sign a Swamp post (canonicalize + append signature block)
//	kiss verify  verify a signed Swamp post
package main

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/swamp-protocol/kiss-a-frog/did"
	"github.com/swamp-protocol/kiss-a-frog/keys"
	"github.com/swamp-protocol/kiss-a-frog/sign"
	"github.com/swamp-protocol/kiss-a-frog/words"
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
  kiss new [--name NAME] [--authored-by DID]   mint an identity from fresh words (BIP-39)
           [--index N] [--passphrase P]
           [--raw]                             mint from raw entropy instead (no words backup)
           [--yes]                             skip interactive confirmations
  kiss new --from-words [flags as above]       recover an identity from existing words
  kiss list                                    list local keys
  kiss sign   --key DID  <file>                sign a Swamp post in place
  kiss verify            <file>                verify a signed Swamp post
  kiss version                                 print version info

Keys are stored at ~/.swamp/keys/<did-short>/. Minting shows the words once
and never stores them (Swamp SPEC §3.3); the paper is the backup. With
--from-words, the words are read from stdin.
`)
}

func cmdNew(args []string) error {
	fs := flag.NewFlagSet("new", flag.ExitOnError)
	name := fs.String("name", "", "display name for this key (optional)")
	authoredBy := fs.String("authored-by", "", "DID of the principal this key speaks for (optional)")
	fromWords := fs.Bool("from-words", false, "recover an identity from an existing mnemonic (read from stdin)")
	raw := fs.Bool("raw", false, "mint from raw entropy with no words backup (pre-§3.3 behavior)")
	index := fs.Uint("index", 0, "identity index i for the SLIP-0010 path m/i' (default 0)")
	passphrase := fs.String("passphrase", "", "optional BIP-39 passphrase (advanced; unrecoverable by design)")
	yes := fs.Bool("yes", false, "skip interactive confirmations (needed when stdin is not a terminal)")
	fs.Parse(args)

	if *raw {
		if *fromWords {
			return errors.New("--raw and --from-words are mutually exclusive")
		}
		k, err := keys.New(*name, *authoredBy)
		if err != nil {
			return err
		}
		printMinted(k)
		return nil
	}

	derivation := fmt.Sprintf("bip39/slip10 m/%d'", *index)

	if *fromWords {
		mnemonic, err := readMnemonic()
		if err != nil {
			return err
		}
		priv, err := words.DeriveIdentity(mnemonic, *passphrase, uint32(*index))
		if err != nil {
			return err
		}
		pub := priv.Public().(ed25519.PublicKey)
		// SPEC §3.3: recovery MUST display the derived DID before saving, so
		// a wrong word, passphrase, or index surfaces as a visible mismatch.
		d, err := did.Encode(pub)
		if err != nil {
			return err
		}
		fmt.Printf("Derived %s (path m/%d')\n", d, *index)
		if !*yes {
			ok, err := confirm("Is this the identity you expected? Save it? [y/N] ")
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("not saved (check words, passphrase, and --index; pass --yes to skip this prompt)")
			}
		}
		k, err := keys.Store(pub, priv, *name, *authoredBy, derivation)
		if err != nil {
			return err
		}
		printMinted(k)
		return nil
	}

	// Words-first mint (SPEC §3.3): show the words once, never store them.
	mnemonic, err := words.New()
	if err != nil {
		return err
	}
	priv, err := words.DeriveIdentity(mnemonic, *passphrase, uint32(*index))
	if err != nil {
		return err
	}
	fmt.Printf(`Your identity words (BIP-39). WRITE THESE DOWN ON PAPER — they are shown
once and never stored. Anyone with the words IS this identity; without
them, a lost key is an identity reset.

    %s

`, mnemonic)
	if !*yes {
		ok, err := confirm("Have you written the words down? [y/N] ")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("not saved — write the words down and run kiss new again")
		}
	}
	k, err := keys.Store(priv.Public().(ed25519.PublicKey), priv, *name, *authoredBy, derivation)
	if err != nil {
		return err
	}
	printMinted(k)
	return nil
}

func printMinted(k *keys.Key) {
	fmt.Printf("Minted %s\n", k.DID)
	fmt.Printf("  stored at %s\n", k.Dir)
	if k.Meta.DisplayName != "" {
		fmt.Printf("  display: %s\n", k.Meta.DisplayName)
	}
	if k.Meta.AuthoredBy != "" {
		fmt.Printf("  authored_by: %s\n", k.Meta.AuthoredBy)
	}
	if k.Meta.Derivation != "" {
		fmt.Printf("  derivation: %s\n", k.Meta.Derivation)
	}
}

// stdin is shared by all interactive prompts so buffered input is never lost
// between them.
var stdin = bufio.NewReader(os.Stdin)

// stdinIsTTY reports whether stdin is an interactive terminal.
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// readMnemonic reads the recovery words: prompted line-by-line on a terminal
// (empty line ends), or all of stdin when piped.
func readMnemonic() (string, error) {
	if !stdinIsTTY() {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	fmt.Print("Enter your words (finish with an empty line):\n> ")
	var lines []string
	for {
		line, err := stdin.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
		if err != nil || line == "" {
			break
		}
		fmt.Print("> ")
	}
	return strings.Join(lines, " "), nil
}

// confirm asks a yes/no question on the terminal. When stdin is not a
// terminal it cannot ask, so it refuses — pass --yes for non-interactive use.
func confirm(prompt string) (bool, error) {
	if !stdinIsTTY() {
		return false, errors.New("stdin is not a terminal; pass --yes to confirm non-interactively")
	}
	fmt.Print(prompt)
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
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
