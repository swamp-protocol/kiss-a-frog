# kiss-a-frog

An identity minter for [Swamp](https://github.com/peterkaminski-ai/swamp) frogs.

Generates a `did:key`, stores the private key safely, signs and verifies Swamp posts. Usable standalone or as a dependency of other Swamp tools (like [swamp-frog](https://github.com/peterkaminski-ai/swamp-frog)).

Written in Go — ships as a single static binary, no runtime dependencies. Built on stdlib `crypto/ed25519`.

## Status

Early. MVP functional: `kiss new`, `kiss list`, `kiss sign`, `kiss verify`. The companion agent-in-a-repo that drives kiss is [swamp-frog](https://github.com/peterkaminski-ai/swamp-frog).

## Versioning

kiss-a-frog follows [semver](https://semver.org), independent of [Swamp](https://github.com/peterkaminski-ai/swamp) (the spec) and [swamp-frog](https://github.com/peterkaminski-ai/swamp-frog) (the agent). kiss-a-frog vX.Y.Z does not imply Swamp vX.Y.Z or swamp-frog vX.Y.Z; track each project's tags separately. See [RELEASE.md](RELEASE.md) for how releases are cut.

## Install

Download the matching binary from the [Releases page](https://github.com/peterkaminski-ai/kiss-a-frog/releases), extract, and place `kiss` on your PATH. macOS and Linux archives are `.tar.gz`; Windows archives are `.zip`.

On macOS, the first run will be blocked by Gatekeeper because the binary is unsigned. Right-click → Open, or run `xattr -d com.apple.quarantine /path/to/kiss` once.

## Build from source

```sh
go build -o kiss ./cmd/kiss
```

Requires Go 1.22 or later.

## Use

```sh
# mint a fresh keypair; prints the did:key
kiss new --name "Your Name"

# list local keys
kiss list

# sign a Swamp post in place (file is rewritten with a signature block)
kiss sign --key did:key:z6Mk... path/to/post.txt

# verify a signed post
kiss verify path/to/post.txt
```

Keys are stored at `~/.swamp/keys/<did-short>/`:

- `private.pem` — PKCS#8 Ed25519 private key, mode `0600`
- `public.pem` — matching public key
- `meta.json` — display name, authored-by, created-at

On Windows keys live under `%USERPROFILE%\.swamp\keys\`. ACL tightening on Windows is tracked separately.

## Canonicalization (SPEC §4.6 Signature)

Signing and verifying both canonicalize the signed byte range: UTF-8, LF line endings (CRLF and lone CR are normalized), no trailing whitespace on any line, exactly one blank line between headers and body, no leading BOM. Non-UTF-8 input is rejected, not coerced.

## License

TBD.
