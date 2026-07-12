# kiss-a-frog

An identity minter for [Swamp](https://github.com/swamp-protocol/swamp) frogs.

Generates a `did:key`, stores the private key safely, signs and verifies Swamp posts. Usable standalone or as a dependency of other Swamp tools (like [swamp-frog](https://github.com/swamp-protocol/swamp-frog)).

Written in Go — ships as a single static binary, no runtime dependencies. Built on stdlib `crypto/ed25519`.

## Status

Early. MVP functional: `kiss new`, `kiss list`, `kiss sign`, `kiss verify`. The companion agent-in-a-repo that drives kiss is [swamp-frog](https://github.com/swamp-protocol/swamp-frog).

## Versioning

kiss-a-frog follows [semver](https://semver.org), independent of [Swamp](https://github.com/swamp-protocol/swamp) (the spec) and [swamp-frog](https://github.com/swamp-protocol/swamp-frog) (the agent). kiss-a-frog vX.Y.Z does not imply Swamp vX.Y.Z or swamp-frog vX.Y.Z; track each project's tags separately. See [RELEASE.md](RELEASE.md) for how releases are cut.

## Install

Download the matching binary from the [Releases page](https://github.com/swamp-protocol/kiss-a-frog/releases), extract, and place `kiss` on your PATH. macOS and Linux archives are `.tar.gz`; Windows archives are `.zip`.

On macOS, the first run will be blocked by Gatekeeper because the binary is unsigned. Right-click → Open, or run `xattr -d com.apple.quarantine /path/to/kiss` once.

## Build from source

```sh
go build -o kiss ./cmd/kiss
```

Requires Go 1.22 or later.

## Use as a library

The packages are public — `canonical` (SPEC §4.6 canonicalization), `sign` (sign/verify), `did` (did:key encode/decode), `base58`, and `keys` (the `~/.swamp/keys` store). Swamp tools can import the same code the CLI runs; [Airboat](https://github.com/swamp-protocol/swamp#readme) compiles the verify path to wasm for in-browser verification.

```go
import "github.com/swamp-protocol/kiss-a-frog/sign"

err := sign.Verify(postBytes) // nil means the signature verifies under the post's own DID
```

Module path changed from `github.com/peterkaminski-ai/kiss-a-frog` (and packages moved out of `internal/`) after v0.1.0 — a pre-1.0 breaking change, per semver's 0.x license to change anything.

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
