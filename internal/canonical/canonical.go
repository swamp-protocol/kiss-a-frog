// Package canonical implements the canonicalization rules for signing Swamp
// posts (SPEC §4.6 Signature).
//
// Rules (envelope-level):
//
//   - UTF-8.
//   - LF line endings. CRLF and lone CR are normalized to LF.
//   - No trailing whitespace (ASCII space or tab) on any line.
//   - Exactly one blank line separates the header block from the body.
//   - No leading UTF-8 BOM.
//
// Canonicalize is loud about malformed bytes where possible. Non-UTF-8 input
// returns an error rather than being silently coerced. Header folding is
// deferred to a higher layer (the caller parses headers if they need to).
package canonical

import (
	"bytes"
	"errors"
	"strings"
	"unicode/utf8"
)

// ErrNotUTF8 is returned when the input is not valid UTF-8.
var ErrNotUTF8 = errors.New("canonical: input is not valid UTF-8")

// Canonicalize returns the canonical byte form of a Swamp post input suitable
// for signing.
//
// The input is expected to be the full post envelope (headers + blank line +
// body), without the signature block. Callers that want to sign a post
// strip the signature block first.
func Canonicalize(b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		return nil, ErrNotUTF8
	}
	// Strip UTF-8 BOM if present.
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})

	// Normalize CRLF and lone CR to LF.
	s := string(b)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	// Trim trailing ASCII whitespace (space, tab) from each line.
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}

	// Collapse the first run of blank lines between headers and body to
	// exactly one blank line. "Between headers and body" = the first blank
	// line that appears after any non-blank line.
	//
	// We do this by walking once: as soon as we've seen a non-blank line
	// and then hit a blank, we emit exactly one blank and then skip any
	// further consecutive blanks.
	var out []string
	seenNonBlank := false
	collapsedHeaderSep := false
	i := 0
	for i < len(lines) {
		line := lines[i]
		if !collapsedHeaderSep && seenNonBlank && line == "" {
			out = append(out, "")
			for i < len(lines) && lines[i] == "" {
				i++
			}
			collapsedHeaderSep = true
			continue
		}
		if line != "" {
			seenNonBlank = true
		}
		out = append(out, line)
		i++
	}

	return []byte(strings.Join(out, "\n")), nil
}
