package canonical

import (
	"bytes"
	"testing"
)

func mustCanon(t *testing.T, in string) string {
	t.Helper()
	out, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatalf("Canonicalize err: %v", err)
	}
	return string(out)
}

func TestCRLFNormalized(t *testing.T) {
	got := mustCanon(t, "From: a\r\nDID: x\r\n\r\nbody\r\n")
	want := "From: a\nDID: x\n\nbody\n"
	if got != want {
		t.Errorf("CRLF:\n got: %q\nwant: %q", got, want)
	}
}

func TestLoneCRNormalized(t *testing.T) {
	got := mustCanon(t, "From: a\rDID: x\r\rbody\r")
	want := "From: a\nDID: x\n\nbody\n"
	if got != want {
		t.Errorf("lone CR:\n got: %q\nwant: %q", got, want)
	}
}

func TestTrailingWhitespaceTrimmed(t *testing.T) {
	in := "From: a  \t\nDID: x \n\nbody line  \nmore \t\n"
	got := mustCanon(t, in)
	want := "From: a\nDID: x\n\nbody line\nmore\n"
	if got != want {
		t.Errorf("trailing ws:\n got: %q\nwant: %q", got, want)
	}
}

func TestBOMStripped(t *testing.T) {
	in := "\ufeffFrom: a\nDID: x\n\nbody\n"
	got := mustCanon(t, in)
	if bytes.HasPrefix([]byte(got), []byte{0xEF, 0xBB, 0xBF}) {
		t.Errorf("BOM not stripped: %q", got)
	}
	want := "From: a\nDID: x\n\nbody\n"
	if got != want {
		t.Errorf("BOM:\n got: %q\nwant: %q", got, want)
	}
}

func TestExtraBlankLinesBetweenHeadersAndBodyCollapsed(t *testing.T) {
	in := "From: a\nDID: x\n\n\n\nbody\n"
	got := mustCanon(t, in)
	want := "From: a\nDID: x\n\nbody\n"
	if got != want {
		t.Errorf("extra blank lines:\n got: %q\nwant: %q", got, want)
	}
}

func TestBlankLinesInBodyPreserved(t *testing.T) {
	// After the headers/body separator is settled, further blank lines in
	// the body must be preserved — they carry meaning (e.g., grouping in
	// sightings, paragraph breaks in markdown).
	in := "From: a\nDID: x\n\nline 1\n\nline 2\n\n\nline 3\n"
	got := mustCanon(t, in)
	want := "From: a\nDID: x\n\nline 1\n\nline 2\n\n\nline 3\n"
	if got != want {
		t.Errorf("body blanks:\n got: %q\nwant: %q", got, want)
	}
}

func TestIdempotent(t *testing.T) {
	in := "From: a  \r\nDID: x\r\n\r\n\r\nbody \t\r\n"
	once := mustCanon(t, in)
	twice := mustCanon(t, once)
	if once != twice {
		t.Errorf("not idempotent:\nonce:  %q\ntwice: %q", once, twice)
	}
}

func TestNonUTF8Rejected(t *testing.T) {
	if _, err := Canonicalize([]byte{0xff, 0xfe, 0xfd}); err == nil {
		t.Error("expected error on non-UTF-8 input")
	}
}
