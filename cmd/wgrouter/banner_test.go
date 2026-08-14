package main

import (
	"bytes"
	"strings"
	"testing"
)

// The banner is for a human watching a foreground run. Under systemd or in a
// container the logs are machine-parsed, and six lines of box drawing at the
// top of every restart is noise in exactly the place someone is reading an
// error.
func TestBannerIsSuppressedWhenNotATerminal(t *testing.T) {
	var buf bytes.Buffer
	printBanner(&buf, "v1", false, true)
	if buf.Len() != 0 {
		t.Errorf("banner printed to a non-terminal:\n%s", buf.String())
	}
}

func TestBannerPrintsOnATerminal(t *testing.T) {
	var buf bytes.Buffer
	printBanner(&buf, "v1.2.3", true, true)
	out := buf.String()

	if !strings.Contains(out, "v1.2.3") {
		t.Error("the version is missing from the banner")
	}
	if !strings.Contains(out, "█") {
		t.Error("the block art is missing on a UTF-8 terminal")
	}
}

// Without a UTF-8 locale the block characters render as mojibake, so the
// fallback must contain no multi-byte characters at all.
func TestPlainBannerIsPureASCII(t *testing.T) {
	var buf bytes.Buffer
	printBanner(&buf, "v1.2.3", true, false)

	for i, r := range buf.String() {
		if r > 127 {
			t.Fatalf("non-ASCII rune %q at byte %d in the plain banner", r, i)
		}
	}
}

// The rule is drawn to the tagline's width. If they drift apart the banner
// looks broken, and it is the kind of thing nobody notices until it ships.
func TestBannerRuleMatchesTaglineWidth(t *testing.T) {
	for _, utf8 := range []bool{true, false} {
		var buf bytes.Buffer
		printBanner(&buf, "v1.2.3", true, utf8)

		var rule, tagline string
		for _, l := range strings.Split(buf.String(), "\n") {
			l = strings.TrimSpace(l)
			switch {
			case strings.HasPrefix(l, "─") || strings.HasPrefix(l, "---"):
				rule = l
			case strings.HasPrefix(l, "WireGuard router"):
				tagline = l
			}
		}
		if rule == "" || tagline == "" {
			t.Fatalf("utf8=%v: could not find the rule and tagline", utf8)
		}
		if len([]rune(rule)) != len([]rune(tagline)) {
			t.Errorf("utf8=%v: rule is %d wide, tagline is %d",
				utf8, len([]rune(rule)), len([]rune(tagline)))
		}
	}
}

// Every line of the block art must be the same width, or the banner is visibly
// ragged. This catches a mis-pasted letter, which is easy to do and hard to
// spot by eye.
func TestBlockArtIsRectangular(t *testing.T) {
	lines := strings.Split(strings.Trim(bannerBlock, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("block art has %d lines, want 6", len(lines))
	}
	width := len([]rune(lines[0]))
	for i, l := range lines {
		if got := len([]rune(l)); got != width {
			t.Errorf("block art line %d is %d runes wide, want %d:\n%s", i+1, got, width, l)
		}
	}
}

func TestLocaleDetection(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "en_US.UTF-8")
	if !localeIsUTF8() {
		t.Error("en_US.UTF-8 was not detected as UTF-8")
	}

	t.Setenv("LANG", "C")
	if localeIsUTF8() {
		t.Error("the C locale was detected as UTF-8")
	}

	// LC_ALL wins over LANG.
	t.Setenv("LC_ALL", "C")
	t.Setenv("LANG", "en_US.UTF-8")
	if localeIsUTF8() {
		t.Error("LC_ALL=C was overridden by LANG")
	}
}
