package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// bannerBlock is the startup banner, drawn with box-drawing characters.
const bannerBlock = `
 ██╗    ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗ 
 ██║    ██║██╔════╝ ██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║ █╗ ██║██║  ███╗██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝
 ██║███╗██║██║   ██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗
 ╚███╔███╔╝╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║
  ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝
`

// bannerPlain is the same thing for terminals that are not on a UTF-8 locale,
// where the block characters above would render as mojibake.
const bannerPlain = `
__          __  _____  _____   ____  _    _ _______ ______ _____
\ \        / / / ____||  __ \ / __ \| |  | |__   __|  ____|  __ \
 \ \  /\  / / | |  __ | |__) | |  | | |  | |  | |  | |__  | |__) |
  \ \/  \/ /  | | |_ ||  _  /| |  | | |  | |  | |  |  __| |  _  /
   \  /\  /   | |__| || | \ \| |__| | |__| |  | |  | |____| | \ \
    \/  \/     \_____||_|  \_\ \____/ \____/   |_|  |______||_|  \_\
`

// printBanner writes the startup banner.
//
// It goes to stderr, the same stream as the logs, but only when that stream is
// a terminal. Under systemd or in a container the logs are machine-parsed --
// journald, a log shipper, `grep` -- and six lines of box drawing at the top of
// every restart is noise in exactly the place someone is trying to read an
// error. So the banner is for a human watching a foreground run, and nobody
// else.
func printBanner(w io.Writer, version string, interactive, utf8 bool) {
	if !interactive {
		return
	}

	art, line, sep := bannerBlock, "─", "·"
	if !utf8 {
		art, line, sep = bannerPlain, "-", "-"
	}

	// The rule is sized from the tagline rather than a fixed width, so the two
	// cannot drift apart when the wording or the version string changes.
	tagline := fmt.Sprintf("WireGuard router control panel %s %s everything over netlink, no shell-outs",
		version, sep)
	rule := strings.Repeat(line, len([]rune(tagline)))

	fmt.Fprint(w, art)
	fmt.Fprintf(w, " %s\n", rule)
	fmt.Fprintf(w, " %s\n", tagline)
	fmt.Fprintf(w, " %s\n\n", rule)
}

// stderrIsTerminal reports whether stderr is attached to a terminal.
//
// os.Stat on the file handle rather than an isatty dependency: a character
// device is the distinction that matters here, and it costs one syscall.
func stderrIsTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// localeIsUTF8 reports whether the environment claims a UTF-8 locale.
//
// Checked because the block-drawing banner is unreadable without it, and a
// wall of replacement characters is a worse first impression than plain ASCII.
func localeIsUTF8() bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := os.Getenv(key)
		if v == "" {
			continue
		}
		return strings.Contains(strings.ToUpper(v), "UTF-8") ||
			strings.Contains(strings.ToUpper(v), "UTF8")
	}
	return false
}
