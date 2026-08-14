// Package fwlog turns the kernel's own log stream into firewall events.
//
// nftables' log statement writes to the kernel ring buffer, which is readable
// at /dev/kmsg. Reading a file is not shelling out, and the alternative --
// parsing `dmesg` output -- would be both a subprocess and a format that
// changes between util-linux releases.
//
// The rules that emit these lines are rate-limited in nftables before the line
// is written, so the volume here is bounded by the kernel rather than by the
// attacker.
package fwlog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"wgrouter/internal/forward"
	"wgrouter/internal/store"
)

// kmsgPath is a variable so tests can point it at a fixture.
var kmsgPath = "/dev/kmsg"

// Prefix marks the lines wgrouter emitted. It is the rule builder's own
// constant, so the two cannot drift apart.
const Prefix = forward.LogPrefix

// batchInterval is how long events are buffered before being written.
//
// One transaction per dropped packet would turn a flood into a write storm
// against SQLite; batching bounds that to one transaction per interval.
const batchInterval = 2 * time.Second

// Sink receives parsed events. The store implements it.
type Sink interface {
	RecordFirewallEvents(ctx context.Context, events []store.FirewallEvent) error
}

// Reader tails the kernel log and records matching events.
type Reader struct {
	sink Sink
	f    *os.File
}

// Open starts reading. The caller must Close it.
//
// It seeks to the end first: the ring buffer holds whatever the system has
// logged since boot, and replaying all of it on every start would fill the
// firewall log with history the operator has already seen.
func Open(sink Sink) (*Reader, error) {
	f, err := os.Open(kmsgPath)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("fwlog: open %s: permission denied. "+
				"Reading the kernel log needs CAP_SYSLOG when kernel.dmesg_restrict=1; "+
				"add it to the systemd unit or set dmesg_restrict=0: %w", kmsgPath, err)
		}
		return nil, fmt.Errorf("fwlog: open %s: %w", kmsgPath, err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		// Not fatal: without the seek we replay the buffer once, which is
		// noisy but not wrong.
		slog.Warn("fwlog: could not seek to the end of the kernel log", "error", err)
	}
	return &Reader{sink: sink, f: f}, nil
}

// Close releases the file.
func (r *Reader) Close() error {
	if r.f == nil {
		return nil
	}
	return r.f.Close()
}

// Run reads until the context is cancelled or done is closed.
func (r *Reader) Run(ctx context.Context, done <-chan struct{}) {
	lines := make(chan string, 256)

	// The read loop is its own goroutine because a read on /dev/kmsg blocks
	// until a message arrives, and there is no way to give it a deadline.
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(r.f)
		sc.Buffer(make([]byte, 0, 8192), 65536)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			default:
				// The consumer is behind. Dropping is correct here: these are
				// already rate-limited samples of a flood, not an audit trail.
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()

	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	var batch []store.FirewallEvent
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := r.sink.RecordFirewallEvents(ctx, batch); err != nil {
			slog.ErrorContext(ctx, "record firewall events", "error", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-done:
			flush()
			return
		case <-ctx.Done():
			flush()
			return
		case line, ok := <-lines:
			if !ok {
				flush()
				return
			}
			if ev, matched := Parse(line, time.Now()); matched {
				batch = append(batch, ev)
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Parse extracts an event from one /dev/kmsg record.
//
// The record is "<priority>,<seq>,<usec>,<flags>;<message>", and the message is
// netfilter's own key=value format. Only lines carrying our prefix are ours;
// everything else on the system logs here too.
func Parse(line string, now time.Time) (store.FirewallEvent, bool) {
	_, msg, ok := strings.Cut(line, ";")
	if !ok {
		msg = line
	}
	idx := strings.Index(msg, Prefix)
	if idx < 0 {
		return store.FirewallEvent{}, false
	}
	rest := msg[idx+len(Prefix):]

	// Our own tag is "<forward id>:<reason>", written by the rule builder.
	tag, fields, _ := strings.Cut(rest, " ")
	idPart, reason, _ := strings.Cut(tag, ":")
	forwardID, _ := strconv.ParseInt(idPart, 10, 64)
	if reason == "" {
		reason = "drop"
	}

	ev := store.FirewallEvent{
		At:        now,
		Reason:    reason,
		ForwardID: forwardID,
	}
	for _, kv := range strings.Fields(fields) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "SRC":
			ev.SrcIP = v
		case "DST":
			ev.DstIP = v
		case "PROTO":
			ev.Proto = strings.ToLower(v)
		case "SPT":
			ev.SrcPort, _ = strconv.Atoi(v)
		case "DPT":
			ev.DstPort, _ = strconv.Atoi(v)
		}
	}
	// A line with our prefix but no source address is not useful and almost
	// certainly means the format changed; recording it would fill the log with
	// blank rows that look like a bug in the firewall rather than in the parser.
	if ev.SrcIP == "" {
		return store.FirewallEvent{}, false
	}
	return ev, true
}
