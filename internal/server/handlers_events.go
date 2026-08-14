package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"wgrouter/internal/forward"
)

// sseInterval is how often the live device stream emits an update.
//
// Handshake times only change every 25s at the fastest (the keepalive
// interval), so polling the kernel harder than this would burn netlink round
// trips to redraw identical numbers.
const sseInterval = 5 * time.Second

// deviceEvent is the payload pushed to the device list.
type deviceEvent struct {
	ID            int64  `json:"id"`
	Presence      string `json:"presence"`
	PresenceLabel string `json:"presenceLabel"`
	Endpoint      string `json:"endpoint"`
	LastHandshake string `json:"lastHandshake"`
	Rx            string `json:"rx"`
	Tx            string `json:"tx"`
	InKernel      bool   `json:"inKernel"`
}

// handleEvents streams live peer state as Server-Sent Events.
//
// SSE rather than a websocket: this is a one-way stream of small updates, it
// works through any proxy that handles chunked responses, and the browser
// reconnects on its own. There is nothing to send upstream, so the second half
// of a websocket would be dead weight.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	// http.ResponseController rather than a w.(http.Flusher) type assertion.
	// The access-log middleware wraps the ResponseWriter, and a wrapper does
	// not satisfy Flusher just because the thing it wraps does -- the
	// assertion fails and the stream dies before it starts. ResponseController
	// follows the Unwrap chain instead.
	rc := http.NewResponseController(w)
	flush := func() bool { return rc.Flush() == nil }

	if s.wgm == nil {
		http.Error(w, "wireguard is not available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	// Without this, a reverse proxy that buffers responses would hold every
	// event until the stream closed, which is never.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if !flush() {
		// Nothing downstream can stream; say so rather than leaving the client
		// waiting on a response that will never arrive incrementally.
		slog.WarnContext(r.Context(), "sse: response writer cannot flush")
		return
	}

	ticker := time.NewTicker(sseInterval)
	defer ticker.Stop()

	send := func() bool {
		snap, err := s.wgm.Snapshot(r.Context(), time.Now())
		if err != nil {
			slog.DebugContext(r.Context(), "sse snapshot", "error", err)
			return true // a transient read failure should not end the stream
		}
		events := make([]deviceEvent, 0, len(snap.Peers))
		for _, p := range snap.Peers {
			events = append(events, deviceEvent{
				ID:            p.ID,
				Presence:      string(p.Presence),
				PresenceLabel: p.PresenceLabel,
				Endpoint:      p.Endpoint,
				LastHandshake: humanSince(p.LastHandshake),
				Rx:            humanBytes(p.RxBytes),
				Tx:            humanBytes(p.TxBytes),
				InKernel:      p.InKernel,
			})
		}
		payload, err := json.Marshal(events)
		if err != nil {
			slog.ErrorContext(r.Context(), "marshal sse payload", "error", err)
			return true
		}
		if _, err := fmt.Fprintf(w, "event: peers\ndata: %s\n\n", payload); err != nil {
			return false // the client went away
		}
		return flush()
	}

	if !send() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}

// loadForwards fills in the forwarding table, joined with what the kernel
// actually has.
func (s *Server) loadForwards(r *http.Request, d *pageData) error {
	d.ForwardModes = srcModeOptions()

	fwds, err := s.store.Forwards(r.Context())
	if err != nil {
		return err
	}

	var status forward.Status
	if s.rec != nil {
		status = s.rec.Status()
		if !status.At.IsZero() {
			d.ReconcileAt = status.At.Format("2006-01-02 15:04:05")
		}
		if status.Err != nil {
			d.ReconcileErr = status.Err.Error()
		}
	}

	for _, f := range fwds {
		row := forwardRow{
			ID:         f.ID,
			Label:      f.Label,
			Proto:      string(f.Proto),
			Listen:     f.Listen.String(),
			IsRange:    f.Listen.IsRange(),
			PeerID:     f.PeerID,
			PeerName:   f.PeerName,
			TargetIP:   f.TargetIP.String(),
			TargetPort: f.TargetPort,
			SrcMode:    string(f.SrcMode),
			ModeLabel:  f.SrcMode.Label(),
			RateLimit:  f.RateLimit,
			SrcPolicy:  string(f.SrcPolicy),
			PolicyLbl:  f.SrcPolicy.Label(),
			Sources:    forward.FormatSources(f.Sources),
			Enabled:    f.Enabled,
			InKernel:   f.Enabled && status.InKernel(f.ID),
		}
		if w, err := s.store.ForwardStats(r.Context(), f.ID, time.Now()); err == nil {
			row.Accepted7d = w.Day7.Accepted
			row.Dropped7d = w.Day7.Dropped
			row.AcceptedAll = w.AllTime.Accepted
			row.DroppedAll = w.AllTime.Dropped
		}
		switch f.SrcMode {
		case forward.SrcModeDirect:
			row.Warn = "The peer must route replies back through the tunnel, or connections will hang."
		}
		d.Forwards = append(d.Forwards, row)
	}
	return nil
}

// srcModeOptions describes the source-preservation choices for the create form.
func srcModeOptions() []modeOption {
	return []modeOption{
		{
			Value:    string(forward.SrcModeMasquerade),
			Label:    forward.SrcModeMasquerade.Label(),
			Help:     "Always works. The peer sees the router's address, not the client's; wgrouter records the real origin in its own log.",
			Selected: true,
		},
		{
			Value: string(forward.SrcModeDirect),
			Label: forward.SrcModeDirect.Label(),
			Help:  "The peer sees the real client address. Requires the peer's AllowedIPs to cover the clients it must reply to -- usually 0.0.0.0/0 -- or replies leave by the wrong path and connections hang.",
		},
	}
}

// countOnline is used by the status page.
func countOnline(rows []deviceRow) int {
	n := 0
	for _, r := range rows {
		if r.Presence == "online" {
			n++
		}
	}
	return n
}
