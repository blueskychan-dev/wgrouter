// Command wgrouter is a WireGuard router control panel: it manages a WireGuard
// interface, its peers, and the nftables port forwards that reach them, behind
// a web UI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wgrouter/internal/auth"
	"wgrouter/internal/config"
	"wgrouter/internal/forward"
	"wgrouter/internal/fwlog"
	"wgrouter/internal/ipam"
	"wgrouter/internal/server"
	"wgrouter/internal/store"
	"wgrouter/internal/wg"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

// reconcileInterval is how often the kernel is re-synced from the database.
//
// Drift only happens when something outside wgrouter changes kernel state, so
// this is a safety net rather than the primary mechanism: every mutation
// reconciles immediately.
const reconcileInterval = 60 * time.Second

// statsPruneInterval is how often old connection samples are discarded. The
// retention window is measured in days, so checking hourly is ample.
const statsPruneInterval = time.Hour

func main() {
	if err := run(os.Args[1:]); err != nil {
		// flag already prints its own usage message for -h and parse errors.
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(os.Stderr, "wgrouter: %v\n", err)
		}
		os.Exit(1)
	}
}

// run holds the whole program lifecycle. Keeping it separate from main means
// every exit path returns an error rather than calling os.Exit from deep in the
// call stack, so deferred cleanup actually runs.
func run(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return err
	}

	// Before the logger, so the banner sits above the first log line rather
	// than interleaved with it.
	if !cfg.NoBanner {
		printBanner(os.Stderr, version, stderrIsTerminal(), localeIsUTF8())
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Error("close database", "error", err)
		}
	}()

	schema, err := st.SchemaVersion(ctx)
	if err != nil {
		return err
	}

	sessions := auth.NewSessionStore()
	done := make(chan struct{})
	defer close(done)
	sessions.StartSweeper(done)

	plan, err := ipam.NewPlan(cfg.TunnelPool)
	if err != nil {
		return err
	}

	// Bring up the kernel side. A failure here is fatal rather than degraded:
	// a router control panel that cannot reach the kernel would show a
	// confident, entirely fictional view of the network.
	kernel, err := wg.NewKernel()
	if err != nil {
		return err
	}
	defer func() {
		if err := kernel.Close(); err != nil {
			slog.Error("close wireguard netlink socket", "error", err)
		}
	}()

	wgm := wg.NewManager(kernel, st, plan, cfg.WGInterface, cfg.WGListenPort, wg.DefaultMTU)
	if _, err := wgm.EnsureServerKey(ctx); err != nil {
		return err
	}
	if err := wgm.Sync(ctx); err != nil {
		return fmt.Errorf("bring up %s: %w", cfg.WGInterface, err)
	}
	wgm.StartReconciler(ctx, reconcileInterval, done)

	fw, err := forward.NewFirewall(cfg.WANInterface, cfg.WGInterface, cfg.ForwardRateLimit, cfg.ForwardBurst)
	if err != nil {
		return err
	}
	defer func() {
		if err := fw.Close(); err != nil {
			slog.Error("close nftables socket", "error", err)
		}
	}()

	changed, err := forward.EnableIPForwarding()
	if err != nil {
		// Not fatal: forwards will not work, but the tunnel and the admin UI
		// will, and saying so is more useful than refusing to start.
		slog.Error("IPv4 FORWARDING COULD NOT BE ENABLED",
			"error", err,
			"advice", "port forwards will be programmed but no packet will be forwarded until net.ipv4.ip_forward=1")
	} else if changed {
		slog.Info("enabled IPv4 forwarding", "sysctl", "net.ipv4.ip_forward")
	}

	// The reconciler feeds counter deltas into the store, which is what backs
	// the 7-day, 30-day and all-time connection figures.
	rec := forward.NewReconciler(fw, st).WithSink(st)
	rec.Start(ctx, reconcileInterval, done)

	startStatsPruner(ctx, st, done)

	if cfg.ForwardRateLimit == 0 {
		slog.Warn("PORT FORWARD RATE LIMITING IS DISABLED",
			"advice", "-forward-rate-limit 0 means a flood on any forwarded port is passed straight to the peer behind it")
	} else {
		slog.Info("port forward flood protection",
			"new_connections_per_second", cfg.ForwardRateLimit, "burst", cfg.ForwardBurst)
	}

	// Logging configuration lives in the database, so it is read once at
	// startup and cached; the firewall half also decides whether the nftables
	// rules carry a log statement at all.
	logSettings, err := st.LoadLogSettings(ctx)
	if err != nil {
		return err
	}
	if logSettings.FirewallEnabled {
		if err := rec.SetLogDrops(ctx, true); err != nil {
			slog.Error("apply firewall logging", "error", err)
		}
		startFirewallLogReader(ctx, st, done)
	}

	srv, err := server.New(cfg, server.Deps{
		Store:      st,
		Sessions:   sessions,
		WG:         wgm,
		Reconciler: rec,
		Plan:       plan,
		Version:    version,
	})
	if err != nil {
		return err
	}
	srv.StartBackground(done)
	if err := srv.LoadLogSettings(ctx); err != nil {
		return err
	}

	warnOnConfiguration(ctx, cfg, st)

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// No WriteTimeout: the SSE status stream is a long-lived response and a
		// write deadline would sever it on a fixed interval. Read timeouts and
		// IdleTimeout still bound a misbehaving client.
		IdleTimeout: 120 * time.Second,
		// BaseContext is deliberately NOT the signal context. If it were, SIGTERM
		// would cancel every in-flight request's context the instant it arrived
		// -- including the database writes they are part-way through -- and the
		// graceful-shutdown window below would have nothing left to drain.
		// Shutdown already stops new connections and waits for active ones.
		BaseContext: func(net.Listener) context.Context { return context.Background() },
	}

	slog.Info("starting wgrouter",
		"version", version,
		"listen", cfg.ListenAddr,
		"tls", cfg.TLSEnabled(),
		"wg_interface", cfg.WGInterface,
		"tunnel_pool", cfg.TunnelPool.String(),
		"schema_version", schema,
		"db", cfg.DBPath,
	)

	errCh := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLSEnabled() {
			err = httpSrv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
	}

	// Give in-flight requests a moment to finish. The context here must not be
	// the cancelled one, or Shutdown would return immediately.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return <-errCh
}

// startFirewallLogReader tails the kernel log for our own drop records.
//
// A failure to open it is not fatal: the drops still happen and are still
// counted, and only the per-packet detail is missing. Refusing to start the
// router because one log is unavailable would be the wrong trade.
func startFirewallLogReader(ctx context.Context, st *store.Store, done <-chan struct{}) {
	rd, err := fwlog.Open(st)
	if err != nil {
		slog.Warn("FIREWALL LOG UNAVAILABLE", "error", err,
			"advice", "dropped packets are still counted; only the per-packet detail is missing")
		return
	}
	go func() {
		defer rd.Close()
		rd.Run(ctx, done)
	}()
	slog.Info("firewall log reader started")
}

// startStatsPruner drops connection samples older than the retention window.
//
// Only the raw per-interval rows are pruned; the all-time totals live in their
// own table and are never discarded, so trimming history cannot make the
// lifetime figures shrink.
func startStatsPruner(ctx context.Context, st *store.Store, done <-chan struct{}) {
	go func() {
		t := time.NewTicker(statsPruneInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := st.PruneStats(ctx, time.Now())
				if err != nil {
					slog.ErrorContext(ctx, "prune connection statistics", "error", err)
					continue
				}
				if n > 0 {
					slog.InfoContext(ctx, "pruned connection statistics", "rows", n)
				}
			}
		}
	}()
}

// warnOnConfiguration prints the loud startup warnings the brief asks for.
func warnOnConfiguration(ctx context.Context, cfg *config.Config, st *store.Store) {
	if cfg.PublicListen() {
		slog.Warn("ADMIN UI IS NOT BOUND TO THE TUNNEL",
			"listen", cfg.ListenAddr,
			"advice", "the admin panel is reachable from outside the WireGuard tunnel; bind it to "+cfg.ServerIP.String()+" unless this is deliberate")
	}
	if !cfg.TLSEnabled() {
		slog.Warn("SERVING PLAIN HTTP",
			"advice", "session cookies cannot be marked Secure and credentials cross the network in the clear; acceptable inside the WireGuard tunnel, not outside it. Set -tls-cert and -tls-key to serve HTTPS")
	}

	n, err := st.UserCount(ctx)
	if err != nil {
		slog.Error("count users", "error", err)
		return
	}
	if n == 0 {
		slog.Warn("FIRST-RUN SETUP PENDING",
			"advice", "no administrator account exists; nothing but the setup wizard is served until one is created")
	}
}
