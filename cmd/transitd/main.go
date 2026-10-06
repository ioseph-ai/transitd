// Command transitd is the per-router transit management agent.
//
// This build is OBSERVE-ONLY: it verifies probe pinning, measures per-transit
// latency/loss, runs the decision engine, and exports metrics and health — but
// it applies nothing to the router. Applying a decision needs the act package
// (issue #4), which does not exist yet; see internal/agent.
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

	"github.com/ioseph-ai/transitd/internal/agent"
	"github.com/ioseph-ai/transitd/internal/config"
)

// version is set by goreleaser ldflags.
var version = "dev"

// shutdownGrace bounds how long the metrics listener may take to drain. It is
// short on purpose: the listener serves scrapes, and the agent's real shutdown
// work (stopping probe loops) happens first and instantly.
const shutdownGrace = 5 * time.Second

func main() {
	cfgPath := flag.String("config", "/etc/transitd.yaml", "path to config file")
	interval := flag.Duration("interval", 0, "decision-evaluation cadence (default the probe interval, 30s)")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Println("transitd", version)
		return
	}

	if err := run(*cfgPath, *interval); err != nil {
		slog.Error("transitd exited", "err", err)
		os.Exit(1)
	}
}

// run owns the process lifecycle: load → wire → serve → drain. Returning an
// error is the only way out that is not a clean signal-triggered shutdown.
func run(cfgPath string, interval time.Duration) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	// The local control channel (issue #2) exists exactly when a mesh key is
	// configured: it authenticates with that key, so an agent with no key has
	// nothing to protect a control endpoint with. The socket path comes from
	// control.socket_path (default /run/transitd/ctrl.sock).
	ag, err := agent.New(agent.Options{
		Config:        cfg,
		Interval:      interval,
		ControlSocket: cfg.Gossip.Enabled(),
	})
	if err != nil {
		return err
	}

	// The agent's loop owns every goroutine that could still be working; its
	// context is therefore the parent of the server's, so a SIGTERM stops probe
	// loops and the http server in that order.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	ln, err := net.Listen("tcp", cfg.ListenMetrics)
	if err != nil {
		return fmt.Errorf("metrics listener: %w", err)
	}
	srv := &http.Server{
		Handler:           ag.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()

	// Serve in the background so the signal path below is the only thing that
	// decides when the listener stops.
	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	slog.Info("transitd started",
		"version", version, "router", cfg.RouterName, "config", cfgPath,
		"metrics", ln.Addr().String(), "observe_only", true)

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received: stopping probe loops and closing metrics listener")
	case err := <-runErr:
		if err != nil {
			_ = srv.Close()
			return err
		}
		// The agent loop stopped on its own; nothing is left to serve.
		if err := srv.Close(); err != nil {
			return fmt.Errorf("metrics close: %w", err)
		}
		slog.Info("transitd stopped cleanly")
		return nil
	case err := <-serveErr:
		// srv.Serve only returns spontaneously when it fails, so this is the
		// metrics surface disappearing: stop the agent rather than run blind.
		stop()
		<-runErr
		if err != nil {
			return fmt.Errorf("metrics server: %w", err)
		}
		return errors.New("metrics server: closed unexpectedly")
	}

	// Shutdown path: ctx was cancelled (SIGTERM/SIGINT). The agent loop shares
	// it, so waiting for runErr is waiting for the probe loops to stop — the
	// order the card asks for. Only then is the listener drained.
	if err := <-runErr; err != nil {
		_ = srv.Close()
		return err
	}
	drainCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		return fmt.Errorf("metrics shutdown: %w", err)
	}
	slog.Info("transitd stopped cleanly")
	return nil
}
