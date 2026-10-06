package bgpwatch

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
)

// Runner executes one vtysh query and returns its stdout. It is the seam that
// makes bgpwatch testable without FRR: production passes ExecRunner, tests pass
// a recording fake.
//
// The interface is deliberately `show`-shaped, not vtysh-shaped: a caller can
// express a query, not a batch. There is no way to reach configuration mode
// through it.
type Runner interface {
	// Show runs a single `show ...` command through vtysh and returns stdout.
	// The command must be one vtysh accepts after `show` (e.g. "bgp summary
	// json"); implementations add the `show` verb themselves.
	Show(ctx context.Context, query string) (string, error)
}

// ExecRunner is the production Runner: it execs `vtysh -c 'show <query>'`.
//
// The command is passed as one argv element, never through a shell, so a query
// built from config cannot be word-split into extra vtysh commands. That is the
// only config-derived input this package has; everything else is a literal
// written here.
type ExecRunner struct {
	// Binary overrides the program; empty means "vtysh" on PATH.
	Binary string
	// Timeout bounds one query. Zero means DefaultQueryTimeout. A hung vtysh
	// must not wedge the poller: it would stall every transit's session view at
	// once.
	Timeout time.Duration
}

// DefaultQueryTimeout bounds one `show ... json` invocation.
const DefaultQueryTimeout = 5 * time.Second

// Show impl execs vtysh for one query.
func (r ExecRunner) Show(ctx context.Context, query string) (string, error) {
	bin := r.Binary
	if bin == "" {
		bin = "vtysh"
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultQueryTimeout
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// `show` is prepended here, not by the caller, so the caller's vocabulary
	// has no verb in it at all: there is no string it can build that is not a
	// show command.
	cmd := exec.CommandContext(qctx, bin, "-c", "show "+query) //nolint:gosec // fixed binary, literal verb, argv slice, no shell
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return stdout.String(), fmt.Errorf("vtysh %q exited %d: %s", query, ee.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), fmt.Errorf("vtysh %q: %w", query, err)
	}
	return stdout.String(), nil
}

// Poller holds the bounded polling state for one router's BGP view.
//
// It owns no goroutine of its own: Run drives the cadence and a test can call
// the individual Show* methods synchronously with a fake Runner and a fake
// clock. That is the same shape as probes.Loop, for the same reason.
type Poller struct {
	// Runner executes vtysh queries. Nil means an ExecRunner.
	Runner Runner

	// MaxPrefixes caps a prefix-level parse. Zero means
	// config.DefaultMaxPrefixes.
	MaxPrefixes int

	// Interval is the poll cadence. It is floored at
	// config.MinBGPWatchInterval regardless of what is set here — the 1 Hz cap
	// is enforced in the type, not only in config validation, so a caller that
	// builds a Poller directly cannot poll faster either.
	Interval time.Duration

	// Emit receives a Session observation for every configured transit's
	// neighbor after each successful summary poll. Nil means no callback.
	Emit func(Session)

	// Clock is the time source; nil means time.Now.
	Clock func() time.Time

	lastPoll time.Time
	mu       sync.Mutex
}

// New builds a Poller over cfg with production defaults filled in.
func New(cfg config.BGPWatchConfig, r Runner) *Poller {
	if r == nil {
		r = ExecRunner{}
	}
	p := &Poller{
		Runner:      r,
		MaxPrefixes: cfg.MaxPrefixes,
		Interval:    cfg.Interval,
	}
	if p.MaxPrefixes <= 0 {
		p.MaxPrefixes = config.DefaultMaxPrefixes
	}
	if p.Interval <= 0 {
		p.Interval = config.DefaultBGPWatchInterval
	}
	if p.Interval < config.MinBGPWatchInterval {
		p.Interval = config.MinBGPWatchInterval
	}
	return p
}

// interval resolves the effective cadence with the floor applied.
func (p *Poller) interval() time.Duration {
	if p.Interval <= 0 {
		return config.DefaultBGPWatchInterval
	}
	if p.Interval < config.MinBGPWatchInterval {
		return config.MinBGPWatchInterval
	}
	return p.Interval
}

// maxPrefixes resolves the effective prefix cap.
func (p *Poller) maxPrefixes() int {
	if p.MaxPrefixes <= 0 {
		return config.DefaultMaxPrefixes
	}
	return p.MaxPrefixes
}

// tooSoon reports whether a poll is inside the 1 Hz window, and records the
// attempt. It is the enforcement point for the cadence cap: whatever a caller
// does — a second Run, a burst of direct Show* calls — no two polls leave inside
// the floor.
func (p *Poller) tooSoon() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if !p.lastPoll.IsZero() && now.Sub(p.lastPoll) < config.MinBGPWatchInterval {
		return true
	}
	p.lastPoll = now
	return false
}

func (p *Poller) now() time.Time {
	if p.Clock != nil {
		return p.Clock()
	}
	return time.Now()
}

// AF is an address family for the prefix-level views.
type AF string

const (
	// AFIPv4 is the ipv4 unicast view.
	AFIPv4 AF = "ipv4"
	// AFIPv6 is the ipv6 unicast view.
	AFIPv6 AF = "ipv6"
)

// Summary polls `show bgp summary json` and returns the parsed IPv4 unicast
// session view. `show bgp summary` is equivalent to the ipv4 unicast view on
// FRR; the explicit form is used so the query names what it reads.
//
// It is subject to the 1 Hz cap: a call inside the window returns
// ErrRateLimited.
func (p *Poller) Summary(ctx context.Context) (Summary, error) {
	if p.tooSoon() {
		return Summary{}, ErrRateLimited
	}
	out, err := p.Runner.Show(ctx, "bgp summary json")
	if err != nil {
		return Summary{}, err
	}
	return ParseSummary(out)
}

// Prefixes polls `show bgp <af> unicast json` and returns the prefix-level view,
// capped at MaxPrefixes. A table larger than the cap is ErrTooManyPrefixes, not
// a truncated result.
func (p *Poller) Prefixes(ctx context.Context, af AF) ([]Prefix, error) {
	if p.tooSoon() {
		return nil, ErrRateLimited
	}
	query, err := afPrefixQuery(af)
	if err != nil {
		return nil, err
	}
	out, err := p.Runner.Show(ctx, query+" json")
	if err != nil {
		return nil, err
	}
	return ParsePrefixes(out, p.maxPrefixes())
}

// BestPath polls `show bgp <af> <prefix> json` and returns the selected path for
// one prefix. A prefix FRR holds no path for is a valid answer with
// BestPath.Exists false, not an error.
func (p *Poller) BestPath(ctx context.Context, af AF, prefix string) (BestPath, error) {
	if p.tooSoon() {
		return BestPath{}, ErrRateLimited
	}
	query, err := afPrefixQuery(af)
	if err != nil {
		return BestPath{}, err
	}
	out, err := p.Runner.Show(ctx, query+" "+prefix+" json")
	if err != nil {
		return BestPath{}, err
	}
	return ParseBestPath(out, prefix)
}

// afPrefixQuery maps an address family to the vtysh view name.
func afPrefixQuery(af AF) (string, error) {
	switch af {
	case AFIPv4:
		return "bgp ipv4 unicast", nil
	case AFIPv6:
		return "bgp ipv6 unicast", nil
	default:
		return "", fmt.Errorf("bgpwatch: unknown address family %q", af)
	}
}

// Run polls the session view on the cadence until ctx is cancelled, calling
// Emit for each configured transit's neighbor after every successful poll. A
// poll error is reported to the caller-supplied OnError (if set) and the loop
// continues: a transient vtysh failure must not kill the session view forever.
//
// transits is the configured set; only transits with a BGPNeighbor are emitted.
func (p *Poller) Run(ctx context.Context, transits []config.Transit, onErr func(error)) {
	poll := func() {
		sum, err := p.Summary(ctx)
		if err != nil {
			if onErr != nil {
				onErr(err)
			}
			return
		}
		if p.Emit == nil {
			return
		}
		for _, t := range transits {
			if t.BGPNeighbor == "" {
				continue
			}
			s, ok := sum.Sessions[t.BGPNeighbor]
			if !ok {
				// The neighbor is configured but absent from the summary: a
				// session FRR does not know about. Emit a hard-down observation
				// rather than nothing, so a transit whose peer entry vanished is
				// not silently treated as up.
				s = Session{Neighbor: t.BGPNeighbor, State: "Unknown", Up: false}
			}
			p.Emit(s)
		}
	}
	poll()
	t := time.NewTicker(p.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			poll()
		}
	}
}
