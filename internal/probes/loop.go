package probes

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
)

// Defaults for the ICMP probe loop. They mirror the latency smoothing named in
// docs/design.md (EWMA) and the loss-drop window the decision engine consumes.
const (
	// DefaultAlpha is the EWMA smoothing factor for latency.
	DefaultAlpha = 0.3
	// DefaultWindow is the rolling loss window, in probe cycles.
	DefaultWindow = 10
	// DefaultTimeoutSec bounds one ping invocation (-W).
	DefaultTimeoutSec = 2
)

// Sample is one transit's aggregated probe observation, emitted once per cycle.
// It is the only thing the rest of the agent sees: the raw ping text never
// leaves this package. A Sample is only ever produced for a transit that passed
// pin verification — see Supervisor.
type Sample struct {
	// Transit is the configured transit name.
	Transit string
	// At is the cycle timestamp, taken from the loop's clock.
	At time.Time
	// LatencyMs is the EWMA of successful reply RTTs. It is NaN until the first
	// reply, so a consumer cannot mistake "no data yet" for "zero latency".
	LatencyMs float64
	// LossPct is packet loss over the rolling window, 0..100.
	LossPct float64
	// Sent and Received are the rolling-window packet counts.
	Sent     int
	Received int
	// Outcome is this cycle's classification, for logging/diagnostics.
	Outcome Outcome
	// Err carries a short diagnostic when this cycle was an invocation error.
	Err string
}

// Loop probes one transit on an interval. It holds only the smoothing state; it
// owns no goroutine of its own, so Run is safe to cancel and a test can drive
// Probe synchronously with a fake Runner and a fake clock.
type Loop struct {
	Transit config.Transit

	// Runner executes ping. Nil means an ExecRunner.
	Runner Runner
	// Variant is the ping implementation; empty means detect once, lazily.
	Variant Variant
	// Family is the address family of the transit's probe target.
	Family Family
	// Interval between cycles; defaults to the transit's ProbeInterval.
	Interval time.Duration
	// Alpha is the latency EWMA factor; 0 means DefaultAlpha.
	Alpha float64
	// Window is the rolling loss window; 0 means DefaultWindow.
	Window int
	// TimeoutSec bounds one ping; 0 means DefaultTimeoutSec.
	TimeoutSec int
	// Clock is the time source; nil means time.Now.
	Clock func() time.Time
	// Emit receives every sample. Nil samples are never emitted.
	Emit func(Sample)

	ewma     float64
	haveEwma bool
	ring     []bool // true = reply, oldest first, capped at Window
}

// NewLoop validates a transit's probe configuration and builds its loop. It
// fails fast on a target that is not an IP or a transit with no source, so a
// misconfiguration surfaces at startup rather than as a ping error every cycle.
func NewLoop(t config.Transit, r Runner) (*Loop, error) {
	if t.ProbeSource == "" {
		return nil, fmt.Errorf("transit %q: probe_source is required", t.Name)
	}
	fam, err := FamilyOf(t.ProbeTarget)
	if err != nil {
		return nil, fmt.Errorf("transit %q: probe_target: %w", t.Name, err)
	}
	if _, err := FamilyOf(t.ProbeSource); err != nil {
		return nil, fmt.Errorf("transit %q: probe_source: %w", t.Name, err)
	}
	if r == nil {
		r = ExecRunner{}
	}
	interval := t.ProbeInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Loop{
		Transit:  t,
		Runner:   r,
		Family:   fam,
		Interval: interval,
	}, nil
}

// Alpha resolves the EWMA factor with its default.
func (l *Loop) alpha() float64 {
	if l.Alpha > 0 {
		return l.Alpha
	}
	return DefaultAlpha
}

// window resolves the loss window size with its default.
func (l *Loop) window() int {
	if l.Window > 0 {
		return l.Window
	}
	return DefaultWindow
}

func (l *Loop) clock() time.Time {
	if l.Clock != nil {
		return l.Clock()
	}
	return time.Now()
}

// Probe runs exactly one cycle and returns the sample. It performs no sleeping;
// Run owns the cadence. It is exported so tests can step the loop
// deterministically.
func (l *Loop) Probe(ctx context.Context) Sample {
	if l.Variant == "" {
		l.Variant = DetectVariant(ctx, l.Runner)
	}

	timeout := l.TimeoutSec
	if timeout <= 0 {
		timeout = DefaultTimeoutSec
	}

	stdout, stderr, _, runErr := l.Runner.Run(ctx, "ping",
		argsFor(l.Variant, l.Family, l.Transit.ProbeSource, l.Transit.ProbeTarget, timeout)...)

	res := PingResult{Outcome: OutcomeError, Err: "runner error"}
	if runErr != nil {
		res.Err = runErr.Error()
	} else {
		res = ParsePing(stdout, stderr)
	}

	switch res.Outcome {
	case OutcomeReply:
		l.observe(true)
		if l.haveEwma {
			l.ewma = l.alpha()*res.RttMs + (1-l.alpha())*l.ewma
		} else {
			l.ewma = res.RttMs
			l.haveEwma = true
		}
	case OutcomeTimeout:
		l.observe(false)
	case OutcomeFragNeeded, OutcomeError:
		// Neither is a loss observation: a frag-needed probe never left, and
		// an invocation error is not a network event. Neither touches the
		// window, so neither can move the loss percentage.
	}

	s := Sample{
		Transit:  l.Transit.Name,
		At:       l.clock(),
		LossPct:  l.lossPct(),
		Sent:     l.sent(),
		Received: l.received(),
		Outcome:  res.Outcome,
		Err:      res.Err,
	}
	if l.haveEwma {
		s.LatencyMs = l.ewma
	} else {
		s.LatencyMs = math.NaN()
	}
	return s
}

// Run probes on the interval until ctx is cancelled, emitting each sample. A
// cycle that produces nothing observable (a timeout, an invocation error) still
// emits: loss is data, and the decision engine must see it.
func (l *Loop) Run(ctx context.Context) {
	// Probe immediately so a freshly started agent has a sample at t=0 rather
	// than after one full interval.
	l.emit(l.Probe(ctx))
	t := time.NewTicker(l.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.emit(l.Probe(ctx))
		}
	}
}

// emit calls the callback if set.
func (l *Loop) emit(s Sample) {
	if l.Emit != nil {
		l.Emit(s)
	}
}

// observe records one cycle outcome in the rolling window.
func (l *Loop) observe(reply bool) {
	w := l.window()
	l.ring = append(l.ring, reply)
	if len(l.ring) > w {
		l.ring = l.ring[len(l.ring)-w:]
	}
}

// lossPct is packet loss over the observed window. It is 0 before any cycle.
func (l *Loop) lossPct() float64 {
	if len(l.ring) == 0 {
		return 0
	}
	fail := 0
	for _, ok := range l.ring {
		if !ok {
			fail++
		}
	}
	return float64(fail) / float64(len(l.ring)) * 100
}

// sent is the number of cycles in the window (one packet each).
func (l *Loop) sent() int { return len(l.ring) }

// received is the number of replies in the window.
func (l *Loop) received() int {
	n := 0
	for _, ok := range l.ring {
		if ok {
			n++
		}
	}
	return n
}

// Snapshot returns the current smoothed latency and rolling loss without
// probing. LatencyMs is NaN before the first reply.
func (l *Loop) Snapshot() (latencyMs, lossPct float64) {
	if l.haveEwma {
		latencyMs = l.ewma
	} else {
		latencyMs = math.NaN()
	}
	return latencyMs, l.lossPct()
}
