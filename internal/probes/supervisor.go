package probes

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/ioseph-ai/transitd/internal/config"
	"github.com/ioseph-ai/transitd/internal/metrics"
	"github.com/ioseph-ai/transitd/internal/pinning"
)

// VerifyFunc verifies a transit's pin. It matches pinning.Verifier.Verify and is
// spelled as a function type here so the supervisor does not depend on the
// concrete verifier and tests can inject a trivial stub.
type VerifyFunc func(ctx context.Context, t config.Transit) pinning.Result

// Supervisor owns one probe loop per VERIFIED transit and is the enforcement
// point for issue #1's suppression rule: an unverified transit produces no
// samples, because no loop is ever started for it.
//
// This is the structural reason suppression cannot regress: it is not a filter
// that a later caller might forget to apply — the sample stream for an
// unverified transit does not exist. A test asserts the empty stream.
type Supervisor struct {
	// Runner executes ping for every loop; nil means an ExecRunner.
	Runner Runner
	// Verify verifies one transit's pin; required.
	Verify VerifyFunc
	// Emit receives samples from every verified transit.
	Emit func(Sample)

	mu      sync.Mutex
	results map[string]pinning.Result
}

// Results returns a copy of the per-transit verification outcomes from the last
// Start call. It is the data behind the healthz payload and the pin_verified
// gauges.
func (s *Supervisor) Results() map[string]pinning.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]pinning.Result, len(s.results))
	for k, v := range s.results {
		out[k] = v
	}
	return out
}

// Verified returns whether a named transit passed the last verification.
func (s *Supervisor) Verified(transit string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.results[transit].Verified
}

// Start verifies every transit and, for each VERIFIED one, starts a probe loop
// in a new goroutine. It returns immediately; the loops stop when ctx is
// cancelled. It returns an error only for a transit whose probe configuration
// is structurally invalid — a failed pin is not an error, it is a suppression.
func (s *Supervisor) Start(ctx context.Context, transits []config.Transit) error {
	if s.Verify == nil {
		return fmt.Errorf("supervisor: Verify func is required")
	}
	if s.Runner == nil {
		s.Runner = ExecRunner{}
	}

	results := make(map[string]pinning.Result, len(transits))
	loops := make([]*Loop, 0, len(transits))
	for _, t := range transits {
		res := s.Verify(ctx, t)
		results[t.Name] = res
		s.recordPin(res)
		if !res.Verified {
			// Suppress: build no loop, emit no sample, and leave the probe
			// gauges absent. The transit is visible only through its
			// pin_verified=0 gauge and the healthz degraded state.
			metrics.ClearProbe(t.Name)
			continue
		}
		l, err := NewLoop(t, s.Runner)
		if err != nil {
			return fmt.Errorf("transit %q verified but probe config is invalid: %w", t.Name, err)
		}
		l.Emit = s.emit
		loops = append(loops, l)
	}

	s.mu.Lock()
	s.results = results
	s.mu.Unlock()

	for _, l := range loops {
		go l.Run(ctx)
	}
	return nil
}

// recordPin exports one verification outcome as the pin_verified gauge.
func (s *Supervisor) recordPin(res pinning.Result) {
	metrics.SetPinVerified(res.Transit, res.Verified)
}

// emit fans a sample out to the caller and to the probe gauges. Suppression is
// already structural (an unverified transit has no loop), so there is nothing to
// filter here — this is the one place probe samples become metrics.
func (s *Supervisor) emit(smp Sample) {
	if !math.IsNaN(smp.LatencyMs) {
		metrics.SetProbe(smp.Transit, smp.LatencyMs, smp.LossPct)
	} else {
		// No reply has ever been seen: export loss but leave a latency sample
		// out entirely, so a dashboard cannot render "0 ms" for a dead transit.
		metrics.SetProbeLossOnly(smp.Transit, smp.LossPct)
	}
	if s.Emit != nil {
		s.Emit(smp)
	}
}

// StartWithLoops is Start with caller-provided loops, for the unit tier: it lets
// a test inject a fake clock and a fake Runner while still exercising the same
// verify-then-maybe-start decision. The loops map is keyed by transit name.
func (s *Supervisor) StartWithLoops(ctx context.Context, transits []config.Transit, loops map[string]*Loop) error {
	if s.Verify == nil {
		return fmt.Errorf("supervisor: Verify func is required")
	}
	results := make(map[string]pinning.Result, len(transits))
	start := make([]*Loop, 0, len(transits))
	for _, t := range transits {
		res := s.Verify(ctx, t)
		results[t.Name] = res
		s.recordPin(res)
		if !res.Verified {
			metrics.ClearProbe(t.Name)
			continue
		}
		l, ok := loops[t.Name]
		if !ok {
			return fmt.Errorf("transit %q verified but no loop was provided", t.Name)
		}
		l.Emit = s.emit
		start = append(start, l)
	}
	s.mu.Lock()
	s.results = results
	s.mu.Unlock()
	for _, l := range start {
		go l.Run(ctx)
	}
	return nil
}

// StaticVerify returns a VerifyFunc that verifies transit t against a fixed map
// of outcomes, keyed by transit name. It is a convenience for tests and for the
// agent's startup path when a pin is verified out-of-band.
func StaticVerify(results map[string]bool) VerifyFunc {
	return func(_ context.Context, t config.Transit) pinning.Result {
		ok := results[t.Name]
		return pinning.Result{
			Transit:  t.Name,
			Verified: ok,
			EgressIf: t.EgressInterface,
			Reason:   fmt.Sprintf("static verification: verified=%t", ok),
		}
	}
}

// IntervalOrDefault returns a transit's probe interval with the package default
// applied, for callers that build loops without going through NewLoop.
func IntervalOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return 30 * time.Second
	}
	return d
}
