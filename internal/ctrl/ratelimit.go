package ctrl

import (
	"sync"
	"time"
)

// Limiter is a per-method token bucket. Each method gets its own bucket, so a
// burst of `ping` cannot starve `set-primary`, and the buckets are independent
// of the client: the rate limit is not a per-caller quota in this MVP (there is
// no caller identity to key on locally) but a cap on how fast the agent will
// accept a given method from anyone.
//
// The zero value is not usable; construct one with NewLimiter.
type Limiter struct {
	burst  float64
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

// bucket is one method's token state.
type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter builds a limiter that allows burst requests per window, refilling
// continuously. A burst below 1 is raised to 1 so a misconfigured caller cannot
// turn the limiter into a hard deny. now is the clock; nil means time.Now.
func NewLimiter(burst int, window time.Duration, now func() time.Time) *Limiter {
	if burst < 1 {
		burst = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		burst:   float64(burst),
		window:  window,
		now:     now,
		buckets: make(map[string]*bucket),
	}
}

// Allow consumes one token for method and reports whether the request may
// proceed. It is safe for concurrent use.
//
// The refill is continuous (tokens per second), not a fixed-window reset, so a
// client is never able to burst twice in one boundary crossing; a steady client
// at or below the rate is never limited no matter where it starts.
func (l *Limiter) Allow(method string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[method]
	if !ok {
		// A method's first request starts from a full bucket: the allowance is
		// "burst requests", not "burst requests minus the first".
		l.buckets[method] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		b.tokens += elapsed.Seconds() * (l.burst / l.window.Seconds())
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rateLimitedMethods is the set of methods the limiter guards. `status` is
// deliberately absent: it is read-only, it is the method a monitoring probe
// calls hardest, and shedding it would make a healthy agent look unreachable.
// The reserved/unknown methods are absent too — they are rejected as
// bad_request before the limiter is ever consulted, so a bucket for them would
// be dead state.
var rateLimitedMethods = map[string]bool{
	MethodPing:       true,
	MethodSetPrimary: true,
}

// RateLimited reports whether method is subject to the limiter.
func RateLimited(method string) bool { return rateLimitedMethods[method] }
