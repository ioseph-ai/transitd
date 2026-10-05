# Design: global visibility monitor (DFZ view vs intended state)

> P1 backlog feature. Self-contained design doc. Public-repo safe: examples
> use RFC 5737/3849 ranges and RFC 5398 documentation ASNs (64496–64511).
> Runtime-only; read-only polls; **API failure never causes agent action**.
> Tracking: #8

## 1. Goal

Periodically ask the outside world — via free, programmatic, public BGP
visibility APIs — *"which AS paths does the DFZ currently see for our
prefixes?"*, compare that against **what we intended to announce** (derived
from local agent config + gossip state), and classify divergences:

| Condition | Meaning |
|---|---|
| **stuck cond-adv** | backup transit still announcing our prefix while primary is healthy (failover never reverted) |
| **leak** | prefix visible from a border/origin we did not intend to announce from |
| **hijack** | unknown origin ASN originates our prefix |
| **visibility loss** | prefix (partially) gone from the DFZ while we believe we announce it |

Output: Prometheus metrics + structured events + (opt-in, default off)
decision-engine influence limited to *annotating* transits — never
autonomous remediation. This feature is an **observer**: it must never
mutate FRR state by itself.

## 2. Data sources: which API, and why both

| | Cloudflare Radar | RouteViews (LG / MRT-derived APIs) |
|---|---|---|
| Freshness | ~near-real-time | Raw RIB snapshots; per-collector lag varies (minutes) |
| Shape | Clean JSON, AS-path per prefix, AS-set helpers | Rawer: AS-path lists per collector vantage point |
| Auth | Free API key (config, optional; unauthenticated tier exists) | None |
| Rate limits | Documented, modest | Politeness only (public resource) |
| Coverage | Aggregated global view | True multi-vantage (per-LG views) |

**Primary: Cloudflare Radar** (`/api/v0/routing/as-path/asn/{asn}/prefix/{prefix}`
style endpoints + prefix visibility endpoint) for freshness and shape.
**Secondary: RouteViews** collectors' looking-glass APIs as an independent
cross-check when Radar flags something (or Radar is down/being rate-limited).
The design treats every source as a **provider interface** so either can be
the primary and others can be added (RIPE RIS is a natural third; the
validated research noted it alongside RouteViews).

Provider contract:

```go
// internal/visibility/provider.go
type VantageView struct {
    Source     string    // "radar" | "routeviews"
    Vantage    string    // collector/ASN seeing it (empty for aggregated views)
    Prefix     string
    OriginASN  uint32    // last ASN in path
    ASPath     []uint32  // leftmost = vantage-adjacent ... rightmost = origin
    SeenAt     time.Time
}

type Provider interface {
    Name() string
    // FetchViews returns observed paths for ONE prefix. Implementations must
    // honor ctx deadlines and their own cache.
    FetchViews(ctx context.Context, prefix string) ([]VantageView, error)
}
```

## 3. Intended state: where "should" comes from

The comparison baseline is built **internally**, no new config for the
baseline itself:

```go
// internal/visibility/intent.go
type IntendedAnnouncement struct {
    Prefix    string
    OriginASN uint32          // our ASN (from local agent context / config)
    // AnnouncingBorders: border routers (by router_name from gossip) that
    // SHOULD be announcing this prefix now, derived from the merged decide
    // state (primary healthy → primary borders; cond-adv failover → backup
    // borders). The monitor consumes gossip snapshots; it does not decide.
    ShouldAnnounce bool
    ExpectedUpstreamASNs []uint32 // transits permitted to appear adjacent to origin
}

// BuildIntent merges: local Config (watched_prefixes, expected_origins),
// gossip state (each router's current announce set = f(primary, cond-adv
// state)), and static expectations. Pure function — heavily unit-tested.
func BuildIntent(cfg *config.Config, snap gossip.ViewSnapshot) []IntendedAnnouncement
```

Stuck cond-adv detection in one sentence: gossip says "primary healthy,
announcing via primary" for ≥ `stuck_grace` (default 15m), while the DFZ
still shows the backup transit's ASN adjacent to origin → stuck.

## 4. User-facing config surface

```go
type VisibilityConfig struct {
    Enabled          bool          `yaml:"enabled"`            // opt-in master
    Interval         time.Duration `yaml:"interval"`           // default 5m, min 60s
    ProviderOrder    []string      `yaml:"provider_order"`     // default ["radar","routeviews"]
    RadarAPIToken    string        `yaml:"radar_api_token"`    // optional; env TRANSITD_RADAR_TOKEN preferred (yaml allowed but discouraged)
    RouteViewsURLs   []string      `yaml:"routeviews_urls"`    // optional overrides; default public collectors
    HTTPTimeout      time.Duration `yaml:"http_timeout"`       // default 20s
    CacheTTL         time.Duration `yaml:"cache_ttl"`          // default 120s (dedup within & across checks)
    MaxAge           time.Duration `yaml:"max_age"`            // discard provider data older than this (default 30m)
    StuckGrace       time.Duration `yaml:"stuck_grace"`        // default 15m
    ConsecutiveAlert int           `yaml:"consecutive_alert"`  // default 2 polls before firing event
    DecideAnnotation bool          `yaml:"decide_annotation"`  // default false: exports finding to decide only as annotation
    QuorumPeers      int           `yaml:"quorum_peers"`       // min gossip peers agreeing before "loss" verdicts (default 1)

    WatchedPrefixes []WatchedPrefix `yaml:"watched_prefixes"`
}

type WatchedPrefix struct {
    Prefix         string   `yaml:"prefix"`           // doc example: 192.0.2.0/24, 2001:db8::/48
    ExpectedOrigins []uint32 `yaml:"expected_origins"` // e.g. [64496]
    // ExpectedPaths: optional list of regex over space-separated AS path,
    // e.g. ["^64500 64496$"]. EMPTY = origin-only matching (default, loose).
    ExpectedPaths  []string `yaml:"expected_paths"`
    AnnouncedBy    []string `yaml:"announced_by"`     // border router_names allowed to originate (leak check)
}
```

```yaml
visibility:
  enabled: true
  interval: 5m
  watched_prefixes:
    - prefix: 192.0.2.0/24
      expected_origins: [64496]
      announced_by: [edge-1, edge-2]
```

Validation: prefixes parse (v4+v6); `expected_origins` non-empty;
`expected_paths` compile as regex and are anchored by the matcher (see §6);
at most N=64 watched prefixes (bounded work per poll).

## 5. Architecture and data flow

One monitor per **cluster**, not per router: run on a configurable subset
(`visibility.enabled: true` on ONE router, or a leader-elected agent via the
existing gossip layer — simplest v1: each enabled router runs it but only
the lowest `router_name` in lexicographic order *publishes* events; others
stay silent hot-standbys). This avoids N routers hammering public APIs.

```
internal/visibility/
    provider.go       // Provider interface, VantageView
    radar.go          // Cloudflare Radar client (cache, rate-limit tracker)
    routeviews.go     // RouteViews client (cache, per-collector fetch)
    intent.go         // BuildIntent from config + gossip snapshot
    classify.go       // the verdict engine (pure functions)
    monitor.go        // scheduler loop, provider failover, consecutive-poll logic
    metrics.go        // prometheus collectors
    events.go         // structured event emission (log + optional gossip broadcast)
    *_test.go
```

Flow per tick:

```
tick (Interval, jitter ±10%)
  → BuildIntent(cfg, gossipSnapshot)                 []IntendedAnnouncement
  → for each watched prefix (serial, bounded):
       views = providerOrder[0].FetchViews(ctx, p)   (cached ≤ CacheTTL)
       if err/empty → try next provider; if ALL fail → tick = "degraded",
                      NO verdicts emitted this tick (failure isolation)
       if views older than MaxAge → same degraded handling
  → classify.Classify(intent, views, history) []Verdict
  → Verdicts update rolling history (needed for ConsecutiveAlert)
  → those seen >= ConsecutiveAlert polls:
       emit event (log JSON + metrics) ; optionally gossip-broadcast a
       ClusterNotice so ALL routers' metrics expose the finding once
  → DecideAnnotation (if enabled): attach annotation-only note to the
     relevant TransitHealth; decide engine logs it, ranks unchanged
```

### Classify core

```go
type VerdictKind int
const (
    VOK VerdictKind = iota
    VStuckBackup     // backup upstream announcing while intent says primary
    VLeak            // origin OK but announcing border / upstream set wrong
    VHijack          // origin ASN not in ExpectedOrigins
    VVisibilityLoss  // fewer than threshold vantages see prefix while intent=announce
    VUnknown         // provider data insufficient to judge
)

type Verdict struct {
    Kind       VerdictKind
    Prefix     string
    Detail     string   // human explanation w/ observed vs expected
    Observed   []VantageView
    Intent     IntendedAnnouncement
    FirstSeen  time.Time
    Consecutive int
}

// Classify is PURE: same inputs → same verdicts. Table-testable.
func Classify(intent []IntendedAnnouncement, views map[string][]VantageView,
    hist History, now time.Time) []Verdict
```

Classification order per prefix (first match wins, most-specific danger
first): hijack → leak → stuck → visibility-loss → ok, with `VUnknown` when
vantage count < `min_vantages` (default 3 aggregated / 2 per-LG) — one
collector's blindness must not page anyone.

## 6. Matching strictness (the subtle part)

Deliberately **loose by default**, strict only where configured:

1. **Origin-only default**: a view matches if `OriginASN ∈ ExpectedOrigins`.
   Everything upstream of origin is ignored unless `expected_paths` set.
2. **Prepend variance**: paths like `64500 64500 64500 64496` are *normal*
   (our own TE prepends via RFC 8195 large-community workflow happen at
   announce time). The matcher normalizes repeated-ASN runs when comparing
   against `expected_paths`, and never flags prepends of *known* transits.
3. **ROA-valid alternates**: any view whose origin is in `expected_origins`
   is OK regardless of path length/shape; a view with origin NOT in
   `expected_origins` is a hijack **even if it looks prepend-weird** —
   origin substitution is not a prepend artifact.
4. **expected_paths regex semantics**: matched against the *normalized*
   path string (runs collapsed, spaces); anchor enforcement: if the user
   regex lacks `^`/`$`, the matcher wraps it (`^(?:...)$`) and logs that it
   did — surprises here produce false "leak" pages otherwise.
5. **Visibility-loss strictness**: requires (a) intent says announce,
   (b) ≥ `min_vantages` vantages REPORTED (i.e. providers healthy), and
   (c) zero matching views for the prefix, sustained `ConsecutiveAlert`
   polls. Partial visibility (some vantages see it) → warn-level metric
   only, never an event, because per-region visibility flaps benignly.

## 7. Rate limits, caching, and failure isolation

- **Client-side cache** (`CacheTTL`, default 120s): a tick and a manual
  re-check within TTL share one fetch; prefix-level dedup across providers
  keyed `provider:prefix`.
- **Token bucket per provider** (Radar documented limits; RouteViews
  self-imposed 1 req/s): the scheduler takes the *cheapest* eligible fetch
  per tick; if the bucket is empty, that tick uses cached data if fresh,
  else degrades (no verdicts) — never blocks the agent.
- **Provider failover order**: try in `provider_order`; a provider failing
  3 consecutive ticks gets a cooldown (10m) and is skipped.
- **Hard failure isolation** (the invariant): the monitor runs in its own
  goroutine with its own context; any panic is recovered; the ONLY writes
  it can perform are metrics, logs, events, and (if `decide_annotation`)
  an annotation field on health — there is no code path from the monitor to
  `act`. A dead API can at worst cause silence, flagged by
  `transitd_visibility_provider_up{provider}` and a warn alert.
- **Resource envelope**: 1 HTTP client, no goroutine per prefix (serial
  bounded loop), response size capped (512KB), JSON decoded streaming.

## 8. Prometheus metrics + alerts

```
transitd_visibility_prefix_ok{prefix}                 gauge 1/0
transitd_visibility_verdict{prefix,kind}              gauge (kind ∈ stuck,leak,hijack,loss)
transitd_visibility_origin_asn{prefix}                gauge info-style (origin ASN value)
transitd_visibility_vantage_count{prefix,provider}    gauge
transitd_visibility_provider_up{provider}             gauge
transitd_visibility_provider_requests_total{provider} counter
transitd_visibility_provider_errors_total{provider}   counter
transitd_visibility_events_total{prefix,kind}         counter
transitd_visibility_last_success_unixtime             gauge
```

Suggested alerts: page `verdict{kind="hijack"}==1` ≥1 poll after
ConsecutiveAlert; page `visibility_loss`; warn `stuck` (backup bleeding
traffic); warn `provider_up==0` for 30m (monitor blind, network fine).

## 9. Edge cases

- **Our own prepends / TE shifts** mid-window: normalization (§6.2) plus
  `StuckGrace` prevents self-inflicted stuck/leak verdicts during planned
  shifts; intent rebuilds each tick from gossip, so the window is one tick.
- **More specific announcements (DFZ deaggregation by us)**: watcher is
  exact-prefix; a covering prefix seeing origin OK while a more-specific is
  hijacked → both watched if configured; classifier never infers covering-
  prefix health for more-specifics (documented).
- **MOAS legitimately multi-origin** (provider assignments): multiple
  `expected_origins` handles it; anything else is flagged as designed.
- **Radar aggregated view lags a flap**: freshness bounded by `MaxAge`;
  verdicts require ConsecutiveAlert polls ≥ interval → worst-case false
  positive window is interval×ConsecutiveAlert, self-healing next tick.
- **RouteViews collector sees only its region** → per-vantage verdicts
  pre-aggregated: vantage count drives min_vantages; a single blind
  collector never yields "loss".
- **IPv6**: same providers, same matcher; prefixes carry family in the
  string; no separate logic.
- **API schema drift**: strict JSON decode into typed structs (no
  map[string]any) → decode error = degraded tick + error counter, visible
  in metrics; no panic path.
- **Config with `expected_paths` too loose (unanchored)**: anchored at
  match time (§6.4) + validation warns on unanchored patterns at startup.
- **Two operators enable visibility on 2+ routers**: hot-standby leader
  election (§5) means one publisher; metrics idempotent.

## 10. Failure modes + mitigations (summary)

- API down / rate-limited → degraded tick, no verdicts, provider cooldown,
  `provider_up` alert. **No agent action, ever.**
- Stale caches poisoning verdicts → `MaxAge` discard + `CacheTTL` << poll
  interval semantics documented.
- False hijack page from provider data bug → ConsecutiveAlert ≥2 + vantage
  cross-check (hijack confirmed by secondary provider when available —
  cross-check is *advisory*, noted in event detail).
- Gossip partition → intent degrades to local-config-only expectations;
  stuck detection suspended (`VUnknown`) rather than guessing.
- Monitor goroutine leak/hang → per-tick context deadline (HTTPTimeout ×
  prefixes bounded by serial loop + overall watchdog 2×Interval).

## 11. Test strategy

CI-safe, no routers, no live APIs:

- **Classifier table tests** (the heart): synthetic intent+views → verdicts:
  healthy; prepended path OK; backup announcing while primary healthy
  (stuck); backup announcing during failover intent (OK — the point);
  unknown origin (hijack); known origin via unconfigured upstream (leak);
  zero views with healthy providers (loss); zero views with providers
  down (unknown, no verdicts); single blind vantage (ok); unanchored
  expected_paths auto-anchoring; consecutive-poll promotion logic.
- **Intent builder tests**: gossip snapshot permutations (primary healthy/
  failed, cond-adv armed/clear) → expected announce sets.
- **Provider clients against httptest servers**: golden JSON fixtures
  (Radar-shaped, RouteViews-shaped), cache hits within TTL, token-bucket
  behavior, 429/5xx retry+cooldown, MaxAge discard, size cap, streaming
  decode.
- **Failure-isolation test**: provider returning garbage / hanging /
  panicking → agent's other loops unaffected (assert decide called with
  unchanged health; assert no vtysh batch emitted — golden-batch empty).
- **Scheduler tests**: leader election determinism, jitter bounds,
  ConsecutiveAlert, cooldown expiry.
- **Integration (FRR containers, optional job)**: exabgp announces
  192.0.2.0/24 with origin 64496 vs 64511; a stub "provider" fed from the
  lab FRR's RIB (test double implementing Provider) → assert hijack event
  fires end-to-end into metrics.

## 12. Out of scope

- RPKI/ROA validation itself (we consume the *expectation* via
  expected_origins; no RTR protocol).
- Automatic mitigation of any verdict (RPKI publish, prefix-list edits,
  session shutdowns) — observer only; remediation stays operator-driven
  (P2+ discussion).
- Historical BGP event storage/retention beyond metrics + logs.
- SLA-style latency measurement of visibility propagation.
- Third-party commercial BGP monitors (only free/public providers).
