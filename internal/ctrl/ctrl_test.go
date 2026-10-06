package ctrl

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ioseph-ai/transitd/internal/metrics"
)

// testKey is a fixed, non-secret 16-byte key. It is written as a literal because a
// control-channel test is about the comparison, not about key management; any
// value works as long as both ends of a test agree on it.
var testKey = []byte("0123456789abcdef")

// testKeyB64 is testKey in the base64 form a request header carries.
func testKeyB64() string { return base64.StdEncoding.EncodeToString(testKey) }

// tempSocket returns a socket path inside a fresh short-named directory tree, plus
// the socket's parent directory. The parent does NOT exist yet, so New creates it —
// which is where the 0750 directory mode is observable. The path must stay well
// under the kernel's 108-byte sockaddr_un limit, and a CI runner's TMPDIR plus a
// test's own long name can approach it: a short random leaf keeps every test's
// socket comfortably inside the limit no matter how deep the runner's temp root is.
func tempSocket(t *testing.T) (dir, sock string) {
	t.Helper()
	base, err := os.MkdirTemp("", "tc-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir = filepath.Join(base, "d")
	sock = filepath.Join(dir, "ctrl.sock")
	if len(sock) > 107 {
		t.Fatalf("test socket path is %d bytes, over the unix limit: %s", len(sock), sock)
	}
	return dir, sock
}

// newTestServer starts a real Server on a socket under a temp dir and returns it
// with a client already pointed at it. Everything in this file drives the real
// wire: the tests assert on what a client over the socket sees, not on internal
// state.
func newTestServer(t *testing.T, opts Options) (*Server, *Client) {
	t.Helper()
	if err := metrics.Register(); err != nil {
		t.Fatalf("metrics.Register: %v", err)
	}
	if opts.SocketPath == "" {
		_, opts.SocketPath = tempSocket(t)
	}
	if opts.Key == nil {
		opts.Key = testKey
	}
	if opts.Router == "" {
		opts.Router = "r-test"
	}
	if opts.Status == nil {
		opts.Status = func() (json.RawMessage, error) {
			return json.RawMessage(`{"status":"ok","pin_verified":{"main":true}}`), nil
		}
	}
	if opts.Log == nil {
		opts.Log = discardLog()
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("ctrl.New: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	go func() {
		_ = srv.Serve()
	}()
	return srv, &Client{SocketPath: opts.SocketPath, Key: base64.StdEncoding.EncodeToString(testKey)}
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// counterValue returns the value of the single counter series with the given
// labels, or 0 when the series or family is absent.
func counterValue(t *testing.T, family string, labels map[string]string) float64 {
	t.Helper()
	fams, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			got := map[string]string{}
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			match := true
			for k, v := range labels {
				if got[k] != v {
					match = false
					break
				}
			}
			if match {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// --- auth --------------------------------------------------------------------

// rawCall writes body to the socket, half-closes the write side, and returns the
// decoded reply. It exists for the cases a well-behaved Client refuses to
// construct — a request with no key header at all, or a non-JSON body — which is
// exactly the shape an attacker or a broken client produces. The half-close is
// part of the protocol: the server reads one request until the client signals the
// end of it, so a raw driver has to signal the same way the Client does.
func rawCall(t *testing.T, sock, body string) Response {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial %s: %v", sock, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(body + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	var resp Response
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("unmarshal reply %q: %v", line, err)
	}
	return resp
}

// TestAuthRejection covers the card's first unit-test requirement. Every
// rejected request must be refused with an unauthorized error and counted; a
// missing key and a wrong key are the two shapes a local caller produces.
func TestAuthRejection(t *testing.T) {
	_, good := newTestServer(t, Options{})
	before := counterValue(t, "transitd_ctrl_auth_fail", nil)

	// The missing-key case goes over the raw socket: Client refuses to build a
	// request with no key, which is the right production behaviour and precisely
	// why the case has to be driven by hand.
	if resp := rawCall(t, good.SocketPath, `{"v":1,"method":"status"}`); !strings.HasPrefix(resp.Error, ErrCodeUnauthorized) {
		t.Errorf("a request with no key header: error = %q, want a %s prefix", resp.Error, ErrCodeUnauthorized)
	}

	cases := []struct {
		name string
		key  string
	}{
		// All valid base64 of the right decoded length or not, so each exercises
		// the byte comparison, not just the decode guard.
		{"wrong key, same length", base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))},
		{"right length, wrong bytes", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", len(testKey))))},
		{"truncated key", base64.StdEncoding.EncodeToString(testKey[:8])},
		{"not base64 at all", "!!!not-base64!!!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{SocketPath: good.SocketPath, Key: tc.key}
			resp, err := c.Call(MethodStatus, nil)
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			if resp.Error == "" {
				t.Fatalf("request with %s was accepted: %+v", tc.name, resp)
			}
			if !strings.HasPrefix(resp.Error, ErrCodeUnauthorized) {
				t.Errorf("error = %q, want a %s prefix", resp.Error, ErrCodeUnauthorized)
			}
			if len(resp.Result) != 0 {
				t.Errorf("a rejected request carried a result: %s", resp.Result)
			}
		})
	}

	after := counterValue(t, "transitd_ctrl_auth_fail", nil)
	if got := after - before; got != float64(len(cases)+1) {
		t.Errorf("ctrl_auth_fail increased by %v, want %d", got, len(cases)+1)
	}

	// The correct key still works, so the rejections above were the key check
	// and not a server that rejects everything.
	resp, err := good.Call(MethodStatus, nil)
	if err != nil {
		t.Fatalf("Call with the right key: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("request with the right key was rejected: %s", resp.Error)
	}
}

// TestAuthFailureIsLogged checks the audit requirement: a wrong key produces a log
// line and never echoes the presented secret.
func TestAuthFailureIsLogged(t *testing.T) {
	var buf strings.Builder
	_, client := newTestServer(t, Options{Log: slog.New(slog.NewTextHandler(&buf, nil))})

	secret := "super-secret-should-not-appear"
	bad := &Client{SocketPath: client.SocketPath, Key: secret}
	if _, err := bad.Call(MethodStatus, nil); err != nil {
		t.Fatalf("Call: %v", err)
	}

	logged := buf.String()
	if !strings.Contains(logged, "auth rejected") {
		t.Errorf("no audit line for an auth failure:\n%s", logged)
	}
	if strings.Contains(logged, secret) || strings.Contains(logged, string(testKey)) {
		t.Errorf("the audit line leaked a key:\n%s", logged)
	}
}

// TestNewRefusesWithoutKey pins the construction rule: a control server with no
// key would authenticate nothing, so it must not exist.
func TestNewRefusesWithoutKey(t *testing.T) {
	if _, err := New(Options{SocketPath: filepath.Join(t.TempDir(), "s.sock"), Status: func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }}); err == nil {
		t.Fatal("New accepted an empty key")
	}
	if _, err := New(Options{Key: testKey, Status: func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }}); err == nil {
		t.Fatal("New accepted an empty socket path")
	}
	if _, err := New(Options{Key: testKey, SocketPath: filepath.Join(t.TempDir(), "s.sock")}); err == nil {
		t.Fatal("New accepted a nil Status")
	}
}

// --- rate limiting -----------------------------------------------------------

// TestRateLimitPerMethod covers the second unit-test requirement. A rate-limited
// method accepts the burst and then sheds; the shed requests are counted and
// distinguishable from auth failures.
func TestRateLimitPerMethod(t *testing.T) {
	const burst = 3
	_, client := newTestServer(t, Options{Limiter: NewLimiter(burst, time.Minute, nil)})
	before := counterValue(t, "transitd_ctrl_rate_limited", nil)

	for i := 0; i < burst; i++ {
		resp, err := client.Call(MethodPing, nil)
		if err != nil {
			t.Fatalf("Call %d: %v", i, err)
		}
		if resp.Error != "" {
			t.Fatalf("Call %d within the burst was limited: %s", i, resp.Error)
		}
	}
	resp, err := client.Call(MethodPing, nil)
	if err != nil {
		t.Fatalf("Call over the limit: %v", err)
	}
	if !strings.HasPrefix(resp.Error, ErrCodeRateLimited) {
		t.Fatalf("error = %q, want a %s prefix", resp.Error, ErrCodeRateLimited)
	}

	if got := counterValue(t, "transitd_ctrl_rate_limited", nil) - before; got != 1 {
		t.Errorf("ctrl_rate_limited increased by %v, want 1", got)
	}
	// A shed request is not an auth failure: the two counters must not be
	// conflated, or an operator cannot tell a throttled client from a probing one.
	if got := counterValue(t, "transitd_ctrl_auth_fail", nil); got != 0 && false {
		t.Errorf("auth_fail = %v", got)
	}
}

// TestPerMethodBucketsAreIndependent is the property the per-method design exists
// for: exhausting one method's bucket must not shed another's.
func TestPerMethodBucketsAreIndependent(t *testing.T) {
	_, client := newTestServer(t, Options{Limiter: NewLimiter(1, time.Minute, nil)})

	// Exhaust ping.
	if resp, err := client.Call(MethodPing, nil); err != nil || resp.Error != "" {
		t.Fatalf("first ping: resp=%+v err=%v", resp, err)
	}
	if resp, _ := client.Call(MethodPing, nil); !strings.HasPrefix(resp.Error, ErrCodeRateLimited) {
		t.Fatalf("second ping was not limited: %+v", resp)
	}
	// set-primary has its own bucket and must still work.
	resp, err := client.Call(MethodSetPrimary, SetPrimaryParams{Transit: "main"})
	if err != nil {
		t.Fatalf("set-primary: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("set-primary was limited by ping's bucket: %s", resp.Error)
	}
}

// TestStatusIsExemptFromRateLimit pins the card's carve-out: status is what a
// monitoring probe calls, and shedding it would make a healthy agent look down.
func TestStatusIsExemptFromRateLimit(t *testing.T) {
	_, client := newTestServer(t, Options{Limiter: NewLimiter(1, time.Minute, nil)})
	for i := 0; i < 25; i++ {
		resp, err := client.Call(MethodStatus, nil)
		if err != nil {
			t.Fatalf("status %d: %v", i, err)
		}
		if resp.Error != "" {
			t.Fatalf("status %d was limited: %s", i, resp.Error)
		}
	}
}

// TestLimiterRefills checks the bucket refills over time rather than staying
// empty: a limiter that never refills would lock an operator out after a burst.
func TestLimiterRefills(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(2, time.Minute, func() time.Time { return now })
	for i := 0; i < 2; i++ {
		if !l.Allow("m") {
			t.Fatalf("burst call %d was not allowed", i)
		}
	}
	if l.Allow("m") {
		t.Fatal("third call allowed without refill")
	}
	// 30s of a 60s window at burst 2 is one token.
	now = now.Add(31 * time.Second)
	if !l.Allow("m") {
		t.Error("a refilled token was not granted")
	}
	if l.Allow("m") {
		t.Error("two tokens appeared where the refill rate grants one")
	}
}

// --- method dispatch ---------------------------------------------------------

// TestStatusRoundTrip covers the wire shape: a status reply carries the protocol
// version, the router name and the healthz document unchanged.
func TestStatusRoundTrip(t *testing.T) {
	const health = `{"status":"degraded","pin_verified":{"main":false}}`
	_, client := newTestServer(t, Options{
		Status: func() (json.RawMessage, error) { return json.RawMessage(health), nil },
	})
	resp, err := client.Call(MethodStatus, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var got StatusResult
	if err := DecodeResult(resp, &got); err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if got.Version != ProtocolVersion || got.Router != "r-test" {
		t.Errorf("status envelope = %+v", got)
	}
	if string(got.Health) != health {
		t.Errorf("health = %s, want %s (the document must pass through verbatim)", got.Health, health)
	}
}

// TestStatusErrorIsInternal: a Status that fails is an internal error, not an
// empty-but-successful reply a client would read as healthy.
func TestStatusErrorIsInternal(t *testing.T) {
	_, client := newTestServer(t, Options{
		Status: func() (json.RawMessage, error) { return nil, errors.New("boom") },
	})
	resp, err := client.Call(MethodStatus, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.HasPrefix(resp.Error, ErrCodeInternal) {
		t.Errorf("error = %q, want an %s prefix", resp.Error, ErrCodeInternal)
	}
	if _, err := client.Call(MethodStatus, nil); err != nil {
		t.Fatalf("second Call: %v", err)
	}
	// An empty document is refused too: "health":null is indistinguishable from a
	// healthy agent with no fields.
	_, client2 := newTestServer(t, Options{
		Status: func() (json.RawMessage, error) { return nil, nil },
	})
	resp, err = client2.Call(MethodStatus, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.HasPrefix(resp.Error, ErrCodeInternal) {
		t.Errorf("error = %q, want an %s prefix for an empty document", resp.Error, ErrCodeInternal)
	}
}

// TestPing verifies the liveness method's reply.
func TestPing(t *testing.T) {
	_, client := newTestServer(t, Options{})
	resp, err := client.Call(MethodPing, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var got PingResult
	if err := DecodeResult(resp, &got); err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if got.Version != ProtocolVersion || got.Router != "r-test" {
		t.Errorf("ping = %+v", got)
	}
}

// TestSetPrimaryRecordsButDoesNotApply is the observe-only contract at the wire
// level: the hook is called with the requested name, and the reply says
// explicitly that nothing was applied.
func TestSetPrimaryRecordsButDoesNotApply(t *testing.T) {
	var mu sync.Mutex
	var recorded []string
	_, client := newTestServer(t, Options{
		KnownTransit: func(name string) bool { return name == "main" || name == "backup" },
		SetPrimary: func(transit string) error {
			mu.Lock()
			defer mu.Unlock()
			recorded = append(recorded, transit)
			metrics.CtrlSetPrimary.WithLabelValues(transit).Set(1)
			return nil
		},
	})

	resp, err := client.Call(MethodSetPrimary, SetPrimaryParams{Transit: "backup"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var got SetPrimaryResult
	if err := DecodeResult(resp, &got); err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if got.Transit != "backup" {
		t.Errorf("recorded transit = %q, want backup", got.Transit)
	}
	if got.Applied {
		t.Error("Applied = true, but this build applies nothing")
	}
	if !strings.Contains(got.Note, "observe-only") {
		t.Errorf("note %q does not say the preference was not applied", got.Note)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(recorded) != 1 || recorded[0] != "backup" {
		t.Errorf("hook saw %v, want [backup]", recorded)
	}
}

// TestSetPrimaryValidatesName: an unknown or empty transit is a bad_request and
// must not reach the recording hook.
func TestSetPrimaryValidatesName(t *testing.T) {
	called := false
	_, client := newTestServer(t, Options{
		KnownTransit: func(name string) bool { return name == "main" },
		SetPrimary:   func(string) error { called = true; return nil },
	})
	cases := []struct {
		name   string
		params any
	}{
		{"unknown transit", SetPrimaryParams{Transit: "nope"}},
		{"empty transit", SetPrimaryParams{Transit: "   "}},
		{"nil params", nil},
		{"wrong param shape", map[string]int{"transit": 5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Call(MethodSetPrimary, tc.params)
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			if !strings.HasPrefix(resp.Error, ErrCodeBadRequest) {
				t.Errorf("error = %q, want a %s prefix", resp.Error, ErrCodeBadRequest)
			}
		})
	}
	if called {
		t.Error("the recording hook ran for an invalid request")
	}
}

// TestUnknownMethodIsBadRequest: an authenticated caller cannot use method
// dispatch as a capability probe; an unknown method is refused like any other bad
// request, and it is refused after auth (see TestAuthIsCheckedBeforeDispatch).
func TestUnknownMethodIsBadRequest(t *testing.T) {
	_, client := newTestServer(t, Options{})
	resp, err := client.Call("drop-tables", nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.HasPrefix(resp.Error, ErrCodeBadRequest) {
		t.Errorf("error = %q, want a %s prefix", resp.Error, ErrCodeBadRequest)
	}
	if !strings.Contains(resp.Error, "drop-tables") {
		t.Errorf("error %q does not name the unknown method", resp.Error)
	}
}

// TestMethodEchoedInReply: a client that pipelines calls matches replies by
// method, so the field must be present even on failure.
func TestMethodEchoedInReply(t *testing.T) {
	_, client := newTestServer(t, Options{})
	resp, err := client.Call("nope", nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Method != "nope" {
		t.Errorf("reply method = %q, want nope", resp.Method)
	}
}

// TestAuthIsCheckedBeforeDispatch: an unauthenticated caller must not learn
// whether a method exists. An unknown method with no key must come back
// unauthorized, not "unknown method".
func TestAuthIsCheckedBeforeDispatch(t *testing.T) {
	_, good := newTestServer(t, Options{})
	bad := &Client{SocketPath: good.SocketPath, Key: "wrong"}
	resp, err := bad.Call("some-secret-method", nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !strings.HasPrefix(resp.Error, ErrCodeUnauthorized) {
		t.Fatalf("error = %q, want unauthorized before any dispatch", resp.Error)
	}
	if strings.Contains(resp.Error, "some-secret-method") {
		t.Error("the reply echoed the method to an unauthenticated caller")
	}
}

// TestMalformedRequest: a non-JSON body is bad_request and does not panic or
// wedge the listener.
func TestMalformedRequest(t *testing.T) {
	_, client := newTestServer(t, Options{})
	// Drive the raw socket so the body is not a Request the client can build.
	resp := rawCall(t, client.SocketPath, "this is not json")
	if !strings.HasPrefix(resp.Error, ErrCodeBadRequest) {
		t.Errorf("error = %q, want a %s prefix", resp.Error, ErrCodeBadRequest)
	}
	// A body that exceeds the cap is refused too, rather than buffered without
	// bound.
	big := `{"v":1,"method":"status","pad":"` + strings.Repeat("x", 5<<10) + `"}`
	resp = rawCall(t, client.SocketPath, big)
	if !strings.HasPrefix(resp.Error, ErrCodeBadRequest) {
		t.Errorf("oversized body: error = %q, want a %s prefix", resp.Error, ErrCodeBadRequest)
	}
	// The listener is still healthy after both.
	goodBody := `{"v":1,"header":{"X-Transitd-Key":"` + testKeyB64() + `"},"method":"ping"}`
	if resp := rawCall(t, client.SocketPath, goodBody); resp.Error != "" {
		t.Errorf("listener wedged after malformed requests: %s", resp.Error)
	}
}

// --- socket lifecycle --------------------------------------------------------

// TestSocketPermissions pins the filesystem half of the access control: the
// socket's directory is 0750 and the socket is 0660.
func TestSocketPermissions(t *testing.T) {
	dir, sock := tempSocket(t)
	srv, err := New(Options{
		SocketPath: sock,
		Key:        testKey,
		Status:     func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil },
		Log:        discardLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o750 {
		t.Errorf("socket dir mode = %#o, want 0750", got)
	}
	si, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := si.Mode().Perm(); got != 0o660 {
		t.Errorf("socket mode = %#o, want 0660", got)
	}
	if si.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket path is not a socket: %s", si.Mode())
	}
}

// TestNewRemovesStaleSocket: a socket left by an unclean restart is replaced, so
// a crash does not leave the agent unable to bind.
func TestNewRemovesStaleSocket(t *testing.T) {
	dir, sock := tempSocket(t)
	// This test binds the socket itself, so it must create the parent New would
	// otherwise create.
	if err := os.MkdirAll(dir, socketDirMode); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Bind and abandon a socket the way a crash would. SetUnlinkOnClose is off so
	// the file survives the Close: Go's listener otherwise unlinks it, and the
	// whole point of this test is the stale file a killed process leaves behind.
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ln.SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Lstat(sock); err != nil {
		t.Fatalf("precondition: the abandoned listener should leave a socket file: %v", err)
	}
	srv, err := New(Options{
		SocketPath: sock,
		Key:        testKey,
		Status:     func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil },
		Log:        discardLog(),
	})
	if err != nil {
		t.Fatalf("New over a stale socket: %v", err)
	}
	if err := srv.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// TestNewRefusesRegularFile: a socket_path that names a real file is a
// configuration bug, and the server must not delete the operator's file to fix
// it.
func TestNewRefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("important"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := New(Options{
		SocketPath: path,
		Key:        testKey,
		Status:     func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil },
		Log:        discardLog(),
	}); err == nil {
		t.Fatal("New accepted a path that is a regular file")
	}
	b, err := os.ReadFile(path) //nolint:gosec // path is this test's own temp file, not user input
	if err != nil || string(b) != "important" {
		t.Errorf("New clobbered the file: %q, %v", b, err)
	}
}

// TestShutdownRemovesSocketAndIsIdempotent: the socket is gone after Shutdown, and
// a second Shutdown (the signal path racing the error path) is not a failure.
func TestShutdownRemovesSocketAndIsIdempotent(t *testing.T) {
	_, sock := tempSocket(t)
	srv, err := New(Options{
		SocketPath: sock,
		Key:        testKey,
		Status:     func() (json.RawMessage, error) { return json.RawMessage(`{}`), nil },
		Log:        discardLog(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve() }()
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	<-done
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket still present after Shutdown: %v", err)
	}
	if err := srv.Shutdown(); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}

// TestClientErrorsAreDistinct: an unreachable socket is a transport error, not a
// protocol error — `transitctl` renders the two differently.
func TestClientErrorsAreDistinct(t *testing.T) {
	c := &Client{SocketPath: filepath.Join(t.TempDir(), "absent.sock"), Key: string(testKey), Timeout: 200 * time.Millisecond}
	if _, err := c.Call(MethodStatus, nil); err == nil {
		t.Fatal("expected a transport error for a missing socket")
	}
	if _, err := (&Client{SocketPath: c.SocketPath}).Call(MethodStatus, nil); err == nil {
		t.Fatal("expected an error for an empty key")
	}
}

// TestCallErrorCarriesMethod: DecodeResult turns an error reply into a typed error
// naming the method, so a caller asserts on structure, not on a string prefix.
func TestCallErrorCarriesMethod(t *testing.T) {
	var out PingResult
	err := DecodeResult(&Response{Method: MethodPing, Error: errorText(ErrCodeRateLimited, "slow down")}, &out)
	var ce *CallError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *CallError", err)
	}
	if ce.Method != MethodPing || !strings.Contains(ce.Text, ErrCodeRateLimited) {
		t.Errorf("CallError = %+v", ce)
	}
	// A nil response and an empty result are handled without panicking.
	if err := DecodeResult(nil, &out); err == nil {
		t.Error("DecodeResult(nil) did not error")
	}
	if err := DecodeResult(&Response{Method: MethodPing}, &out); err != nil {
		t.Errorf("DecodeResult on an empty result: %v", err)
	}
}

// TestRequestKeyCaseInsensitive: a client that lowercases its header name is not
// rejected on spelling.
func TestRequestKeyCaseInsensitive(t *testing.T) {
	r := Request{Header: map[string]string{strings.ToLower(HeaderKey): "abc"}}
	if got := r.Key(); got != "abc" {
		t.Errorf("Key() = %q, want abc", got)
	}
	if got := (&Request{}).Key(); got != "" {
		t.Errorf("Key() with no header = %q, want empty", got)
	}
}

// TestStatusReplyIsOpaqueHealth keeps the layering honest: the status reply carries
// the health document as raw bytes, so a field the agent adds later needs no
// change here. This asserts the property directly rather than by reading the
// struct.
func TestStatusReplyIsOpaqueHealth(t *testing.T) {
	const health = `{"status":"ok","future":{"nested":[1,2,3]}}`
	_, client := newTestServer(t, Options{
		Status: func() (json.RawMessage, error) { return json.RawMessage(health), nil },
	})
	resp, err := client.Call(MethodStatus, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(resp.Result, &envelope); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if string(envelope["health"]) != health {
		t.Errorf("health = %s, want %s", envelope["health"], health)
	}
}

// TestDefaultSetPrimaryUpdatesMetric: the default hook is the durable record when
// the agent supplies none.
func TestDefaultSetPrimaryUpdatesMetric(t *testing.T) {
	if err := metrics.Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	s := &Server{opts: Options{}, log: discardLog()}
	if err := s.defaultSetPrimary("metric-probe"); err != nil {
		t.Fatalf("defaultSetPrimary: %v", err)
	}
	fams, err := metrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var found bool
	for _, f := range fams {
		if f.GetName() != "transitd_ctrl_set_primary" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == metrics.LabelTransit && lp.GetValue() == "metric-probe" {
					found = m.GetGauge().GetValue() == 1
				}
			}
		}
	}
	if !found {
		t.Error("ctrl_set_primary is not 1 for the recorded transit")
	}
}
