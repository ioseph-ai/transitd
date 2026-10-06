package ctrl

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ioseph-ai/transitd/internal/metrics"
)

// Socket directory and socket modes. The directory is 0750 so only root (and a
// group the operator chooses) can traverse into it; the socket is 0660 for the
// same reason. Both are owned by the process's uid/gid, which for the agent is
// root:root. A local client is therefore already inside the OS permission
// boundary, and the shared key is the second, orthogonal gate (see PROTOCOL.md).
const (
	socketDirMode  = 0o750
	socketFileMode = 0o660
)

// DefaultReadTimeout bounds how long the server waits for one request's bytes.
// A control client is local and interactive: a request that has not arrived in
// this long is not going to. It is short so a connection that opens and stalls
// cannot tie up the accept loop's goroutines.
const DefaultReadTimeout = 5 * time.Second

// StatusFunc returns the healthz-equivalent JSON document. It is the agent's
// seam into this package: the server never imports internal/agent, so a test can
// hand it a literal and the wire contract is proved without an agent in the
// process.
type StatusFunc func() (json.RawMessage, error)

// Options configures a Server. Router, Key and Status are required; everything
// else has a production default.
type Options struct {
	// SocketPath is the unix socket to serve on. Required.
	SocketPath string

	// Key is the gossip shared key, decoded. Every request must present it.
	// Required: a server with no key would authenticate nothing, and this
	// package refuses to be constructed that way rather than open an
	// unauthenticated control channel.
	Key []byte

	// Router is the agent's configured router name, echoed in every reply.
	Router string

	// Status produces the healthz-equivalent document for MethodStatus. Required.
	Status StatusFunc

	// SetPrimary records a desired-primary preference. It is called only after a
	// request passed auth and the rate limit, with a transit name already checked
	// against the configured set. Nil means the default, which logs the
	// preference and updates transitd_ctrl_set_primary; the agent supplies its own
	// to also keep the preference in memory for /healthz.
	SetPrimary func(transit string) error

	// KnownTransit reports whether name is a configured transit. Nil means the
	// default, which accepts any syntactically valid name — correct for a test
	// with no config, wrong for the agent, which always sets it.
	KnownTransit func(name string) bool

	// Limiter is the per-method token bucket. Nil means
	// NewLimiter(DefaultRateLimit, time.Minute, nil).
	Limiter *Limiter

	// Log receives the audit lines: every auth failure, every rate-limit drop
	// and every accepted set-primary. Nil means slog.Default().
	Log *slog.Logger

	// ReadTimeout bounds one request's read. Zero means DefaultReadTimeout.
	ReadTimeout time.Duration
}

// Server is the local control channel. It owns the listening socket for its
// whole life: New creates it, Shutdown removes it.
type Server struct {
	opts Options
	log  *slog.Logger

	ln      net.Listener
	limiter *Limiter

	// wg tracks in-flight connections so Shutdown can wait for them rather than
	// closing the listener out from under a reply.
	wg sync.WaitGroup

	// closeOnce guards Shutdown against a double call, which would otherwise
	// close an already-closed listener and remove a socket a successor may have
	// recreated.
	closeOnce sync.Once
}

// New binds the socket and returns a serving Server. It creates the socket's
// parent directory with mode 0750 if missing, binds with mode 0660, and refuses
// to run with a missing key or status function.
func New(opts Options) (*Server, error) {
	if opts.SocketPath == "" {
		return nil, fmt.Errorf("ctrl: Options.SocketPath is required")
	}
	if len(opts.Key) == 0 {
		return nil, fmt.Errorf("ctrl: Options.Key is required — the control channel authenticates every request with the gossip shared key")
	}
	if opts.Status == nil {
		return nil, fmt.Errorf("ctrl: Options.Status is required")
	}
	s := &Server{opts: opts, log: opts.Log, limiter: opts.Limiter}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.limiter == nil {
		s.limiter = NewLimiter(DefaultRateLimit, time.Minute, nil)
	}
	if s.opts.SetPrimary == nil {
		s.opts.SetPrimary = s.defaultSetPrimary
	}
	if s.opts.KnownTransit == nil {
		s.opts.KnownTransit = func(string) bool { return true }
	}
	if s.opts.ReadTimeout <= 0 {
		s.opts.ReadTimeout = DefaultReadTimeout
	}

	dir := filepath.Dir(opts.SocketPath)
	// Create the directory 0750 if it is missing, and fix its mode only when we
	// created it: MkdirAll applies the umask, and a freshly created directory whose
	// mode the umask masked is a directory the group may not be able to traverse
	// as intended. A directory that already exists is the operator's — chmod-ing it
	// would let a socket_path that names a shared directory (say /run/ctrl.sock)
	// silently tighten /run's mode, which is not this server's to change.
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, socketDirMode); err != nil {
			return nil, fmt.Errorf("ctrl: creating socket directory %s: %w", dir, err)
		}
		if err := os.Chmod(dir, socketDirMode); err != nil {
			return nil, fmt.Errorf("ctrl: setting socket directory mode on %s: %w", dir, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("ctrl: probing socket directory %s: %w", dir, err)
	}

	// A unix socket cannot be bound over (EADDRINUSE for a stale socket file). A
	// socket left by a previous crash is expected after an unclean restart, so it
	// is removed first — but only if it really is a socket, so a mistyped
	// socket_path that names a regular file is refused rather than deleted.
	if fi, err := os.Lstat(opts.SocketPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("ctrl: %s exists and is not a socket (mode %s) — refusing to remove it", opts.SocketPath, fi.Mode())
		}
		if err := os.Remove(opts.SocketPath); err != nil {
			return nil, fmt.Errorf("ctrl: removing stale socket %s: %w", opts.SocketPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ctrl: probing %s: %w", opts.SocketPath, err)
	}

	ln, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("ctrl: listening on %s: %w", opts.SocketPath, err)
	}
	// The process umask would otherwise mask the mode net.Listen passed, so the
	// 0660 promise is applied explicitly after the bind.
	if err := os.Chmod(opts.SocketPath, socketFileMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("ctrl: setting socket mode on %s: %w", opts.SocketPath, err)
	}
	s.ln = ln
	return s, nil
}

// Serve accepts connections until Shutdown. It is the blocking form; the agent
// runs it on its own goroutine.
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			// Shutdown closes the listener; that is a clean stop, not a failure.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("ctrl: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(conn)
		}()
	}
}

// Addr returns the bound socket address, for a log line.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Shutdown stops accepting, waits for in-flight connections, and removes the
// socket. It is idempotent because both a signal path and an error path reach
// it; a double call would close an already-closed listener and try to remove a
// socket that is already gone.
func (s *Server) Shutdown() error {
	var err error
	s.closeOnce.Do(func() {
		if cerr := s.ln.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
			err = fmt.Errorf("ctrl: closing listener: %w", cerr)
		}
		// Wait before removing the file: a handler still writing its reply must
		// not find the socket gone under it. The socket unlinks on close, so the
		// explicit Remove below is a belt-and-braces cleanup for a path the kernel
		// may have already unlinked.
		s.wg.Wait()
		if rerr := os.Remove(s.opts.SocketPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("ctrl: removing socket %s: %w", s.opts.SocketPath, rerr))
		}
	})
	return err
}

// serveConn reads one request, dispatches it and writes the reply, then closes
// the connection. The protocol is one request per connection: it keeps the
// server's state per-connection free and makes the socket trivially driveable by
// tools that open, write, read and hang up.
func (s *Server) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(s.opts.ReadTimeout))

	// io.LimitReader caps the body at maxRequestBytes+1 so an oversized request is
	// detected (a full read) rather than buffered without bound.
	body, err := io.ReadAll(io.LimitReader(conn, maxRequestBytes+1))
	if err != nil {
		s.writeResp(conn, Response{V: ProtocolVersion, Error: errorText(ErrCodeBadRequest, "reading request: "+err.Error())})
		return
	}
	if len(body) > maxRequestBytes {
		s.writeResp(conn, Response{V: ProtocolVersion, Error: errorText(ErrCodeBadRequest, "request body exceeds 4 KiB")})
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeResp(conn, Response{V: ProtocolVersion, Error: errorText(ErrCodeBadRequest, "malformed JSON request: "+err.Error())})
		return
	}

	// Auth first, before method dispatch: an unauthenticated caller must not be
	// able to probe which methods exist by the shape of the error it gets back.
	if !s.authenticate(&req) {
		s.writeResp(conn, Response{V: ProtocolVersion, Method: req.Method, Error: errorText(ErrCodeUnauthorized, "missing or wrong "+HeaderKey)})
		return
	}

	method := req.Method
	if method == "" {
		s.writeResp(conn, Response{V: ProtocolVersion, Error: errorText(ErrCodeBadRequest, "request has no method")})
		return
	}
	if RateLimited(method) && !s.limiter.Allow(method) {
		metrics.CtrlRateLimited.Inc()
		s.log.Warn("control: request rate-limited", "method", method, "remote", conn.RemoteAddr().String())
		s.writeResp(conn, Response{V: ProtocolVersion, Method: method, Error: errorText(ErrCodeRateLimited, "too many requests; retry later")})
		return
	}

	result, code, detail := s.dispatch(method, req.Params)
	if code != "" {
		s.writeResp(conn, Response{V: ProtocolVersion, Method: method, Error: errorText(code, detail)})
		return
	}
	s.writeResp(conn, Response{V: ProtocolVersion, Method: method, Result: result})
}

// authenticate compares the presented key against the configured one in constant
// time and records the outcome. Every failure audit-logs and increments
// transitd_ctrl_auth_fail; the key itself is never logged.
//
// The presented header carries the key in its base64 config form (what an
// operator has in `gossip.key`, and what PROTOCOL.md documents), while the server
// holds the decoded bytes. The presented value is decoded and the two byte
// strings compared, so the comparison is over the secret itself rather than over
// one encoding of it — two base64 spellings of the same key (trailing padding
// aside) are the same key.
func (s *Server) authenticate(req *Request) bool {
	presented := req.Key()
	presentedBytes, decErr := base64.StdEncoding.DecodeString(presented)
	// A value that is not base64 at all cannot be the key. Decode failure and a
	// wrong key produce the same reply, and the comparison below still runs on a
	// zero-length slice so neither path returns early in a way that would be
	// measurable.
	ok := decErr == nil && subtle.ConstantTimeCompare(presentedBytes, s.opts.Key) == 1
	if !ok {
		metrics.CtrlAuthFail.Inc()
		s.log.Warn("control: auth rejected",
			"method", req.Method,
			"presented", presented == "",
			"reason", authReason(presented, decErr))
		return false
	}
	return true
}

// authReason renders a failure for the audit line without echoing the secret. A
// missing key, a malformed one and a wrong one are operationally different (a
// broken client vs. a probing one), so they are distinguishable in the log.
func authReason(presented string, decErr error) string {
	switch {
	case presented == "":
		return "no " + HeaderKey + " header"
	case decErr != nil:
		return "presented key is not base64"
	default:
		return "wrong key"
	}
}

// dispatch routes an authenticated, rate-limit-cleared request to its method. It
// returns the marshalled result, or an error code with a detail string.
func (s *Server) dispatch(method string, params json.RawMessage) (json.RawMessage, string, string) {
	switch method {
	case MethodStatus:
		return s.methodStatus()
	case MethodPing:
		b, err := json.Marshal(PingResult{Version: ProtocolVersion, Router: s.opts.Router})
		if err != nil {
			return nil, ErrCodeInternal, err.Error()
		}
		return b, "", ""
	case MethodSetPrimary:
		return s.methodSetPrimary(params)
	default:
		return nil, ErrCodeBadRequest, fmt.Sprintf("unknown method %q", method)
	}
}

// methodStatus returns the healthz-equivalent document, wrapped with the protocol
// version and router name. It does not call the Status func outside the lock-free
// path: Status is the agent's own reader and is expected to be cheap.
func (s *Server) methodStatus() (json.RawMessage, string, string) {
	health, err := s.opts.Status()
	if err != nil {
		return nil, ErrCodeInternal, "collecting health: " + err.Error()
	}
	if len(health) == 0 {
		// A nil/empty document would marshal to "health":null, which a client
		// cannot tell from a healthy agent with no fields. Refuse it.
		return nil, ErrCodeInternal, "status function returned an empty document"
	}
	b, err := json.Marshal(StatusResult{Version: ProtocolVersion, Router: s.opts.Router, Health: health})
	if err != nil {
		return nil, ErrCodeInternal, err.Error()
	}
	return b, "", ""
}

// methodSetPrimary validates the transit name, records the preference through the
// SetPrimary hook, and replies. Applied is always false in this MVP: the reply
// says so explicitly so a client cannot mistake "recorded" for "in effect".
func (s *Server) methodSetPrimary(params json.RawMessage) (json.RawMessage, string, string) {
	var p SetPrimaryParams
	if len(params) == 0 {
		return nil, ErrCodeBadRequest, "set-primary requires params with a transit name"
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, ErrCodeBadRequest, "bad params: " + err.Error()
	}
	p.Transit = strings.TrimSpace(p.Transit)
	if p.Transit == "" {
		return nil, ErrCodeBadRequest, "set-primary requires a non-empty transit name"
	}
	if !s.opts.KnownTransit(p.Transit) {
		return nil, ErrCodeBadRequest, fmt.Sprintf("unknown transit %q", p.Transit)
	}
	if err := s.opts.SetPrimary(p.Transit); err != nil {
		return nil, ErrCodeInternal, "recording preference: " + err.Error()
	}
	// The audit line is the durable record an operator reads to answer "who
	// asked for what, and when". It is logged at INFO because a preference
	// request is a normal operator action, unlike an auth failure.
	s.log.Info("control: set-primary requested (recorded, NOT applied — observe-only, issue #4)",
		"transit", p.Transit, "applied", false)

	b, err := json.Marshal(SetPrimaryResult{
		Version: ProtocolVersion,
		Router:  s.opts.Router,
		Transit: p.Transit,
		Applied: false,
		Note:    "recorded desired primary; not applied — this build is observe-only (act wiring tracks issue #4)",
	})
	if err != nil {
		return nil, ErrCodeInternal, err.Error()
	}
	return b, "", ""
}

// defaultSetPrimary is the SetPrimary hook used when the agent does not supply
// one: it records the preference as a metric, 1 for the named transit and 0 for
// every other transit the hook has ever seen. The agent overrides it to also
// keep the name for /healthz.
func (s *Server) defaultSetPrimary(transit string) error {
	metrics.CtrlSetPrimary.WithLabelValues(transit).Set(1)
	return nil
}

// writeResp encodes one reply. An encode failure cannot be reported to the
// client — the reply is the failure channel — so it is logged and the connection
// is simply closed.
//
// The write gets its own deadline: the read deadline governs how long a client may
// take to send its request, but a client that has sent it and then stopped reading
// would otherwise block this Write forever and hang Shutdown's wait on in-flight
// connections. A local client is fast, so the deadline is short.
func (s *Server) writeResp(conn net.Conn, resp Response) {
	b, err := json.Marshal(resp)
	if err != nil {
		s.log.Error("control: encoding reply", "err", err)
		return
	}
	b = append(b, '\n')
	_ = conn.SetWriteDeadline(time.Now().Add(s.opts.ReadTimeout))
	if _, err := conn.Write(b); err != nil {
		s.log.Debug("control: writing reply", "err", err)
	}
}
