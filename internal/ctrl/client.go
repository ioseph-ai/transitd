package ctrl

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// DefaultDialTimeout bounds connecting to the agent's socket. A local unix
// socket connect is effectively instant; the timeout exists so a client against
// a full accept queue or a hung agent fails with a message instead of hanging
// forever.
const DefaultDialTimeout = 5 * time.Second

// maxResponseBytes bounds a reply the client will read. It mirrors the server's
// request cap: the largest legitimate reply is a healthz document with one entry
// per transit, which is far below this.
const maxResponseBytes = 1 << 20 // 1 MiB

// Client is the control channel's client side. It is what `cmd/transitctl` uses
// and what the integration test drives against a live agent, so the wire format
// has one implementation shared by production and test rather than two that can
// drift.
type Client struct {
	// SocketPath is the agent's control socket. Required.
	SocketPath string
	// Key is the gossip shared key, base64, as the operator's config holds it.
	// Required.
	Key string
	// Timeout bounds the whole call: dial, write and read. Zero means
	// DefaultDialTimeout.
	Timeout time.Duration
}

// Call sends one request and returns the reply. A transport failure (dial, write,
// read) is returned as an error; a well-formed protocol-level failure is returned
// as a Response with a non-empty Error, which the caller renders. Keeping those
// two apart is what lets `transitctl` say "the agent refused" distinctly from "I
// could not reach the agent".
func (c *Client) Call(method string, params any) (*Response, error) {
	if c.SocketPath == "" {
		return nil, fmt.Errorf("ctrl: client socket path is empty")
	}
	if c.Key == "" {
		return nil, fmt.Errorf("ctrl: client key is empty (the control channel authenticates with the gossip shared key)")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	deadline := time.Now().Add(timeout)

	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("unix", c.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("ctrl: dialing %s: %w", c.SocketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("ctrl: encoding params: %w", err)
		}
		rawParams = b
	}
	req := Request{
		V:      ProtocolVersion,
		Header: map[string]string{HeaderKey: c.Key},
		Method: method,
		Params: rawParams,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("ctrl: encoding request: %w", err)
	}
	body = append(body, '\n')
	if _, err := conn.Write(body); err != nil {
		return nil, fmt.Errorf("ctrl: writing request: %w", err)
	}

	// Half-close the write side so the server's one-read-per-connection loop
	// sees a clean EOF rather than waiting for the read timeout. A plain unix
	// socket supports this; if it errors, the read below still works because the
	// request bytes are already in the socket buffer.
	if uw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = uw.CloseWrite()
	}

	line, err := bufio.NewReader(io.LimitReader(conn, maxResponseBytes+1)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, fmt.Errorf("ctrl: reading reply: %w", err)
	}
	if len(line) > maxResponseBytes {
		return nil, fmt.Errorf("ctrl: reply exceeds %d bytes", maxResponseBytes)
	}
	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(line), &resp); err != nil {
		return nil, fmt.Errorf("ctrl: malformed reply from %s: %w", c.SocketPath, err)
	}
	return &resp, nil
}

// DecodeResult unmarshals a response's Result into out, turning an error response
// into a Go error carrying the protocol's error text. It is the one place a
// caller has to look at the `error` field, so no caller can accidentally treat a
// failure envelope as a success.
func DecodeResult(resp *Response, out any) error {
	if resp == nil {
		return fmt.Errorf("ctrl: nil response")
	}
	if resp.Error != "" {
		return &CallError{Method: resp.Method, Text: resp.Error}
	}
	if out == nil {
		return nil
	}
	if len(resp.Result) == 0 {
		return nil
	}
	return json.Unmarshal(resp.Result, out)
}

// CallError is a protocol-level failure returned by the agent: the request was
// delivered and answered, but refused. Its presence in the type system is what
// lets a caller (and a test) assert on the error CODE without string-matching an
// errno.
type CallError struct {
	Method string
	Text   string
}

func (e *CallError) Error() string {
	return fmt.Sprintf("control %s: %s", e.Method, e.Text)
}
