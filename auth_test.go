package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func authRequest(t *testing.T, m keys, host string, mutate func(*jwt.AuthorizationRequestClaims)) (*nats.Msg, nkeys.KeyPair) {
	t.Helper()
	server, _ := nkeys.CreateServer()
	curve, _ := nkeys.CreateCurveKeys()
	user, _ := nkeys.CreateUser()
	c := jwt.NewAuthorizationRequestClaims(pub(user))
	c.Audience = "nats-authorization-request"
	c.Expires = time.Now().Add(2 * time.Second).Unix()
	c.UserNkey = pub(user)
	c.Server.ID = pub(server)
	c.Server.XKey = pub(curve)
	c.ClientInformation.Host = host
	if mutate != nil {
		mutate(c)
	}
	token, err := c.Encode(server)
	if err != nil {
		t.Fatal(err)
	}
	data, err := curve.Seal([]byte(token), pub(m.xkey()))
	if err != nil {
		t.Fatal(err)
	}
	return &nats.Msg{Data: data, Header: nats.Header{"Nats-Server-Xkey": []string{pub(curve)}}}, curve
}

func TestAuthorizationEnvelope(t *testing.T) {
	m := keys("test-auth-envelope")
	for name, mutate := range map[string]func(*jwt.AuthorizationRequestClaims){
		"valid":             nil,
		"expired":           func(c *jwt.AuthorizationRequestClaims) { c.Expires = time.Now().Add(-time.Second).Unix() },
		"no expiry":         func(c *jwt.AuthorizationRequestClaims) { c.Expires = 0 },
		"future":            func(c *jwt.AuthorizationRequestClaims) { c.NotBefore = time.Now().Add(time.Minute).Unix() },
		"issuer mismatch":   func(c *jwt.AuthorizationRequestClaims) { s, _ := nkeys.CreateServer(); c.Server.ID = pub(s) },
		"audience mismatch": func(c *jwt.AuthorizationRequestClaims) { c.Audience = "other" },
		"bad user":          func(c *jwt.AuthorizationRequestClaims) { c.UserNkey = "invalid" },
		"xkey mismatch":     func(c *jwt.AuthorizationRequestClaims) { x, _ := nkeys.CreateCurveKeys(); c.Server.XKey = pub(x) },
	} {
		t.Run(name, func(t *testing.T) {
			msg, _ := authRequest(t, m, "127.0.0.1", mutate)
			_, err := decodeAuthorization(m.xkey(), msg)
			if (err == nil) != (name == "valid") {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for _, msg := range []*nats.Msg{{Data: []byte("invalid")}, {Data: make([]byte, 65537)}} {
		if _, err := decodeAuthorization(m.xkey(), msg); err == nil {
			t.Fatal("accepted malformed payload")
		}
	}
}

func TestAuthorizationRejectsTamperedSignature(t *testing.T) {
	m := keys("signature-test")
	msg, curve := authRequest(t, m, "127.0.0.1", nil)
	raw, err := m.xkey().Open(msg.Data, pub(curve))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(raw), ".")
	replacement := "A"
	if parts[2][0] == 'A' {
		replacement = "B"
	}
	parts[2] = replacement + parts[2][1:]
	msg.Data, err = curve.Seal([]byte(strings.Join(parts, ".")), pub(m.xkey()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeAuthorization(m.xkey(), msg); err == nil {
		t.Fatal("accepted invalid server signature")
	}
}

func TestAuthorizationOverloadAndStop(t *testing.T) {
	s := &service{m: keys("bounded-test"), authAcct: pub(keys("auth-account").auth())}
	h := newAuthHandler(s)
	entered := make(chan struct{}, 8)
	var calls atomic.Int32
	h.authorize = func(ctx context.Context, _ *jwt.AuthorizationRequest) (string, error) {
		calls.Add(1)
		entered <- struct{}{}
		<-ctx.Done()
		return "", ctx.Err()
	}
	var replies sync.WaitGroup
	for i := 0; i < 8; i++ {
		msg, _ := authRequest(t, s.m, fmt.Sprintf("10.0.0.%d", i+1), nil)
		replies.Add(1)
		h.handle(msg, func([]byte) error { replies.Done(); return nil })
		<-entered
	}
	msg, curve := authRequest(t, s.m, "10.1.0.1", nil)
	replied := false
	h.handle(msg, func(data []byte) error {
		replied = true
		raw, err := curve.Open(data, pub(s.m.xkey()))
		if err != nil {
			t.Error(err)
			return err
		}
		c, err := jwt.DecodeAuthorizationResponseClaims(string(raw))
		if err != nil {
			t.Error(err)
			return err
		}
		if c.Error == "" || c.Audience == "" || c.IssuerAccount != s.authAcct {
			t.Error("invalid denial response")
		}
		return nil
	})
	if !replied || calls.Load() != 8 {
		t.Fatalf("overload queued: replied=%v calls=%d", replied, calls.Load())
	}
	before := time.Now()
	h.stop()
	if time.Since(before) > budget+200*time.Millisecond {
		t.Fatal("stop exceeded request budget")
	}
	replies.Wait()
	h.handle(msg, func([]byte) error { t.Error("handled after stop"); return nil })
}

func TestSourceLimiter(t *testing.T) {
	l := sourceLimiter{entries: map[string]*sourceLimit{}}
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !l.allow("127.0.0.1", now) {
			t.Fatal("burst denied")
		}
	}
	if l.allow("::ffff:127.0.0.1", now) {
		t.Fatal("mapped IPv4 bypassed limit")
	}
	if !l.allow("127.0.0.2", now) {
		t.Fatal("different IP blocked")
	}
	if l.allow("invalid", now) {
		t.Fatal("malformed IP accepted")
	}
	for i := 0; i < 5000; i++ {
		l.allow(fmt.Sprintf("2001:db8::%x", i+1), now)
	}
	if len(l.entries) > 4096 {
		t.Fatal("unbounded limiter")
	}
	if !l.allow("192.0.2.1", now.Add(2*time.Minute)) {
		t.Fatal("stale entries not reclaimed")
	}
}

func TestAuthorizationDeadlineStartsAtAdmission(t *testing.T) {
	s := &service{m: keys("deadline-test"), authAcct: pub(keys("account").auth())}
	h := newAuthHandler(s)
	defer h.stop()
	deadline := make(chan time.Time, 1)
	h.authorize = func(ctx context.Context, _ *jwt.AuthorizationRequest) (string, error) {
		d, _ := ctx.Deadline()
		deadline <- d
		return "", errDenied
	}
	expiry := time.Now().Add(2 * time.Second).Unix()
	msg, _ := authRequest(t, s.m, "127.0.0.1", func(c *jwt.AuthorizationRequestClaims) { c.Expires = expiry })
	before := time.Now()
	h.handle(msg, func([]byte) error { return nil })
	select {
	case got := <-deadline:
		if got.After(before.Add(budget+20*time.Millisecond)) || got.After(time.Unix(expiry, 0)) {
			t.Fatalf("deadline exceeds budget or signed expiry: %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("request never dispatched")
	}
}

func TestAuthorizationStopRacesWithAdmission(t *testing.T) {
	s := &service{m: keys("stop-test"), authAcct: pub(keys("account").auth())}
	h := newAuthHandler(s)
	h.authorize = func(ctx context.Context, _ *jwt.AuthorizationRequest) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	messages := make([]*nats.Msg, 32)
	for i := range messages {
		messages[i], _ = authRequest(t, s.m, fmt.Sprintf("192.0.2.%d", i+1), nil)
	}
	var wg sync.WaitGroup
	for _, msg := range messages {
		wg.Add(1)
		go func() { defer wg.Done(); h.handle(msg, func([]byte) error { return nil }) }()
	}
	h.stop()
	wg.Wait()
	h.stop()
}

func TestAuthorizationSourceFloodDoesNotBlockOtherIP(t *testing.T) {
	s := &service{m: keys("source-flood-test"), authAcct: pub(keys("account").auth())}
	h := newAuthHandler(s)
	defer h.stop()
	var calls atomic.Int32
	h.authorize = func(context.Context, *jwt.AuthorizationRequest) (string, error) { calls.Add(1); return "", errDenied }
	for i := 0; i < 12; i++ {
		host := "127.0.0.1"
		if i == 11 {
			host = "127.0.0.2"
		}
		msg, _ := authRequest(t, s.m, host, nil)
		done := make(chan struct{})
		h.handle(msg, func([]byte) error { close(done); return nil })
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("request queued")
		}
	}
	if calls.Load() != 11 {
		t.Fatalf("expected ten same-IP requests and one other IP, got %d", calls.Load())
	}
}
