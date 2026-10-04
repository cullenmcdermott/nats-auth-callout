package main

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/time/rate"
)

// Requests never wait for a worker: queueing can outlive the server's auth deadline.
func startAuthorization(nc *nats.Conn, s *service) (func(), error) {
	h := newAuthHandler(s)
	sub, err := nc.QueueSubscribe("$SYS.REQ.USER.AUTH", "auth", func(msg *nats.Msg) { h.handle(msg, msg.Respond) })
	if err != nil {
		h.stop()
		return nil, err
	}
	// Bound the transport's own pending queue as well as upstream concurrency.
	if err = sub.SetPendingLimits(64, 4<<20); err == nil {
		err = nc.FlushTimeout(budget)
	}
	if err != nil {
		_ = sub.Unsubscribe()
		h.stop()
		return nil, err
	}
	return func() { _ = sub.Unsubscribe(); h.stop() }, nil
}

type authHandler struct {
	s         *service
	authorize func(context.Context, *jwt.AuthorizationRequest) (string, error)
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	stopped   bool
	wg        sync.WaitGroup
	slots     chan struct{}
	sources   sourceLimiter
}

func newAuthHandler(s *service) *authHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &authHandler{s: s, authorize: s.authorize, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 8), sources: sourceLimiter{entries: map[string]*sourceLimit{}}}
}

func (h *authHandler) stop() {
	h.mu.Lock()
	h.stopped = true
	h.cancel()
	h.mu.Unlock()
	h.wg.Wait()
}

func decodeAuthorization(xkey nkeys.KeyPair, msg *nats.Msg) (*jwt.AuthorizationRequestClaims, error) {
	if len(msg.Data) > 64<<10 || len(msg.Data) == 0 {
		return nil, errors.New("invalid authorization payload size")
	}
	serverKey := msg.Header.Get("Nats-Server-Xkey")
	if !nkeys.IsValidPublicCurveKey(serverKey) {
		return nil, errors.New("missing server encryption key")
	}
	data, err := xkey.Open(msg.Data, serverKey)
	if err != nil {
		return nil, errors.New("invalid authorization encryption")
	}
	req, err := jwt.DecodeAuthorizationRequestClaims(string(data))
	if err != nil {
		return nil, errors.New("invalid authorization signature")
	}
	vr := jwt.CreateValidationResults()
	req.Validate(vr)
	if vr.IsBlocking(true) || req.Expires <= time.Now().Unix() || req.Audience != "nats-authorization-request" || !nkeys.IsValidPublicServerKey(req.Server.ID) || req.Issuer != req.Server.ID || req.Server.XKey != serverKey {
		return nil, errors.New("invalid authorization claims")
	}
	return req, nil
}

func (h *authHandler) handle(msg *nats.Msg, reply func([]byte) error) {
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()
	deadline := time.Now().Add(budget)
	req, err := decodeAuthorization(h.s.m.xkey(), msg)
	if err != nil {
		failures.Inc()
		return // No trustworthy reply destination or user identity.
	}
	if expiry := time.Unix(req.Expires, 0); expiry.Before(deadline) {
		deadline = expiry
	}
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return
	}
	allowed := h.sources.allow(req.ClientInformation.Host, time.Now())
	if allowed {
		select {
		case h.slots <- struct{}{}:
		default:
			allowed = false
		}
	}
	if !allowed {
		h.mu.Unlock()
		failures.Inc()
		h.respond(req, "", errors.New("authorization capacity exceeded"), reply)
		return
	}
	h.wg.Add(1) // Serialized with stopped, so Stop cannot race with Add.
	h.mu.Unlock()
	go func() {
		defer h.wg.Done()
		defer func() { <-h.slots }()
		ctx, cancel := context.WithDeadline(h.ctx, deadline)
		defer cancel()
		var user string
		err := ctx.Err()
		if err == nil {
			user, err = h.authorize(ctx, &req.AuthorizationRequest)
		}
		if ctx.Err() != nil {
			user, err = "", ctx.Err()
		}
		h.respond(req, user, err, reply)
	}()
}

func (h *authHandler) respond(req *jwt.AuthorizationRequestClaims, user string, err error, reply func([]byte) error) {
	response := jwt.NewAuthorizationResponseClaims(req.UserNkey)
	response.Audience = req.Server.ID
	response.IssuerAccount = h.s.authAcct
	response.Expires = req.Expires
	if err != nil || user == "" {
		response.Error = "authorization denied"
	} else {
		response.Jwt = user
	}
	token, err := response.Encode(h.s.m.authSigner())
	if err == nil {
		var data []byte
		data, err = h.s.m.xkey().Seal([]byte(token), req.Server.XKey)
		if err == nil {
			err = reply(data)
		}
	}
	if err != nil {
		failures.Inc()
	}
}

type sourceLimit struct {
	limiter *rate.Limiter
	seen    time.Time
}
type sourceLimiter struct {
	entries   map[string]*sourceLimit
	nextSweep time.Time
}

// Called under the handler mutex. The bounded map cannot grow with spoofed clients.
func (l *sourceLimiter) allow(host string, now time.Time) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	host = ip.Unmap().String()
	entry := l.entries[host]
	if entry == nil {
		if len(l.entries) >= 4096 {
			if now.Before(l.nextSweep) {
				return false
			}
			l.nextSweep = now.Add(time.Minute)
			for key, old := range l.entries {
				if now.Sub(old.seen) >= time.Minute {
					delete(l.entries, key)
				}
			}
			if len(l.entries) >= 4096 {
				return false
			}
		}
		entry = &sourceLimit{limiter: rate.NewLimiter(5, 10)}
		l.entries[host] = entry
	}
	entry.seen = now
	return entry.limiter.AllowN(now, 1)
}
