package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

var operatorSecret = keys("test-operator-secret-at-least-32-bytes")

// Fake SA tokens are JWT-shaped with an unsigned payload {sub: "<ns>:<name>", exp, nogroup}.
type saClaims struct {
	Sub     string `json:"sub"`
	Exp     int64  `json:"exp"`
	NoGroup bool   `json:"nogroup,omitempty"`
}

func saToken(c saClaims) string {
	if c.Exp == 0 {
		c.Exp = time.Now().Add(time.Hour).Unix()
	}
	b, _ := json.Marshal(c)
	return "x." + base64.RawURLEncoding.EncodeToString(b) + ".x"
}

func sa(sub string) string { return saToken(saClaims{Sub: sub}) }

// fakeKube is a TokenReview API for saToken tokens.
func fakeKube(t *testing.T) *httptest.Server {
	kube := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer callout-sa-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var tr struct {
			Spec struct {
				Token     string
				Audiences []string
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&tr)
		var c saClaims
		if parts := strings.Split(tr.Spec.Token, "."); len(parts) == 3 {
			b, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(b, &c)
		}
		var st map[string]any
		if p := strings.Split(c.Sub, ":"); len(p) == 2 && len(tr.Spec.Audiences) == 1 && tr.Spec.Audiences[0] == audience {
			groups := []string{"system:serviceaccounts", "system:authenticated"}
			if !c.NoGroup {
				groups = append(groups, "system:serviceaccounts:"+p[0])
			}
			st = map[string]any{"authenticated": true, "user": map[string]any{
				"username": "system:serviceaccount:" + p[0] + ":" + p[1],
				"groups":   groups,
				"extra":    map[string][]string{"authentication.kubernetes.io/pod-name": {p[1] + "-pod"}},
			}}
		} else {
			st = map[string]any{"authenticated": false, "error": "invalid token"}
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": st})
	}))
	t.Cleanup(kube.Close)
	return kube
}

// boot runs a real nats-server on the config `init` generates for master, with its data in dir,
// plus the callout. It returns the client URL and a stop func.
func boot(t *testing.T, dir string, master keys, kube *httptest.Server, admin *oidc.IDTokenVerifier) (string, func()) {
	t.Helper()
	cfg, err := serverConfig(operatorSecret, master)
	if err != nil {
		t.Fatal(err)
	}
	cfg["port"] = -1
	cfg["jetstream"] = map[string]any{"store_dir": filepath.Join(dir, "js")}
	cfg["resolver"] = map[string]any{"type": "full", "dir": filepath.Join(dir, "resolver")}
	conf, _ := json.Marshal(cfg)
	confPath := filepath.Join(dir, "nats.conf")
	if err := os.WriteFile(confPath, conf, 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := server.ProcessConfigFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	opts.NoLog, opts.NoSigs = true, true
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("server not ready")
	}
	tokenFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenFile, []byte("callout-sa-token\n"), 0o600)
	stop, err := start(ns.ClientURL(), &service{
		admin: admin, kube: kube.Client(), kubeAPI: kube.URL, kubeToken: tokenFile, replicas: 1, disk: map[string]int64{"app/worker": 2 << 30},
		m: master, sysAcct: pub(operatorSecret.sys()), authAcct: pub(operatorSecret.auth()),
	})
	if err != nil {
		ns.Shutdown()
		t.Fatal(err)
	}
	return ns.ClientURL(), func() { stop(); ns.Shutdown(); ns.WaitForShutdown() }
}

func dialer(t *testing.T, url string) (func(string) (*nats.Conn, error), func(string) *nats.Conn) {
	dial := func(token string) (*nats.Conn, error) {
		return nats.Connect(url, nats.Token(token), nats.MaxReconnects(0))
	}
	return dial, func(token string) *nats.Conn {
		t.Helper()
		nc, err := dial(token)
		if err != nil {
			t.Fatalf("connect %q: %v", token[:min(len(token), 20)], err)
		}
		t.Cleanup(nc.Close)
		return nc
	}
}

// TestEndToEnd drives every auth path.
func TestEndToEnd(t *testing.T) {
	adminKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	admin := oidc.NewVerifier(adminIssuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&adminKey.PublicKey}}, &oidc.Config{ClientID: adminClient})
	adminToken := func(groups ...string) string {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: adminKey}, nil)
		claims, _ := json.Marshal(map[string]any{
			"iss": adminIssuer, "aud": adminClient, "sub": "me", "groups": groups,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		jws, _ := signer.Sign(claims)
		s, _ := jws.CompactSerialize()
		return s
	}

	url, stop := boot(t, t.TempDir(), keys("test-master-secret-at-least-32-bytes"), fakeKube(t), admin)
	defer stop()
	dial, mustDial := dialer(t, url)

	// Same ServiceAccount shares an account; another ServiceAccount is isolated.
	a1, a2, other := mustDial(sa("app:worker")), mustDial(sa("app:worker")), mustDial(sa("app:other"))
	sub, _ := a2.SubscribeSync("hello")
	spy, _ := other.SubscribeSync("hello")
	_ = a2.Flush()
	_ = other.Flush()
	_ = a1.Publish("hello", []byte("hi"))
	if _, err := sub.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("same SA did not receive: %v", err)
	}
	if m, err := spy.NextMsg(300 * time.Millisecond); err == nil {
		t.Fatalf("other SA received %q", m.Data)
	}

	// JetStream is enabled for workload accounts.
	js, _ := a1.JetStream()
	if _, err := js.AddStream(&nats.StreamConfig{Name: "S", Subjects: []string{"s.>"}}); err != nil {
		t.Fatalf("jetstream: %v", err)
	}

	// NATS_ACCOUNT_DISK overrides the default JetStream disk cap per account.
	for nc, want := range map[*nats.Conn]int64{a1: 2 << 30, other: 1 << 30} {
		js, _ := nc.JetStream()
		if ai, err := js.AccountInfo(); err != nil || ai.Limits.MaxStore != want {
			t.Errorf("max store = %v (err %v), want %d", ai, err, want)
		}
	}
	if _, err := diskLimits("app/worker=1,bad"); err == nil {
		t.Error("diskLimits accepted a bad entry")
	}

	// Admin lands in SYS and can reach server internals.
	adm := mustDial(adminToken(adminGroup))
	if _, err := adm.Request("$SYS.REQ.SERVER.PING", nil, 2*time.Second); err != nil {
		t.Fatalf("admin ping: %v", err)
	}
	if _, err := a1.Request("$SYS.REQ.SERVER.PING", nil, 300*time.Millisecond); err == nil {
		t.Fatal("workload reached SYS")
	}

	for name, tok := range map[string]string{
		"default SA":    sa("app:default"),
		"missing group": saToken(saClaims{Sub: "app:worker", NoGroup: true}),
		"bad SA token":  "garbage",
		"non-admin":     adminToken("devs"),
		"no token":      "",
	} {
		if nc, err := dial(tok); err == nil {
			nc.Close()
			t.Errorf("%s: connected, want rejection", name)
		}
	}

	// The workload connection is dropped when its SA token expires.
	short := mustDial(saToken(saClaims{Sub: "app:worker", Exp: time.Now().Add(2 * time.Second).Unix()}))
	deadline := time.Now().Add(5 * time.Second)
	for !short.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !short.IsClosed() {
		t.Error("workload connection outlived its token")
	}

	// Sanity: the claim sniffing helper ignores junk.
	if iss, _ := peek("a.b"); iss != "" {
		t.Error("peek(junk)")
	}
	if iss, exp := peek(adminToken()); iss != adminIssuer || exp == 0 {
		t.Error("peek(admin)")
	}
}

// TestRotation rotates NATS_AUTH_MASTER and checks a workload keeps its account and JetStream data.
func TestRotation(t *testing.T) {
	dir, kube := t.TempDir(), fakeKube(t)
	admin := oidc.NewVerifier(adminIssuer, &oidc.StaticKeySet{}, &oidc.Config{ClientID: adminClient})

	url, stop := boot(t, dir, keys("first-master-secret-at-least-32-bytes"), kube, admin)
	_, mustDial := dialer(t, url)
	js, _ := mustDial(sa("app:worker")).JetStream()
	if _, err := js.AddStream(&nats.StreamConfig{Name: "S", Subjects: []string{"s.>"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish("s.1", []byte("kept")); err != nil {
		t.Fatal(err)
	}
	stop()

	url, stop = boot(t, dir, keys("second-master-secret-at-least-32-bytes"), kube, admin)
	defer stop()
	_, mustDial = dialer(t, url)
	js, _ = mustDial(sa("app:worker")).JetStream()
	m, err := js.GetLastMsg("S", "s.1")
	if err != nil || string(m.Data) != "kept" {
		t.Fatalf("stream data after rotation: %v", err)
	}
}
