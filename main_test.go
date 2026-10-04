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

// TestEndToEnd runs a real nats-server on the config `init` generates and drives every auth path.
func TestEndToEnd(t *testing.T) {
	k := keys("test-master-secret-at-least-32-bytes")
	dir := t.TempDir()

	cfg, err := serverConfig(k)
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
	defer ns.Shutdown()
	url := ns.ClientURL()

	// Fake SA tokens are JWT-shaped with an unsigned payload {sub: "<ns>:<name>", exp, nogroup}.
	type saClaims struct {
		Sub     string `json:"sub"`
		Exp     int64  `json:"exp"`
		NoGroup bool   `json:"nogroup,omitempty"`
	}
	saToken := func(c saClaims) string {
		if c.Exp == 0 {
			c.Exp = time.Now().Add(time.Hour).Unix()
		}
		b, _ := json.Marshal(c)
		return "x." + base64.RawURLEncoding.EncodeToString(b) + ".x"
	}
	sa := func(sub string) string { return saToken(saClaims{Sub: sub}) }

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
	defer kube.Close()
	tokenFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenFile, []byte("callout-sa-token\n"), 0o600)

	omniKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	admin := oidc.NewVerifier(omniIssuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&omniKey.PublicKey}}, &oidc.Config{ClientID: omniClient})
	omniToken := func(groups ...string) string {
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: omniKey}, nil)
		claims, _ := json.Marshal(map[string]any{
			"iss": omniIssuer, "aud": []string{omniClient}, "sub": "me@cullen.rocks", "cluster": omniCluster,
			"groups": groups, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		jws, _ := signer.Sign(claims)
		s, _ := jws.CompactSerialize()
		return s
	}

	stop, err := start(k, url, &service{admin: admin, kube: kube.Client(), kubeAPI: kube.URL, kubeToken: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	dial := func(token string) (*nats.Conn, error) {
		return nats.Connect(url, nats.Token(token), nats.MaxReconnects(0))
	}
	mustDial := func(token string) *nats.Conn {
		t.Helper()
		nc, err := dial(token)
		if err != nil {
			t.Fatalf("connect %q: %v", token[:min(len(token), 20)], err)
		}
		t.Cleanup(nc.Close)
		return nc
	}

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

	// Admin lands in SYS and can reach server internals.
	adm := mustDial(omniToken("system:masters"))
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
		"non-admin":     omniToken("devs"),
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
	if iss, exp := peek(omniToken()); iss != omniIssuer || exp == 0 {
		t.Error("peek(omni)")
	}
}
