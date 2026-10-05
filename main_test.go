package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var operatorSecret = keys("test-operator-secret-at-least-32-bytes")

// Fake SA tokens are JWT-shaped with an unsigned payload {sub: "<ns>:<name>", exp, nogroup}.
type saClaims struct {
	Sub       string    `json:"sub"`
	Exp       int64     `json:"exp"`
	NoGroup   bool      `json:"nogroup,omitempty"`
	UID       string    `json:"uid,omitempty"`
	NoUID     bool      `json:"nouid,omitempty"`
	Audiences *[]string `json:"audiences,omitempty"`
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
			uid := c.UID
			if uid == "" && !c.NoUID {
				uid = "uid-" + strings.ReplaceAll(c.Sub, ":", "-")
			}
			audiences := []string{audience}
			if c.Audiences != nil {
				audiences = *c.Audiences
			}
			st = map[string]any{"authenticated": true, "audiences": audiences, "user": map[string]any{
				"uid":      uid,
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
	ns, stop := bootServer(t, dir, master, kube, admin, true)
	return ns.ClientURL(), stop
}

func bootServer(t *testing.T, dir string, master keys, kube *httptest.Server, admin *oidc.IDTokenVerifier, websocketTLS bool) (*server.Server, func()) {
	t.Helper()
	cfg, err := serverConfig(operatorSecret, master)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := testCertificate(t, dir)
	t.Setenv("NATS_TLS_CA", certFile)
	t.Setenv("NATS_TLS_SERVER_NAME", "")
	cfg["tls"] = map[string]any{"cert_file": certFile, "key_file": keyFile, "min_version": "1.2"}
	cfg["websocket"] = map[string]any{"port": -1, "tls": cfg["tls"]}
	if !websocketTLS {
		cfg["websocket"] = map[string]any{"port": -1, "no_tls": true}
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
		admin: admin, kube: kube.Client(), kubeAPI: kube.URL, kubeToken: tokenFile, replicas: 1, disk: map[string]int64{"app/worker": 2 << 30}, mem: map[string]int64{"app/worker": 48 << 20},
		m: master, sysAcct: pub(operatorSecret.sys()), authAcct: pub(operatorSecret.auth()),
	})
	if err != nil {
		ns.Shutdown()
		t.Fatal(err)
	}
	return ns, func() { stop(); ns.Shutdown(); ns.WaitForShutdown() }
}

func dialer(t *testing.T, url string) (func(string) (*nats.Conn, error), func(string) *nats.Conn) {
	dial := func(token string) (*nats.Conn, error) {
		cfg, err := natsTLS()
		if err != nil {
			return nil, err
		}
		return nats.Connect(url, nats.Secure(cfg), nats.Token(token), nats.MaxReconnects(0))
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

	// Account byte limits override the defaults only for listed accounts.
	for nc, want := range map[*nats.Conn]int64{a1: 2 << 30, other: 1 << 30} {
		js, _ := nc.JetStream()
		if ai, err := js.AccountInfo(); err != nil || ai.Limits.MaxStore != want {
			t.Errorf("max store = %v (err %v), want %d", ai, err, want)
		}
	}
	for nc, want := range map[*nats.Conn]int64{a1: 48 << 20, other: 0} {
		js, _ := nc.JetStream()
		if ai, err := js.AccountInfo(); err != nil || ai.Limits.MaxMemory != want {
			t.Errorf("max memory = %v (err %v), want %d", ai, err, want)
		}
	}
	if _, err := byteLimits("NATS_ACCOUNT_MEMORY", "app/worker=1,bad"); err == nil || !strings.Contains(err.Error(), "NATS_ACCOUNT_MEMORY") {
		t.Errorf("byteLimits bad entry error = %v, want NATS_ACCOUNT_MEMORY", err)
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

	// Rejected credentials count as deny; error is reserved for our own failures.
	for labels, want := range map[[2]string]bool{
		{"workload", "allow"}: true, {"workload", "deny"}: true, {"admin", "allow"}: true, {"admin", "deny"}: true,
		{"workload", "error"}: false, {"admin", "error"}: false,
	} {
		if got := testutil.ToFloat64(decisions.WithLabelValues(labels[:]...)) > 0; got != want {
			t.Errorf("decisions%v counted = %v, want %v", labels, got, want)
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

func TestTokenReviewTrust(t *testing.T) {
	kube := fakeKube(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("callout-sa-token"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &service{kube: kube.Client(), kubeAPI: kube.URL, kubeToken: tokenFile}
	for name, c := range map[string]saClaims{
		"valid":            {Sub: "app:worker"},
		"missing UID":      {Sub: "app:worker", NoUID: true},
		"missing audience": {Sub: "app:worker", Audiences: &[]string{}},
		"wrong audience":   {Sub: "app:worker", Audiences: &[]string{"https://kubernetes.default.svc"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, _, err := s.tokenReview(context.Background(), saToken(c))
			if (err == nil) != (name == "valid") {
				t.Fatalf("TokenReview %s: err=%v", name, err)
			}
		})
	}
}

func TestAccountOwnership(t *testing.T) {
	kube := fakeKube(t)
	admin := oidc.NewVerifier(adminIssuer, &oidc.StaticKeySet{}, &oidc.Config{ClientID: adminClient})
	m := keys("test-master-secret-at-least-32-bytes")
	url, stop := boot(t, t.TempDir(), m, kube, admin)
	defer stop()
	dial, mustDial := dialer(t, url)
	ownerToken := saToken(saClaims{Sub: "app:worker", UID: "original-uid"})
	original := mustDial(ownerToken)
	js, _ := original.JetStream()
	if _, err := js.AddStream(&nats.StreamConfig{Name: "PRIVATE", Subjects: []string{"private.>"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish("private.data", []byte("original data")); err != nil {
		t.Fatal(err)
	}
	replacement := saToken(saClaims{Sub: "app:worker", UID: "replacement-uid"})
	if nc, err := dial(replacement); err == nil {
		nc.Close()
		t.Error("recreated ServiceAccount inherited account")
	}
	msg, err := js.GetLastMsg("PRIVATE", "private.data")
	if err != nil || string(msg.Data) != "original data" {
		t.Fatalf("original data changed: %v", err)
	}

	// Legacy records must remain intact and require explicit UID migration.
	auth, err := connect(url, "test-kv", pub(operatorSecret.auth()), m.authSigner(), m.user("callout"))
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	jskv, err := jetstream.New(auth)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := jskv.KeyValue(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	e, err := kv.Get(context.Background(), "app/worker")
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Account string `json:"account"`
	}
	raw := e.Value()
	if json.Unmarshal(raw, &record) == nil && record.Account != "" {
		raw = []byte(record.Account)
	}
	if _, err = kv.Put(context.Background(), "app/worker", raw); err != nil {
		t.Fatal(err)
	}
	if nc, err := dial(ownerToken); err == nil {
		nc.Close()
		t.Error("legacy mapping adopted without verified UID")
	}
	after, err := kv.Get(context.Background(), "app/worker")
	if err != nil {
		t.Fatal(err)
	}
	if string(after.Value()) != string(raw) {
		t.Fatal("legacy mapping modified during denied login")
	}
	// An explicit revision-checked migration preserves the original account and data.
	if err := migrateAccount(context.Background(), kv, "app/worker", string(raw), "original-uid"); err != nil {
		t.Fatal(err)
	}

	migrated := mustDial(ownerToken)
	migratedJS, err := migrated.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	preserved, err := migratedJS.GetLastMsg("PRIVATE", "private.data")
	if err != nil || string(preserved.Data) != "original data" {
		t.Fatalf("data not preserved after UID migration: %v", err)
	}

}

func TestPlaintextClientDenied(t *testing.T) {
	s := &service{}
	req := &jwt.AuthorizationRequest{ConnectOptions: jwt.ConnectOptions{Token: "nonempty"}}
	kind, _, _, err := s.decide(context.Background(), req)
	if err == nil {
		t.Fatalf("plaintext accepted, kind=%s", kind)
	}
	if !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("plaintext not rejected at transport boundary: %v", err)
	}
}

func TestConnectRequiresTLS(t *testing.T) {
	ns, err := server.NewServer(&server.Options{Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	defer ns.Shutdown()
	if !ns.ReadyForConnections(time.Second) {
		t.Fatal("server not ready")
	}
	m := keys("test-connect-master")
	nc, err := connect(ns.ClientURL(), "test", pub(m.auth()), m.authSigner(), m.user("callout"))
	if err == nil {
		nc.Close()
		t.Fatal("callout connected to plaintext server")
	}
}

func testCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for path, b := range map[string][]byte{certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), keyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})} {
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile
}

func TestNATSCertificateVerification(t *testing.T) {
	admin := oidc.NewVerifier(adminIssuer, &oidc.StaticKeySet{}, &oidc.Config{ClientID: adminClient})
	url, stop := boot(t, t.TempDir(), keys("test-master-secret-at-least-32-bytes"), fakeKube(t), admin)
	defer stop()
	dial, _ := dialer(t, url)
	nc, err := dial(sa("app:worker"))
	if err != nil {
		t.Fatal(err)
	}
	nc.Close()
	trustedCA := os.Getenv("NATS_TLS_CA")
	otherCA, _ := testCertificate(t, t.TempDir())
	t.Setenv("NATS_TLS_CA", otherCA)
	if nc, err := dial(sa("app:worker")); err == nil {
		nc.Close()
		t.Fatal("untrusted server certificate accepted")
	}
	// Correct CA with an incompatible hostname must still fail verification.
	t.Setenv("NATS_TLS_CA", trustedCA)
	t.Setenv("NATS_TLS_SERVER_NAME", "wrong.example")
	if nc, err := dial(sa("app:worker")); err == nil {
		nc.Close()
		t.Fatal("wrong server hostname accepted")
	}
}

func TestGeneratedTLSConfig(t *testing.T) {
	cfg, err := serverConfig(operatorSecret, keys("test-master-secret-at-least-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	block, ok := cfg["tls"].(map[string]any)
	if !ok || block["cert_file"] == "" || block["key_file"] == "" || block["min_version"] != "1.2" {
		t.Fatalf("TLS config missing: %v", block)
	}
}

func TestTLSConfigInvalidCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NATS_TLS_CA", path)
	if _, err := natsTLS(); err == nil {
		t.Fatal("invalid CA accepted")
	}
}

func TestOldTLSClientDenied(t *testing.T) {
	s := &service{}
	req := &jwt.AuthorizationRequest{TLS: &jwt.ClientTLS{Version: "1.0"}, ConnectOptions: jwt.ConnectOptions{Token: "nonempty"}}
	_, _, _, err := s.decide(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("old TLS accepted: %v", err)
	}
	cfg, err := natsTLS()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify || cfg.MinVersion < tls.VersionTLS12 {
		t.Fatal("insecure client TLS config")
	}
}

func TestMigrationRejectsWrongAccount(t *testing.T) {
	if err := migrateAccount(context.Background(), nil, "app/worker", "invalid", "original-uid"); err == nil {
		t.Fatal("invalid expected account accepted")
	}
}

func TestWebsocketTransport(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "plaintext denied"
		if secure {
			name = "verified WSS allowed"
		}
		t.Run(name, func(t *testing.T) {
			admin := oidc.NewVerifier(adminIssuer, &oidc.StaticKeySet{}, &oidc.Config{ClientID: adminClient})
			ns, stop := bootServer(t, t.TempDir(), keys("test-master-secret-at-least-32-bytes"), fakeKube(t), admin, secure)
			defer stop()
			opts := []nats.Option{nats.Token(sa("app:worker")), nats.MaxReconnects(0)}
			if secure {
				cfg, err := natsTLS()
				if err != nil {
					t.Fatal(err)
				}
				opts = append(opts, nats.Secure(cfg))
			}
			nc, err := nats.Connect(ns.WebsocketURL(), opts...)
			if nc != nil {
				defer nc.Close()
			}
			if (err == nil) != secure {
				t.Fatalf("websocket secure=%v: %v", secure, err)
			}
		})
	}
}
