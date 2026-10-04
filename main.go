// Command nats-auth-callout is a NATS auth callout service.
//
// Pods connect with a projected ServiceAccount token (audience "nats") and are
// placed in a NATS account per namespace/serviceaccount, created on first use.
// Pocket ID tokens carrying the nats-admins group are placed in the system account.
//
//	nats-auth-callout init   print the server config and callout env (JSON)
//	nats-auth-callout        run the callout service
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/synadia-io/callout.go"
)

const (
	adminIssuer = "https://id.cullen.rocks"
	adminClient = "nats"
	adminGroup  = "nats-admins"
	audience    = "nats"
	saDir       = "/var/run/secrets/kubernetes.io/serviceaccount/"
	budget      = 1500 * time.Millisecond // per-request, under the server's 2s auth timeout
	bucket      = "accounts"              // KV in the AUTH account: namespace/serviceaccount -> account public key
	httpAddr    = ":8080"                 // /metrics and /healthz
)

// errDenied marks a rejected credential, as opposed to a failure on our side (result "error").
var errDenied = errors.New("denied")

var (
	decisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nats_auth_callout_decisions_total",
		Help: "Auth decisions by kind (workload, admin) and result (allow, deny, error).",
	}, []string{"kind", "result"})
	latency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nats_auth_callout_duration_seconds",
		Help:    "Time to decide an auth request, by kind.",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 1.5},
	}, []string{"kind"})
	created = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nats_auth_callout_accounts_created_total",
		Help: "Workload accounts created.",
	})
	failures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nats_auth_callout_errors_total",
		Help: "Requests the callout could not answer (bad request, full worker queue, failed reply). The client times out.",
	})
)

// keys derives nkeys from a secret so replicas agree and nothing is stored. There are two secrets:
//   - NATS_OPERATOR_SECRET: the identities of the operator, SYS and AUTH. Only `init` needs it, so it
//     stays in 1Password and never reaches the cluster.
//   - NATS_AUTH_MASTER: every signing key. Rotating it re-signs accounts but keeps their identities,
//     so no JetStream data is orphaned.
type keys []byte

func (k keys) derive(prefix nkeys.PrefixByte, label string) nkeys.KeyPair {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(label))
	r := bytes.NewReader(m.Sum(nil))
	var kp nkeys.KeyPair
	var err error
	if prefix == nkeys.PrefixByteCurve {
		kp, err = nkeys.CreateCurveKeysWithRand(r)
	} else {
		kp, err = nkeys.CreatePairWithRand(prefix, r)
	}
	if err != nil {
		panic(err) // only on a short read, impossible with a 32 byte digest
	}
	return kp
}

// Identities, from NATS_OPERATOR_SECRET.
func (k keys) operator() nkeys.KeyPair { return k.derive(nkeys.PrefixByteOperator, "operator") }
func (k keys) sys() nkeys.KeyPair      { return k.derive(nkeys.PrefixByteAccount, "sys") }
func (k keys) auth() nkeys.KeyPair     { return k.derive(nkeys.PrefixByteAccount, "auth") }

// Signing keys, from NATS_AUTH_MASTER.
func (k keys) operatorSigner() nkeys.KeyPair {
	return k.derive(nkeys.PrefixByteOperator, "operator-signing")
}
func (k keys) sysSigner() nkeys.KeyPair  { return k.derive(nkeys.PrefixByteAccount, "sys-signing") }
func (k keys) authSigner() nkeys.KeyPair { return k.derive(nkeys.PrefixByteAccount, "auth-signing") }
func (k keys) xkey() nkeys.KeyPair       { return k.derive(nkeys.PrefixByteCurve, "xkey") }
func (k keys) user(name string) nkeys.KeyPair {
	return k.derive(nkeys.PrefixByteUser, "user:"+name)
}
func (k keys) accountSigner(acct string) nkeys.KeyPair {
	return k.derive(nkeys.PrefixByteAccount, "account-signing:"+acct)
}

func pub(kp nkeys.KeyPair) string {
	p, err := kp.PublicKey()
	if err != nil {
		panic(err)
	}
	return p
}

// serverConfig returns the nats.conf fragment that trusts these keys. JSON is valid in both
// nats.conf and Helm values.
func serverConfig(o, m keys) (map[string]any, error) {
	op := o.operator()
	oc := jwt.NewOperatorClaims(pub(op))
	oc.Name = "homelab"
	oc.SystemAccount = pub(o.sys())
	oc.SigningKeys.Add(pub(m.operatorSigner()))
	opJWT, err := oc.Encode(op)
	if err != nil {
		return nil, err
	}

	sc := jwt.NewAccountClaims(pub(o.sys()))
	sc.Name = "SYS"
	sc.SigningKeys.Add(pub(m.sysSigner()))
	sysJWT, err := sc.Encode(m.operatorSigner())
	if err != nil {
		return nil, err
	}

	ac := jwt.NewAccountClaims(pub(o.auth()))
	ac.Name = "AUTH"
	ac.SigningKeys.Add(pub(m.authSigner()))
	ac.Authorization = jwt.ExternalAuthorization{
		AuthUsers:       jwt.StringList{pub(m.user("callout"))},
		AllowedAccounts: jwt.StringList{jwt.AnyAccount},
		XKey:            pub(m.xkey()),
	}
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{DiskStorage: 64 << 20, Streams: -1, Consumer: -1} // the accounts bucket
	authJWT, err := ac.Encode(m.operatorSigner())
	if err != nil {
		return nil, err
	}

	// Token-only clients present this bearer JWT, which lands them in AUTH and triggers the callout.
	uc := jwt.NewUserClaims(pub(m.user("sentinel")))
	uc.IssuerAccount = pub(o.auth())
	uc.BearerToken = true
	uc.Pub.Deny.Add(">")
	uc.Sub.Deny.Add(">")
	sentinel, err := uc.Encode(m.authSigner())
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"operator":         opJWT,
		"system_account":   pub(o.sys()),
		"resolver_preload": map[string]string{pub(o.sys()): sysJWT, pub(o.auth()): authJWT},
		"default_sentinel": sentinel,
	}, nil
}

type service struct {
	admin     *oidc.IDTokenVerifier
	kube      *http.Client
	kubeAPI   string
	kubeToken string           // path to our own SA token, re-read per request since kubelet rotates it
	replicas  int              // of the accounts bucket
	disk      map[string]int64 // JetStream disk bytes by account name (namespace/serviceaccount), overriding the 1 GiB default

	m                 keys
	sysAcct, authAcct string
	sys, nc           *nats.Conn
	kv                jetstream.KeyValue
	mu                sync.Mutex
	pushed            map[string]bool // account public keys pushed by this process
}

// authorize decides a request and records it: one log line and the metrics.
func (s *service) authorize(req *jwt.AuthorizationRequest) (string, error) {
	start := time.Now()
	kind, who, user, err := s.decide(req)
	result := "allow"
	if errors.Is(err, errDenied) {
		result = "deny"
	} else if err != nil {
		result = "error"
	}
	d := time.Since(start)
	decisions.WithLabelValues(kind, result).Inc()
	latency.WithLabelValues(kind).Observe(d.Seconds())
	level := map[string]slog.Level{"allow": slog.LevelInfo, "deny": slog.LevelWarn, "error": slog.LevelError}[result]
	attrs := []any{"kind", kind, "who", who, "result", result, "ms", d.Milliseconds(),
		"ip", req.ClientInformation.Host, "client", req.ClientInformation.Name, "server", req.Server.Name}
	if err != nil {
		attrs = append(attrs, "err", err.Error())
	}
	slog.Log(context.Background(), level, "auth", attrs...)
	return user, err
}

func (s *service) decide(req *jwt.AuthorizationRequest) (kind, who, user string, err error) {
	tok := req.ConnectOptions.Token
	if tok == "" {
		return "none", "", "", fmt.Errorf("%w: no token", errDenied)
	}
	// The server gives up on auth after 2s; stay under it so we never answer a dead request.
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	iss, exp := peek(tok)
	if iss == adminIssuer {
		who, user, err = s.authorizeAdmin(ctx, req.UserNkey, tok)
		return "admin", who, user, err
	}
	who, user, err = s.authorizeWorkload(ctx, req.UserNkey, tok, exp)
	return "workload", who, user, err
}

// peek reads iss and exp without verifying: iss only picks which verifier runs, and exp is
// only used after the API server has validated the token.
func peek(tok string) (iss string, exp int64) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", 0
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", 0
	}
	var c struct {
		Iss string
		Exp int64
	}
	_ = json.Unmarshal(b, &c)
	return c.Iss, c.Exp
}

func (s *service) authorizeAdmin(ctx context.Context, userNkey, tok string) (who, user string, err error) {
	idt, err := s.admin.Verify(ctx, tok)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", errDenied, err) // includes a failed JWKS fetch; the reason says which
	}
	var c struct {
		Groups []string `json:"groups"`
	}
	if err := idt.Claims(&c); err != nil {
		return idt.Subject, "", fmt.Errorf("%w: %w", errDenied, err)
	}
	if !slices.Contains(c.Groups, adminGroup) {
		return idt.Subject, "", fmt.Errorf("%w: not in %s", errDenied, adminGroup)
	}
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = idt.Subject
	uc.Expires = idt.Expiry.Unix()
	uc.IssuerAccount = s.sysAcct
	user, err = uc.Encode(s.m.sysSigner())
	return idt.Subject, user, err
}

func (s *service) authorizeWorkload(ctx context.Context, userNkey, tok string, exp int64) (who, user string, err error) {
	who, pod, groups, err := s.tokenReview(ctx, tok)
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(who, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return who, "", fmt.Errorf("%w: not a service account", errDenied)
	}
	if parts[3] == "default" {
		return who, "", fmt.Errorf("%w: give the workload its own ServiceAccount", errDenied)
	}
	if !slices.Contains(groups, "system:serviceaccounts:"+parts[2]) {
		return who, "", fmt.Errorf("%w: missing group for namespace %s", errDenied, parts[2])
	}
	if exp == 0 {
		return who, "", fmt.Errorf("%w: token has no exp", errDenied)
	}
	who = parts[2] + "/" + parts[3]
	if pod != "" {
		who += " pod " + pod
	}
	acct, err := s.account(ctx, parts[2]+"/"+parts[3])
	if err != nil {
		return who, "", err
	}
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = pod
	uc.Expires = exp // dropped at token expiry; clients reconnect with the rotated token
	uc.IssuerAccount = acct
	user, err = uc.Encode(s.m.accountSigner(acct))
	return who, user, err
}

// tokenReview asks the API server to validate a projected token. Unlike local JWKS checks this
// rejects tokens of deleted pods, and sidesteps the cluster's unreachable issuer URL.
func (s *service) tokenReview(ctx context.Context, tok string) (user, pod string, groups []string, err error) {
	self, err := os.ReadFile(s.kubeToken)
	if err != nil {
		return "", "", nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"spec":       map[string]any{"token": tok, "audiences": []string{audience}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.kubeAPI+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return "", "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(self)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.kube.Do(req)
	if err != nil {
		return "", "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("tokenreview: %s", resp.Status)
	}
	var out struct {
		Status struct {
			Authenticated bool
			Error         string
			User          struct {
				Username string
				Groups   []string
				Extra    map[string][]string
			}
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", nil, err
	}
	if !out.Status.Authenticated {
		return "", "", nil, fmt.Errorf("%w: tokenreview: %s", errDenied, out.Status.Error)
	}
	if p := out.Status.User.Extra["authentication.kubernetes.io/pod-name"]; len(p) > 0 {
		pod = p[0]
	}
	return out.Status.User.Username, pod, out.Status.User.Groups, nil
}

// account returns the account for name, creating it on first use. Its identity key is random and
// discarded at once: only the public key is kept, in a KV bucket on the same JetStream storage as
// the data it owns, so the two are lost together or not at all.
func (s *service) account(ctx context.Context, name string) (string, error) {
	e, err := s.kv.Get(ctx, name)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		kp, err := nkeys.CreateAccount()
		if err != nil {
			return "", err
		}
		acct := pub(kp)
		if _, err = s.kv.Create(ctx, name, []byte(acct)); err == nil {
			created.Inc()
			slog.Info("account created", "name", name, "account", acct)
			return acct, s.push(ctx, name, acct)
		} else if !errors.Is(err, jetstream.ErrKeyExists) {
			return "", fmt.Errorf("account %s: %w", name, err)
		}
		e, err = s.kv.Get(ctx, name) // the other replica created it first
	}
	if err != nil {
		return "", fmt.Errorf("account %s: %w", name, err)
	}
	acct := string(e.Value())
	return acct, s.push(ctx, name, acct)
}

// push sends the account JWT, signed with the current keys, to the resolver once per process.
// Pushing is idempotent, so the other replica re-pushing is harmless, and a restart after
// rotating NATS_AUTH_MASTER re-signs every account as it is next used.
func (s *service) push(ctx context.Context, name, acct string) error {
	s.mu.Lock()
	done := s.pushed[acct]
	s.mu.Unlock()
	if done {
		return nil
	}
	ac := jwt.NewAccountClaims(acct)
	ac.Name = name
	ac.SigningKeys.Add(pub(s.m.accountSigner(acct)))
	ac.Limits.Conn = 50
	ac.Limits.Subs = 1000
	ac.Limits.Payload = 1 << 20
	ac.Limits.LeafNodeConn = 0
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{DiskStorage: cmp.Or(s.disk[name], 1<<30), Streams: 10, Consumer: 100}
	token, err := ac.Encode(s.m.operatorSigner())
	if err != nil {
		return err
	}
	msg, err := s.sys.RequestWithContext(ctx, "$SYS.REQ.CLAIMS.UPDATE", []byte(token))
	if err != nil {
		return fmt.Errorf("push account %s: %w", name, err)
	}
	var r struct {
		Data  struct{ Code int }
		Error *struct{ Description string }
	}
	if err := json.Unmarshal(msg.Data, &r); err != nil {
		return err
	}
	if r.Error != nil || r.Data.Code != 200 {
		return fmt.Errorf("push account %s: %s", name, msg.Data)
	}
	s.mu.Lock()
	s.pushed[acct] = true
	s.mu.Unlock()
	slog.Info("account pushed", "name", name, "account", acct)
	return nil
}

// healthy reports whether both NATS connections are up. While either is reconnecting, logins fail.
func (s *service) healthy() bool { return s.sys.IsConnected() && s.nc.IsConnected() }

// logger quiets callout.go's own logging: decisions are logged by authorize, errors by ErrCallback.
type logger struct{}

func (logger) Noticef(f string, a ...any) { slog.Info(fmt.Sprintf(f, a...)) }
func (logger) Warnf(f string, a ...any)   { slog.Warn(fmt.Sprintf(f, a...)) }
func (logger) Fatalf(f string, a ...any)  { slog.Error(fmt.Sprintf(f, a...)); os.Exit(1) }
func (logger) Errorf(string, ...any)      {}
func (logger) Debugf(string, ...any)      {}
func (logger) Tracef(string, ...any)      {}

// connect logs in as a user minted on the fly with an account signing key.
func connect(url, name, acct string, signer, user nkeys.KeyPair) (*nats.Conn, error) {
	uc := jwt.NewUserClaims(pub(user))
	uc.Name = name
	uc.IssuerAccount = acct
	token, err := uc.Encode(signer)
	if err != nil {
		return nil, err
	}
	return nats.Connect(url, nats.Name(name), nats.MaxReconnects(-1),
		nats.UserJWT(func() (string, error) { return token, nil }, user.Sign))
}

// start connects s to NATS and serves auth requests until the returned stop is called.
func start(url string, s *service) (func(), error) {
	sys, err := connect(url, "nats-auth-callout-sys", s.sysAcct, s.m.sysSigner(), s.m.user("sys"))
	if err != nil {
		return nil, fmt.Errorf("sys connect: %w", err)
	}
	nc, err := connect(url, "nats-auth-callout", s.authAcct, s.m.authSigner(), s.m.user("callout"))
	if err != nil {
		sys.Close()
		return nil, fmt.Errorf("callout connect: %w", err)
	}
	stop := func() { nc.Close(); sys.Close() }
	js, err := jetstream.New(nc)
	if err != nil {
		stop()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.kv, err = js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket, Replicas: s.replicas})
	if err != nil {
		stop()
		return nil, fmt.Errorf("accounts bucket: %w", err)
	}
	s.sys, s.nc, s.pushed = sys, nc, map[string]bool{}
	svc, err := callout.NewAuthorizationService(nc,
		callout.Authorizer(s.authorize),
		callout.AsyncWorkers(8), // else one slow request stalls every login; a full queue drops (fails closed)
		callout.ResponseSignerKey(s.m.authSigner()),
		callout.ResponseSignerIssuer(s.authAcct),
		callout.EncryptionKey(s.m.xkey()),
		callout.Logger(logger{}),
		callout.ErrCallback(func(err error) {
			if !errors.Is(err, callout.ErrRejectedAuth) { // rejections were logged by authorize
				failures.Inc()
				slog.Error("callout", "err", err.Error())
			}
		}),
	)
	if err != nil {
		stop()
		return nil, err
	}
	return func() { _ = svc.Stop(); stop() }, nil
}

// diskLimits parses NATS_ACCOUNT_DISK: "namespace/serviceaccount=bytes", comma-separated.
func diskLimits(v string) (map[string]int64, error) {
	m := map[string]int64{}
	for _, kv := range strings.Split(v, ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		name, n, ok := strings.Cut(kv, "=")
		b, err := strconv.ParseInt(n, 10, 64)
		if !ok || err != nil || b <= 0 || !strings.Contains(name, "/") {
			return nil, fmt.Errorf("NATS_ACCOUNT_DISK: bad entry %q, want namespace/serviceaccount=bytes", kv)
		}
		m[name] = b
	}
	return m, nil
}

func secret(name string) keys {
	v := os.Getenv(name)
	if len(v) < 32 {
		log.Fatalf("%s (at least 32 bytes) is required", name)
	}
	return keys(v)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil))) // also catches the log package
	m := secret("NATS_AUTH_MASTER")

	if len(os.Args) > 1 && os.Args[1] == "init" {
		o := secret("NATS_OPERATOR_SECRET")
		cfg, err := serverConfig(o, m)
		if err != nil {
			log.Fatal(err)
		}
		out, _ := json.MarshalIndent(map[string]any{
			"config": cfg,
			"env":    map[string]string{"NATS_SYS_ACCOUNT": pub(o.sys()), "NATS_AUTH_ACCOUNT": pub(o.auth())},
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	sysAcct, authAcct := os.Getenv("NATS_SYS_ACCOUNT"), os.Getenv("NATS_AUTH_ACCOUNT")
	if sysAcct == "" || authAcct == "" {
		log.Fatal("NATS_SYS_ACCOUNT and NATS_AUTH_ACCOUNT are required (from `init`)")
	}

	ca, err := os.ReadFile(saDir + "ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	kube := &http.Client{Timeout: budget, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	ctx := oidc.ClientContext(context.Background(), &http.Client{Timeout: budget})
	// Remote key set rather than discovery, so Pocket ID being down only blocks admin logins, not startup.
	admin := oidc.NewVerifier(adminIssuer, oidc.NewRemoteKeySet(ctx, adminIssuer+"/.well-known/jwks.json"), &oidc.Config{ClientID: adminClient})

	disk, err := diskLimits(os.Getenv("NATS_ACCOUNT_DISK"))
	if err != nil {
		log.Fatal(err)
	}

	url := os.Getenv("NATS_URL")
	if url == "" {
		url = "nats://nats.nats:4222"
	}
	s := &service{
		admin: admin, kube: kube, kubeAPI: "https://kubernetes.default.svc", kubeToken: saDir + "token", replicas: 3, disk: disk,
		m: m, sysAcct: sysAcct, authAcct: authAcct,
	}
	stop, err := start(url, s)
	if err != nil {
		log.Fatal(err)
	}
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "nats_auth_callout_up",
		Help: "1 while both NATS connections are up.",
	}, func() float64 {
		if s.healthy() {
			return 1
		}
		return 0
	})
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.healthy() {
			http.Error(w, "nats disconnected", http.StatusServiceUnavailable)
		}
	})
	go func() { log.Fatal(http.ListenAndServe(httpAddr, nil)) }()
	slog.Info("authorizing", "url", url, "http", httpAddr)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	stop()
}
