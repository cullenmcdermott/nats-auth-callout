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
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
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
	kubeToken string // path to our own SA token, re-read per request since kubelet rotates it
	replicas  int    // of the accounts bucket

	m                 keys
	sysAcct, authAcct string
	sys               *nats.Conn
	kv                jetstream.KeyValue
	mu                sync.Mutex
	pushed            map[string]bool // account public keys pushed by this process
}

func (s *service) authorize(req *jwt.AuthorizationRequest) (string, error) {
	tok := req.ConnectOptions.Token
	if tok == "" {
		return "", errors.New("no token")
	}
	// The server gives up on auth after 2s; stay under it so we never answer a dead request.
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	iss, exp := peek(tok)
	if iss == adminIssuer {
		return s.authorizeAdmin(ctx, req.UserNkey, tok)
	}
	return s.authorizeWorkload(ctx, req.UserNkey, tok, exp)
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

func (s *service) authorizeAdmin(ctx context.Context, userNkey, tok string) (string, error) {
	idt, err := s.admin.Verify(ctx, tok)
	if err != nil {
		return "", err
	}
	var c struct {
		Groups []string `json:"groups"`
	}
	if err := idt.Claims(&c); err != nil {
		return "", err
	}
	if !slices.Contains(c.Groups, adminGroup) {
		return "", fmt.Errorf("%s: not in %s", idt.Subject, adminGroup)
	}
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = idt.Subject
	uc.Expires = idt.Expiry.Unix()
	uc.IssuerAccount = s.sysAcct
	return uc.Encode(s.m.sysSigner())
}

func (s *service) authorizeWorkload(ctx context.Context, userNkey, tok string, exp int64) (string, error) {
	user, pod, groups, err := s.tokenReview(ctx, tok)
	if err != nil {
		return "", err
	}
	parts := strings.Split(user, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return "", fmt.Errorf("%s: not a service account", user)
	}
	if parts[3] == "default" {
		return "", fmt.Errorf("%s: give the workload its own ServiceAccount", user)
	}
	if !slices.Contains(groups, "system:serviceaccounts:"+parts[2]) {
		return "", fmt.Errorf("%s: missing group for namespace %s", user, parts[2])
	}
	if exp == 0 {
		return "", fmt.Errorf("%s: token has no exp", user)
	}
	acct, err := s.account(ctx, parts[2]+"/"+parts[3])
	if err != nil {
		return "", err
	}
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = pod
	uc.Expires = exp // dropped at token expiry; clients reconnect with the rotated token
	uc.IssuerAccount = acct
	return uc.Encode(s.m.accountSigner(acct))
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
		return "", "", nil, fmt.Errorf("tokenreview: not authenticated: %s", out.Status.Error)
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
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{DiskStorage: 1 << 30, Streams: 10, Consumer: 100}
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
	return nil
}

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
	s.sys, s.pushed = sys, map[string]bool{}
	svc, err := callout.NewAuthorizationService(nc,
		callout.Authorizer(s.authorize),
		callout.AsyncWorkers(8), // else one slow request stalls every login; a full queue drops (fails closed)
		callout.ResponseSignerKey(s.m.authSigner()),
		callout.ResponseSignerIssuer(s.authAcct),
		callout.EncryptionKey(s.m.xkey()),
		callout.ErrCallback(func(err error) { log.Printf("rejected: %v", err) }),
	)
	if err != nil {
		stop()
		return nil, err
	}
	return func() { _ = svc.Stop(); stop() }, nil
}

func secret(name string) keys {
	v := os.Getenv(name)
	if len(v) < 32 {
		log.Fatalf("%s (at least 32 bytes) is required", name)
	}
	return keys(v)
}

func main() {
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

	url := os.Getenv("NATS_URL")
	if url == "" {
		url = "nats://nats.nats:4222"
	}
	stop, err := start(url, &service{
		admin: admin, kube: kube, kubeAPI: "https://kubernetes.default.svc", kubeToken: saDir + "token", replicas: 3,
		m: m, sysAcct: sysAcct, authAcct: authAcct,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("authorizing on %s", url)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	stop()
}
