// Command nats-auth-callout is a NATS auth callout service.
//
// Pods connect with a projected ServiceAccount token (audience "nats") and are
// placed in a NATS account per namespace/serviceaccount, created on first use.
// Omni OIDC tokens carrying system:masters for the prod cluster are placed in
// the system account.
//
//	nats-auth-callout init   print the server config (JSON) derived from NATS_AUTH_MASTER
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
	"github.com/nats-io/nkeys"
	"github.com/synadia-io/callout.go"
)

const (
	omniIssuer  = "https://omni.cullen.rocks/oidc"
	omniClient  = "native"
	omniCluster = "prod"
	adminGroup  = "system:masters"
	audience    = "nats"
	saDir       = "/var/run/secrets/kubernetes.io/serviceaccount/"
	budget      = 1500 * time.Millisecond // per-request, under the server's 2s auth timeout
)

// keys derives every nkey from one master secret so replicas agree and nothing is stored.
// ponytail: one secret is the whole trust root; rotating it re-keys every account and orphans
// their JetStream data. Split out an operator signing key if rotation ever matters.
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

func (k keys) operator() nkeys.KeyPair { return k.derive(nkeys.PrefixByteOperator, "operator") }
func (k keys) sys() nkeys.KeyPair      { return k.derive(nkeys.PrefixByteAccount, "sys") }
func (k keys) auth() nkeys.KeyPair     { return k.derive(nkeys.PrefixByteAccount, "auth") }
func (k keys) xkey() nkeys.KeyPair     { return k.derive(nkeys.PrefixByteCurve, "xkey") }
func (k keys) user(name string) nkeys.KeyPair {
	return k.derive(nkeys.PrefixByteUser, "user:"+name)
}
func (k keys) account(name string) nkeys.KeyPair {
	return k.derive(nkeys.PrefixByteAccount, "account:"+name)
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
func serverConfig(k keys) (map[string]any, error) {
	op := k.operator()
	oc := jwt.NewOperatorClaims(pub(op))
	oc.Name = "homelab"
	oc.SystemAccount = pub(k.sys())
	opJWT, err := oc.Encode(op)
	if err != nil {
		return nil, err
	}

	sc := jwt.NewAccountClaims(pub(k.sys()))
	sc.Name = "SYS"
	sysJWT, err := sc.Encode(op)
	if err != nil {
		return nil, err
	}

	ac := jwt.NewAccountClaims(pub(k.auth()))
	ac.Name = "AUTH"
	ac.Authorization = jwt.ExternalAuthorization{
		AuthUsers:       jwt.StringList{pub(k.user("callout"))},
		AllowedAccounts: jwt.StringList{jwt.AnyAccount},
		XKey:            pub(k.xkey()),
	}
	authJWT, err := ac.Encode(op)
	if err != nil {
		return nil, err
	}

	// Token-only clients present this bearer JWT, which lands them in AUTH and triggers the callout.
	uc := jwt.NewUserClaims(pub(k.user("sentinel")))
	uc.BearerToken = true
	uc.Pub.Deny.Add(">")
	uc.Sub.Deny.Add(">")
	sentinel, err := uc.Encode(k.auth())
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"operator":         opJWT,
		"system_account":   pub(k.sys()),
		"resolver_preload": map[string]string{pub(k.sys()): sysJWT, pub(k.auth()): authJWT},
		"default_sentinel": sentinel,
	}, nil
}

type service struct {
	admin     *oidc.IDTokenVerifier
	kube      *http.Client
	kubeAPI   string
	kubeToken string // path to our own SA token, re-read per request since kubelet rotates it

	k      keys
	sys    *nats.Conn
	mu     sync.Mutex
	pushed map[string]bool
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
	if iss == omniIssuer {
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
		Cluster string   `json:"cluster"`
		Groups  []string `json:"groups"`
	}
	if err := idt.Claims(&c); err != nil {
		return "", err
	}
	if c.Cluster != omniCluster || !slices.Contains(c.Groups, adminGroup) {
		return "", fmt.Errorf("%s: not %s on %s", idt.Subject, adminGroup, omniCluster)
	}
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = idt.Subject
	uc.Expires = idt.Expiry.Unix()
	return uc.Encode(s.k.sys())
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
	name := parts[2] + "/" + parts[3]
	akp := s.k.account(name)
	if err := s.ensureAccount(name, akp); err != nil {
		return "", err
	}
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = pod
	uc.Expires = exp // dropped at token expiry; clients reconnect with the rotated token
	return uc.Encode(akp)
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

// ensureAccount pushes the account JWT to the resolver once per process. Pushing is
// idempotent, so a restart or the other replica re-pushing is harmless.
func (s *service) ensureAccount(name string, akp nkeys.KeyPair) error {
	s.mu.Lock()
	done := s.pushed[name]
	s.mu.Unlock()
	if done {
		return nil
	}
	ac := jwt.NewAccountClaims(pub(akp))
	ac.Name = name
	ac.Limits.Conn = 50
	ac.Limits.Subs = 1000
	ac.Limits.Payload = 1 << 20
	ac.Limits.LeafNodeConn = 0
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{DiskStorage: 1 << 30, Streams: 10, Consumer: 100}
	token, err := ac.Encode(s.k.operator())
	if err != nil {
		return err
	}
	msg, err := s.sys.Request("$SYS.REQ.CLAIMS.UPDATE", []byte(token), 2*time.Second)
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
	s.pushed[name] = true
	s.mu.Unlock()
	return nil
}

// connect logs in as a user minted on the fly from an account key.
func connect(url, name string, acct, user nkeys.KeyPair) (*nats.Conn, error) {
	uc := jwt.NewUserClaims(pub(user))
	uc.Name = name
	token, err := uc.Encode(acct)
	if err != nil {
		return nil, err
	}
	return nats.Connect(url, nats.Name(name), nats.MaxReconnects(-1),
		nats.UserJWT(func() (string, error) { return token, nil }, user.Sign))
}

// start connects s to NATS and serves auth requests until the returned stop is called.
func start(k keys, url string, s *service) (func(), error) {
	sys, err := connect(url, "nats-auth-callout-sys", k.sys(), k.user("sys"))
	if err != nil {
		return nil, fmt.Errorf("sys connect: %w", err)
	}
	nc, err := connect(url, "nats-auth-callout", k.auth(), k.user("callout"))
	if err != nil {
		sys.Close()
		return nil, fmt.Errorf("callout connect: %w", err)
	}
	s.k, s.sys, s.pushed = k, sys, map[string]bool{}
	svc, err := callout.NewAuthorizationService(nc,
		callout.Authorizer(s.authorize),
		callout.AsyncWorkers(8), // else one slow request stalls every login; a full queue drops (fails closed)
		callout.ResponseSignerKey(k.auth()),
		callout.EncryptionKey(k.xkey()),
		callout.ErrCallback(func(err error) { log.Printf("rejected: %v", err) }),
	)
	if err != nil {
		nc.Close()
		sys.Close()
		return nil, err
	}
	return func() { _ = svc.Stop(); nc.Close(); sys.Close() }, nil
}

func main() {
	master := os.Getenv("NATS_AUTH_MASTER")
	if len(master) < 32 {
		log.Fatal("NATS_AUTH_MASTER (at least 32 bytes) is required")
	}
	k := keys(master)

	if len(os.Args) > 1 && os.Args[1] == "init" {
		cfg, err := serverConfig(k)
		if err != nil {
			log.Fatal(err)
		}
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))
		return
	}

	ca, err := os.ReadFile(saDir + "ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	kube := &http.Client{Timeout: budget, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	ctx := oidc.ClientContext(context.Background(), &http.Client{Timeout: budget})
	// Remote key set rather than discovery, so Omni being down only blocks admin logins, not startup.
	admin := oidc.NewVerifier(omniIssuer, oidc.NewRemoteKeySet(ctx, omniIssuer+"/keys"), &oidc.Config{ClientID: omniClient})

	url := os.Getenv("NATS_URL")
	if url == "" {
		url = "nats://nats.nats:4222"
	}
	stop, err := start(k, url, &service{admin: admin, kube: kube, kubeAPI: "https://kubernetes.default.svc", kubeToken: saDir + "token"})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("authorizing on %s", url)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	stop()
}
