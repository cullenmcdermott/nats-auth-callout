# nats-auth-callout

NATS auth callout for the homelab cluster. Pods authenticate with a projected
ServiceAccount token; admins authenticate with a Pocket ID token. Keys are derived from two
secrets, and the only state is a KV bucket mapping each ServiceAccount to its account and verified Kubernetes UID.

```mermaid
sequenceDiagram
    participant C as Client (pod or admin)
    participant N as NATS server
    participant A as nats-auth-callout
    participant K as kube-apiserver
    participant P as Pocket ID keys

    C->>N: CONNECT token=<JWT>
    N->>A: auth request (AUTH account, encrypted)
    alt iss == id.cullen.rocks
        A->>P: verify signature (JWKS)
        A-->>N: user JWT in SYS, expires with the token<br/>(needs group nats-admins)
    else projected SA token (aud=nats)
        A->>K: TokenReview
        K-->>A: system:serviceaccount:<ns>:<sa>
        A->>N: KV accounts: check UID, look up or create <ns>/<sa>
        A->>N: $SYS.REQ.CLAIMS.UPDATE (account JWT, once per process)
        A-->>N: user JWT in account <ns>/<sa>
    end
    N-->>C: connected
```

- Each `namespace/serviceaccount` gets its own NATS account, created on first connect and
  pushed to the server's full resolver. The `default` ServiceAccount is rejected. TokenReview must return the `nats` audience and a nonempty UID. A recreated ServiceAccount with a different UID is denied access to the old account.
- An account's identity key is random and discarded at once. Its public key and owning ServiceAccount UID are kept in the
  `accounts` KV bucket in the AUTH account, on the same JetStream storage as the data it owns.
  If NATS data is lost, both go together and workloads get fresh, empty accounts.

## Keys

| Secret | Derives | Where it lives |
|---|---|---|
| `NATS_OPERATOR_SECRET` | identities of the operator, SYS and AUTH | 1Password `nats-auth-callout operator` (vault Private), used only by `init`; never in the cluster |
| `NATS_AUTH_MASTER` | every signing key, the xkey, the callout's own users | 1Password `nats-auth-callout` (vault k8s-secrets) → ExternalSecret |

Users are signed with account signing keys and accounts with the operator signing key, so rotating
`NATS_AUTH_MASTER` re-signs everything but changes no identity: JetStream data is kept.
- Per-account caps: 50 connections, 1000 subscriptions, 1 MiB payload, no leafnodes,
  JetStream 1 GiB disk / 10 streams / 100 consumers. NATS has no msgs/sec throttle; these are caps.
  Raise the disk cap per account with `NATS_ACCOUNT_DISK=namespace/serviceaccount=bytes,...`;
  it counts every replica, so an R3 stream of N bytes needs 3N.

## Bootstrap

```bash
# 1. the two secrets
op item create --vault Private --category password --title 'nats-auth-callout operator' \
  --generate-password='letters,digits,64'
op item create --vault k8s-secrets --category login --title nats-auth-callout \
  --generate-password='letters,digits,64'

# 2. print the server config and the callout's env
NATS_OPERATOR_SECRET="$(op read 'op://Private/nats-auth-callout operator/password')" \
NATS_AUTH_MASTER="$(op read op://k8s-secrets/nats-auth-callout/password)" \
  go run . init
```

3. In the homelab repo, merge `.config` into `k8s/nats/values.yaml` under `config.merge`, and set
   `.env` (`NATS_SYS_ACCOUNT`, `NATS_AUTH_ACCOUNT`, both public keys) on the callout Deployment.
4. In Pocket ID, create a public OIDC client with client ID `nats` and device code enabled, and a
   `nats-admins` group with your user in it.

The service reads `NATS_AUTH_MASTER`, `NATS_SYS_ACCOUNT`, `NATS_AUTH_ACCOUNT` (all required) and
`NATS_URL` (default `tls://nats.nats:4222`). TLS 1.2 or newer and server certificate verification are required, including when the URL uses `nats://`.

Set `NATS_TLS_CA` to a mounted PEM CA file for private certificates; otherwise the system trust store is used. Set `NATS_TLS_SERVER_NAME` when the certificate DNS name differs from the connection hostname, for example `nats.cullen.rocks` when connecting through `nats.nats`. Invalid CA files fail startup. Client authorization also requires a TLS 1.2 or newer connection to the NATS server.

### TLS deployment

The generated config expects `tls.crt` and `tls.key` at `/etc/nats-certs/nats/`. Mount the certificate before enabling this config. With the NATS Helm chart, enable `config.nats.tls` using your certificate Secret and require `min_version: "1.2"`.

Websocket TLS needs its own configuration: enable `config.websocket.tls`, then configure Traefik to use HTTPS to the backend and verify its certificate. For a certificate for `nats.cullen.rocks`, use a `ServersTransport` with `serverName: nats.cullen.rocks` and `insecureSkipVerify: false`. Keep the public ingress on WSS. Enabling TLS only at Traefik leaves the internal leg exposed. See [NATS TLS documentation](https://docs.nats.io/learn/security/encryption) and [Traefik backend annotations](https://doc.traefik.io/traefik/reference/routing-configuration/kubernetes/ingress/).

### Migrating existing account mappings

This version requires a coordinated maintenance rollout. Build and pin the new image before applying the TLS changes: the old image does not implement `NATS_TLS_SERVER_NAME`. Update workload clients to verify the configured certificate identity too.

Back up the `accounts` KV bucket and confirm access to `NATS_AUTH_MASTER` and the public account settings. A SYS login cannot access AUTH's KV bucket. The new binary's `migrate` command uses the existing callout identity to establish a verified TLS maintenance connection without printing credentials; it requires no Kubernetes API access.

For each mapping, verify which workload owns its data and obtain the intended ServiceAccount UID (`kubectl get serviceaccount NAME -n NAMESPACE -o jsonpath='{.metadata.uid}'`). Stop all old callout replicas before changing KV values: old readers cannot read the new format. Keep NATS and its storage running.

With the new binary, the existing callout environment, and TLS enabled and verified, run:

```bash
nats-auth-callout migrate NAMESPACE/SERVICEACCOUNT EXISTING_ACCOUNT_PUBLIC_KEY VERIFIED_SERVICEACCOUNT_UID
```

The command requires the existing value to match the supplied account public key and performs a revision-checked update to:

```json
{"account":"<existing account public key>","uid":"<verified ServiceAccount UID>"}
```

The account key and JetStream data are preserved. It never creates a missing mapping or rebinds an account to a different UID; repeating an identical migration is safe. If a name has been recreated or ownership is uncertain, halt migration for that entry and leave it denied. Explicitly provision a fresh account only after resolving ownership; never bind old data to an unverified replacement UID.

Start only upgraded callout replicas after migration. Verify login, account isolation, and existing stream data before cleanup. For rollback to the old binary, stop new readers and restore the backed-up raw-key mappings before starting old readers. If verified ownership, maintenance credentials, or a new image digest are unavailable, stop the rollout.

### Rotating `NATS_AUTH_MASTER`

Generate a new password in the `nats-auth-callout` item, rerun `init`, and roll out the new
`.config` (bump the pod annotation in `values.yaml`, since the operator can't be hot-reloaded)
together with the callout. Logins fail until both are on the new keys. Existing connections drop
and reconnect. Each account is re-signed the first time it is used after the restart.

## Develop and build

`flox activate` provides Go, ko and the nats CLI. Then `go test -race ./...`.

Depot CI (`.depot/workflows/ci.yml`) tests every push and PR. Pushes to main and `v*` tags also
build `ghcr.io/cullenmcdermott/nats-auth-callout` (amd64 + arm64) with ko and sign it with cosign.
Pin the digest in the Deployment. The image runs as nonroot (uid 65532, distroless static base)
and needs no writable filesystem. Verify a signature with
`cosign verify --key cosign.pub ghcr.io/cullenmcdermott/nats-auth-callout@sha256:<digest>`.

Depot CI secrets (in Depot, not GitHub): `GHCR_TOKEN` (org-wide) and repo-scoped `COSIGN_PRIVATE_KEY` and
`COSIGN_PASSWORD`, also kept in the 1Password item `nats-auth-callout cosign` (vault Private).

To build locally without pushing:

```bash
KO_DOCKER_REPO=ghcr.io/cullenmcdermott/nats-auth-callout ko build --bare --push=false .
```

## Workload usage

Give the workload its own ServiceAccount, then project a token with audience `nats`:

```yaml
spec:
  serviceAccountName: my-app   # not "default"
  containers:
    - name: app
      volumeMounts:
        - { name: nats-token, mountPath: /var/run/secrets/nats, readOnly: true }
  volumes:
    - name: nats-token
      projected:
        sources:
          - serviceAccountToken:
              audience: nats
              path: token
              expirationSeconds: 3600
```

The connection is dropped when the token expires. Re-read the file on every (re)connect so the
client reconnects transparently with the rotated token:

```go
// Uses the system CA pool and verifies the public certificate identity.
nc, err := nats.Connect("tls://nats.nats:4222",
    nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: "nats.cullen.rocks"}),
    nats.MaxReconnects(-1),
    nats.TokenHandler(func() string {
        b, _ := os.ReadFile("/var/run/secrets/nats/token")
        return strings.TrimSpace(string(b))
    }))
```

## Admin usage

```bash
TOKEN=$(kubectl oidc-login get-token --grant-type=device-code \
  --oidc-issuer-url=https://id.cullen.rocks --oidc-client-id=nats \
  --oidc-extra-scope=groups | jq -r .status.token)
nats --server wss://nats.cullen.rocks --token "$TOKEN" server list
```

Requires the `nats-admins` group. You land in the SYS account and the session expires with the
token. The token is only valid for NATS (`aud=nats`), not for anything else Pocket ID protects.

## Observability

Logs are JSON on stderr, one `auth` line per decision:

```json
{"level":"WARN","msg":"auth","kind":"workload","who":"system:serviceaccount:app:default","result":"deny","ms":4,"ip":"10.244.1.7","client":"","server":"nats-1","err":"denied: give the workload its own ServiceAccount"}
```

`result` is `allow`, `deny` (bad credential: client's problem) or `error` (TokenReview, KV or
account push failed: ours). Account creation and pushes are logged too. Port 8080 serves:

| Path | |
|---|---|
| `/healthz` | 503 while either NATS connection is down (liveness probe) |
| `/metrics` | `nats_auth_callout_decisions_total{kind,result}`, `nats_auth_callout_duration_seconds{kind}`, `nats_auth_callout_accounts_created_total`, `nats_auth_callout_errors_total` (malformed requests, admission rejections, failed replies), `nats_auth_callout_up`, plus Go runtime |

## Known ceilings

- `NATS_AUTH_MASTER` can sign for any account until it is rotated. Rotation is a short outage,
  not a seamless handover (the operator lists only one signing key at a time).
- Losing `NATS_OPERATOR_SECRET` means rebuilding the trust root, which orphans all JetStream data.
- A deleted pod stays connected until its token expires (at most `expirationSeconds`).
- Cross-account sharing (exports/imports) is not implemented.
- Authentication has eight concurrent slots and no worker waiting queue. Each source IP gets
  five attempts per second with a burst of ten; at most 4096 IPs are tracked. Signed request
  expiry and the 1.5s budget bound upstream work. Overload is denied promptly. Clients sharing
  a proxy or NAT share its budget; distributed floods still require edge rate limits.
- Unknown `kid`s can still cause JWKS refetches within those admission limits.
- Accounts are never garbage-collected, and any ServiceAccount in any namespace gets one (no
  namespace allowlist; fine for a single-owner cluster).
- The JetStream per-account disk limit is soft in clustered mode.
- If the resolver data is wiped but JetStream's isn't, the callout re-pushes accounts only after it
  restarts.
