# Tasks

## 1. Trust boundaries

- [x] 1.1 Add audience and UID regression tests, observe failure, implement rejection, and run the tests.
- [x] 1.2 Add account ownership and legacy-mapping regression tests, observe failure, preserve stored keys, and run tests.
- [x] 1.3 Add TLS rejection and verified-connection tests, observe failure, implement TLS enforcement, and run tests.

## 2. Bounded requests

- [x] 2.1 Implement bounded dispatch, per-IP admission, signed request validation, and deadlines with failing-then-passing tests.
- [x] 2.2 Integrate the handler and verify real NATS auth, isolation, token expiry, and signing-key rotation with race tests.

## 3. Deployment and verification

- [x] 3.1 Document UID migration and TLS deployment requirements and prepare validated backend TLS manifests.
- [x] 3.2 Run formatting, go vet, race tests, govulncheck, OpenSpec validation, and final simplicity/security review.
