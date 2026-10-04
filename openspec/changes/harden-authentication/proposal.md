# Proposal

## Why

Security review reproduced login starvation and data inheritance across ServiceAccount UIDs, and found missing audience checks and plaintext credential transport.

## What Changes

- Bound authentication concurrency and per-IP admission; validate signed request deadlines.
- Validate TokenReview audiences and bind stored accounts to verified ServiceAccount UIDs.
- **BREAKING**: require verified NATS TLS and reject non-TLS client authorization.
- **BREAKING**: deny legacy account mappings until explicitly associated with a verified UID; preserve data and identities.

## Capabilities

### New Capabilities

- `secure-authentication`: enforce identity, transport, and bounded authentication requirements.

### Modified Capabilities

None.

## Impact

Callout implementation, integration tests, generated server config, deployment documentation, and dependencies. Existing deployments need TLS certificates and account mapping migration before rollout. No production deployment or data deletion is performed.
