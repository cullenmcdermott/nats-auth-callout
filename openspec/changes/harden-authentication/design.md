# Design

## Context

See proposal.md for motivation. The callout library fixes its queue at 5,000 requests and omits deadline validation. TokenReview exposes verified audience and identity fields. The deployment manifests live in the separate homelab repository.

## Goals / Non-Goals

Goals: fail closed at trust boundaries; keep existing JetStream data intact; bound upstream work.
Non-goals: production rollout, account deletion, transparent adoption of unverified legacy mappings.

## Decisions

- Use a native NATS queue subscription, existing JWT/nkeys libraries, nonblocking eight-request admission, signed request expiry, and bounded per-IP token buckets. This avoids patching or vendoring a library with an unconfigurable queue.
- Store JSON `{account, uid}` at the existing namespace/serviceaccount key. Reject missing or mismatched UIDs instead of overwriting account identities or automatically adopting old mappings. An explicit migrate command establishes AUTH maintenance access, validates the expected legacy public key, and uses revision-checked updates without printing credentials.
- Require returned `nats` audience and a verified ServiceAccount UID.
- Require TLS 1.2 or newer for NATS connections and client authorization. Configure certificate trust explicitly; never disable certificate verification.

## Risks / Trade-offs

- Existing raw-key mappings → document explicit, verified UID association before rollout.
- Many clients behind one IP → document admission limits and enforce rate limiting at the edge too.
- Sustained distributed attacks → concurrency remains bounded, but edge controls are still needed.
- Certificates must be mounted and backend websocket TLS configured → provide deployment changes and verification guidance; do not claim production is secured without rollout.

## Migration Plan

Build and pin the new image; back up mappings and verify their owners; verify maintenance access. Stop old callout readers, provision and verify TLS, use the new binary migrate command to bind verified UIDs with revision checks, then start only upgraded replicas. Old readers cannot read JSON mappings and the old image cannot apply the new hostname override. Preserve backups and NATS storage throughout; rollback restores raw mappings with readers stopped. No automatic cleanup.
