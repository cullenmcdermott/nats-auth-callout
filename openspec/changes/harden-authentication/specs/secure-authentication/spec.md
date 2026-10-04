# Spec Delta

## Purpose

Secure authentication for NATS workload and admin clients while bounding upstream work and preserving stored account data.

## ADDED Requirements

### Requirement: Audience-aware workload validation
The service SHALL require authenticated TokenReview responses containing the nats audience and a nonempty ServiceAccount UID.

#### Scenario: Missing or incompatible returned audience
- **WHEN** an authenticated response omits nats from returned audiences
- **THEN** the workload is denied

### Requirement: UID-bound account ownership
The service SHALL associate account mappings with verified ServiceAccount UIDs and SHALL deny missing or mismatched UID bindings without modifying stored account data.

#### Scenario: Recreated ServiceAccount
- **WHEN** a verified identity has the same namespace and name but a different UID
- **THEN** it cannot access the previous identity's account or data

#### Scenario: Legacy account mapping
- **WHEN** an account mapping contains only an account public key
- **THEN** login is denied until an administrator explicitly binds its verified owner UID

### Requirement: Encrypted transport
The service SHALL require verified TLS for its NATS connections, SHALL reject client authorization without TLS 1.2 or newer, and SHALL generate server TLS configuration.

#### Scenario: Plaintext connection
- **WHEN** a client or callout attempts a plaintext NATS connection
- **THEN** authentication fails closed

### Requirement: Bounded authentication work
The service SHALL limit concurrent upstream authentication work, rate-limit each source IP with bounded state, and reject stale signed requests before external authentication.

#### Scenario: One-source login flood
- **WHEN** one source exceeds its admission budget
- **THEN** excess requests are rejected without upstream work and another source remains eligible

#### Scenario: Expired request
- **WHEN** a signed authentication request has expired
- **THEN** no upstream authentication is performed
