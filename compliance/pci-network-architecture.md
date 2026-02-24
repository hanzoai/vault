# PCI DSS Scope Containment -- Network Architecture

**Document:** Hanzo Vault PCI Network Segmentation and Scope Reduction
**Version:** 1.0
**Date:** 2026-02-23
**Classification:** Internal -- PCI Compliance
**Applicable Standard:** PCI DSS v4.0 (Requirements 1, 2, 3, 4, 7, 8, 10, 11, 12)
**Repository:** github.com/hanzoai/vault

---

## Table of Contents

1. [Three-Zone Network Architecture](#1-three-zone-network-architecture)
2. [Trust Boundaries](#2-trust-boundaries)
3. [mTLS + SPIFFE/SPIRE Identity](#3-mtls--spiffespire-identity)
4. [Kubernetes Network Policies](#4-kubernetes-network-policies)
5. [Data Flow for Card Payment](#5-data-flow-for-card-payment)
6. [Audit and Compliance Controls](#6-audit-and-compliance-controls)
7. [HSM Integration Architecture](#7-hsm-integration-architecture)

---

## 1. Three-Zone Network Architecture

The architecture isolates cardholder data into the smallest possible blast radius.
Only Zone 3 (Vault CDE) is in full PCI DSS scope. Zone 2 has minimal exposure.
Zone 1 never sees raw PAN and is entirely out of PCI scope.

### Zone 1: Public API (OUT of PCI scope)

| Property | Value |
|----------|-------|
| **K8s Namespace** | `hanzo` |
| **Network** | Public subnet behind WAF + CDN |
| **Services** | commerce-api, checkout-page, customer-portal, webhooks |
| **Data Exposure** | `tok_*` tokens, brand, last4, expMonth/expYear only |
| **PAN Access** | NEVER -- all card data is pre-tokenized |

Services in this zone accept customer-facing traffic. They receive and transmit
only vault tokens (`tok_` prefixed, 52-character hex). The Commerce API passes
tokens to Zone 2 for payment processing. No raw PAN or ciphertext ever enters
this zone.

**Scope justification:** Zone 1 services handle only non-sensitive card metadata
(brand, last4, expiry) and opaque tokens. Per PCI DSS v4.0 Section 3.4, tokens
that cannot be reversed to recover PAN are not considered cardholder data.

### Zone 2: Payments Core (minimal PCI exposure)

| Property | Value |
|----------|-------|
| **K8s Namespace** | `hanzo-payments` |
| **Network** | Private subnet, reachable only from Zone 1 via internal LB |
| **Services** | payment-intents, routing-engine, disputes, refunds |
| **Data Exposure** | `tok_*` tokens, payment state machines, processor references |
| **PAN Access** | NEVER directly -- requests Vault to produce processor tokens |

Payments Core orchestrates payment lifecycle (create intent, route, capture,
refund, dispute) without ever handling raw PAN. When a processor requires a
network token or PAN, Payments Core calls Vault's detokenize endpoint over
mTLS. The raw PAN transits only inside the mTLS tunnel to the processor and
is never persisted in Zone 2.

**Scope justification:** Zone 2 is in scope for PCI DSS requirements related
to secure transmission (Req 4) and access control (Req 7/8) because it
initiates detokenization requests. It is NOT in scope for Requirement 3
(storage of cardholder data) because it never stores PAN.

### Zone 3: Vault CDE (full PCI scope -- Cardholder Data Environment)

| Property | Value |
|----------|-------|
| **K8s Namespace** | `hanzo-vault` |
| **Network** | Isolated private subnet, NO internet access, NO direct ingress |
| **Services** | vault-service (tokenize/detokenize), hsm-proxy, key-ceremony |
| **Data Exposure** | Encrypted PAN (AES-256-GCM), encryption keys (HSM-backed) |
| **Listen Port** | 8443 (mTLS only) |
| **Egress** | HSM (PKCS#11) only, no internet |

This is the Cardholder Data Environment. The vault-service binary
(`cmd/vault/main.go`) listens on `:8443` and exposes five card endpoints:

```
POST   /vault/cards                    -- Tokenize (encrypt PAN, return tok_*)
POST   /vault/cards/{token}/detokenize -- Detokenize (decrypt PAN, return raw)
GET    /vault/cards/{token}            -- Metadata (brand, last4, exp -- no PAN)
DELETE /vault/cards/{token}            -- Delete card record
POST   /vault/cards/{token}/rotate     -- Rotate token identifier
GET    /health                         -- Health check (no auth)
```

**RBAC roles** (from `auth/rbac.go`):

| Role | Permissions | Cannot |
|------|------------|--------|
| `tokenizer` | tokenize, metadata, delete | detokenize, key ops |
| `operator` | tokenize, detokenize, delete, rotate, metadata | key ops |
| `key_admin` | key_generate, key_rotate, key_destroy | card data access |
| `auditor` | audit_read | card data, key ops |

**Encryption**: AES-256-GCM with 12-byte random nonce, base64-encoded ciphertext
stored alongside key ID for envelope decryption (`crypto/encrypt.go`).

**Token format**: `tok_` + 48 hex characters (24 random bytes), validated by
`crypto.ValidateToken()`. Tokens are cryptographically random and cannot be
reversed to derive PAN.

**Deduplication**: SHA-256 fingerprint of normalized PAN. Prevents duplicate
vault entries without storing raw PAN in the index.

---

## 2. Trust Boundaries

### Network Topology (ASCII)

```
                                    PCI SCOPE BOUNDARY
                                    ===================
                                    :                 :
  Internet                          :                 :
     |                              :                 :
     v                              :                 :
 +-------+      +---------------+   :  +-----------+  :  +------------------+
 |  WAF  |----->|  Ingress      |   :  | Internal  |  :  |                  |
 |  CDN  |      |  Controller   |   :  | Load      |  :  |   VAULT CDE      |
 +-------+      +-------+-------+   :  | Balancer  |  :  |   (Zone 3)       |
                        |            :  +-----+-----+  :  |                  |
                        v            :        |        :  |  vault-service   |
                +---------------+    :        |        :  |  :8443 mTLS      |
                |               |    :        v        :  |                  |
                |  ZONE 1       |    :  +-----------+  :  |  hsm-proxy       |
                |  Public API   |    :  |           |  :  |                  |
                |               |    :  |  ZONE 2   |  :  |  key-ceremony    |
                |  commerce-api |--->:->|  Payments  |--->-|                  |
                |  checkout     |    :  |  Core      |  :  +--------+---------+
                |  portal       |    :  |           |  :           |
                |  webhooks     |    :  | intents   |  :           v
                |               |    :  | routing   |  :  +------------------+
                +---------------+    :  | disputes  |  :  |                  |
                                     :  | refunds   |  :  |   HSM            |
                tok_* only           :  +-----------+  :  |   (PKCS#11)      |
                brand, last4         :                 :  |                  |
                exp, fingerprint     :  tok_* + mTLS   :  +------------------+
                                     :                 :
                                     :                 :
                                     ===================
```

### Protocol and Authentication at Each Boundary

```
+-------------------+          +-------------------+          +-------------------+
|                   |          |                   |          |                   |
|    ZONE 1         |  HTTPS   |    ZONE 2         |  mTLS    |    ZONE 3         |
|    Public API     |--------->|    Payments Core   |--------->|    Vault CDE      |
|                   | Bearer   |                   | SPIFFE   |                   |
|    hanzo ns       | JWT/API  |    hanzo-payments  | x509     |    hanzo-vault    |
|                   | key      |    ns              | certs    |    ns             |
+-------------------+          +-------------------+          +-------------------+
        ^                              |                              |
        |                              |                              |
   TLS 1.3                        HTTPS to                       PKCS#11
   (public)                       processors                     (local)
        |                         (egress only)                       |
        v                              v                              v
    Internet                    Acquirer/PSP                        HSM
```

### Boundary Rules

| From | To | Protocol | Auth | Data Permitted |
|------|----|----------|------|----------------|
| Internet | Zone 1 | TLS 1.3 | Bearer JWT / API key | Customer requests (no PAN) |
| Zone 1 | Zone 2 | HTTPS (internal LB) | Service JWT | tok_*, amount, currency, metadata |
| Zone 2 | Zone 3 | mTLS (port 8443) | SPIFFE x509 | tok_* for detokenize; raw PAN for tokenize |
| Zone 3 | HSM | PKCS#11 (local socket) | Session auth | Key operations only |
| Zone 2 | Processors | HTTPS (egress) | Processor API keys | Network tokens, transaction data |
| Zone 3 | Internet | BLOCKED | N/A | No egress permitted |
| Zone 1 | Zone 3 | BLOCKED | N/A | No direct communication |

---

## 3. mTLS + SPIFFE/SPIRE Identity

### Trust Domain

```
Trust domain:     hanzo.ai
SPIRE server:     hanzo-vault namespace (Zone 3)
Certificate TTL:  1 hour (automatic rotation)
Root CA:          Offline, HSM-protected
```

### SPIFFE ID Assignment

Every workload receives a SPIFFE ID derived from its Kubernetes namespace and
service account. The SPIRE server runs inside the CDE (Zone 3) so that the
root of trust is within the highest-security zone.

```
Format: spiffe://hanzo.ai/{namespace}/{service-account}

Examples:
  spiffe://hanzo.ai/hanzo/commerce-api
  spiffe://hanzo.ai/hanzo-payments/payments-core
  spiffe://hanzo.ai/hanzo-vault/vault-tokenizer
  spiffe://hanzo.ai/hanzo-vault/vault-detokenizer
  spiffe://hanzo.ai/hanzo-vault/key-ceremony
```

### Service Identity and Authorization Matrix

| Service | SPIFFE ID | Can Call | Cannot Call |
|---------|-----------|----------|-------------|
| commerce-api | `spiffe://hanzo.ai/hanzo/commerce` | payments-core (Zone 2) | vault (Zone 3) -- BLOCKED by NetworkPolicy |
| checkout-js | N/A (browser) | vault:tokenize only (direct TLS, scoped) | vault:detokenize, vault:metadata |
| payments-core | `spiffe://hanzo.ai/hanzo-payments/payments` | vault:tokenize, vault:detokenize, vault:metadata | vault:key_*, vault:delete |
| vault-tokenizer | `spiffe://hanzo.ai/hanzo-vault/tokenizer` | HSM (PKCS#11) | Internet, Zone 1, Zone 2 |
| vault-detokenizer | `spiffe://hanzo.ai/hanzo-vault/detokenizer` | HSM (PKCS#11) | Internet, Zone 1, Zone 2 |
| key-ceremony | `spiffe://hanzo.ai/hanzo-vault/keyadmin` | HSM (PKCS#11) | Card data (no tokenize/detokenize perms) |
| audit-collector | `spiffe://hanzo.ai/hanzo-vault/auditor` | Audit DB (read-only) | Card data, key material |

### Certificate Lifecycle

```
1. Workload starts -> SPIRE agent on node attests workload identity
2. SPIRE server issues SVID (SPIFFE Verifiable Identity Document)
   - x509 certificate with SPIFFE ID in SAN
   - 1-hour TTL
3. Workload uses SVID for mTLS connections
4. SPIRE agent rotates SVID at 50% of TTL (every 30 minutes)
5. If rotation fails, workload retries with backoff
6. Stale SVIDs are rejected by peers (TTL check)
```

### Vault mTLS Enforcement

The vault-service (`cmd/vault/main.go`) in production MUST be configured with:

```go
// Production TLS configuration (not shown in dev main.go)
tlsConfig := &tls.Config{
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  spiffeTrustBundle,     // SPIRE trust bundle
    MinVersion: tls.VersionTLS13,
}
```

Only clients presenting a valid SVID from the `hanzo.ai` trust domain with an
authorized SPIFFE ID are permitted to connect.

---

## 4. Kubernetes Network Policies

### Zone 3: hanzo-vault (CDE)

```yaml
# Deny all ingress/egress by default, then allow only what is needed.
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-default-deny
  namespace: hanzo-vault
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []

---
# Allow ingress from hanzo-payments namespace on port 8443 only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-allow-payments-ingress
  namespace: hanzo-vault
spec:
  podSelector:
    matchLabels:
      app: vault-service
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: hanzo-payments
      ports:
        - protocol: TCP
          port: 8443

---
# Allow ingress from checkout.js tokenization (scoped to tokenize endpoint
# via application-layer auth -- NetworkPolicy permits the TLS connection).
# This is the ONLY direct path from outside the CDE into the vault.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-allow-checkout-tokenize
  namespace: hanzo-vault
spec:
  podSelector:
    matchLabels:
      app: vault-service
      role: tokenizer
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: hanzo
          podSelector:
            matchLabels:
              app: checkout-proxy
      ports:
        - protocol: TCP
          port: 8443

---
# Allow egress to HSM only (cluster-local or hardware appliance).
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-allow-hsm-egress
  namespace: hanzo-vault
spec:
  podSelector:
    matchLabels:
      app: vault-service
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: hsm-proxy
      ports:
        - protocol: TCP
          port: 2223

---
# Allow vault pods to reach SPIRE agent on the node.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-allow-spire-agent
  namespace: hanzo-vault
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: spire-agent
      ports:
        - protocol: TCP
          port: 8081

---
# Allow DNS resolution within the cluster.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-allow-dns
  namespace: hanzo-vault
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53

---
# Allow vault to reach its own PostgreSQL database (CDE-internal).
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-allow-db-egress
  namespace: hanzo-vault
spec:
  podSelector:
    matchLabels:
      app: vault-service
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: vault-postgres
      ports:
        - protocol: TCP
          port: 5432
```

### Zone 2: hanzo-payments

```yaml
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-default-deny
  namespace: hanzo-payments
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []

---
# Allow ingress from hanzo namespace (Zone 1) only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-allow-public-api-ingress
  namespace: hanzo-payments
spec:
  podSelector:
    matchLabels:
      app: payments-core
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: hanzo
      ports:
        - protocol: TCP
          port: 8080

---
# Allow egress to hanzo-vault (Zone 3) on port 8443.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-allow-vault-egress
  namespace: hanzo-payments
spec:
  podSelector:
    matchLabels:
      app: payments-core
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: hanzo-vault
      ports:
        - protocol: TCP
          port: 8443

---
# Allow egress to payment processors (external).
# In production, use specific CIDR ranges for each processor.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-allow-processor-egress
  namespace: hanzo-payments
spec:
  podSelector:
    matchLabels:
      app: payments-core
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              # Block private ranges except hanzo-vault
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443

---
# Allow DNS.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-allow-dns
  namespace: hanzo-payments
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53

---
# Allow SPIRE agent communication.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-allow-spire-agent
  namespace: hanzo-payments
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: spire-agent
      ports:
        - protocol: TCP
          port: 8081
```

### Zone 1: hanzo (Public API)

```yaml
---
# Zone 1 allows ingress from the internet via the ingress controller.
# It CANNOT reach Zone 3 (hanzo-vault) directly.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: public-api-allow-ingress
  namespace: hanzo
spec:
  podSelector:
    matchLabels:
      tier: public-api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080

---
# Allow egress to hanzo-payments (Zone 2) only.
# BLOCK direct egress to hanzo-vault (Zone 3).
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: public-api-allow-payments-egress
  namespace: hanzo
spec:
  podSelector:
    matchLabels:
      tier: public-api
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: hanzo-payments
      ports:
        - protocol: TCP
          port: 8080

---
# Explicitly deny egress to hanzo-vault from all public API pods.
# This is defense-in-depth on top of the default-deny in hanzo-vault.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: public-api-deny-vault-egress
  namespace: hanzo
spec:
  podSelector:
    matchLabels:
      tier: public-api
  policyTypes:
    - Egress
  egress: []
  # Note: This is enforced by the absence of a rule allowing
  # egress to hanzo-vault. Combined with default-deny on hanzo-vault
  # ingress, Zone 1 -> Zone 3 is double-blocked.

---
# Allow DNS for Zone 1.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: public-api-allow-dns
  namespace: hanzo
spec:
  podSelector:
    matchLabels:
      tier: public-api
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Namespace Labels (required for selectors)

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: hanzo
  labels:
    name: hanzo
    pci-zone: "1"
    pci-scope: "false"

---
apiVersion: v1
kind: Namespace
metadata:
  name: hanzo-payments
  labels:
    name: hanzo-payments
    pci-zone: "2"
    pci-scope: "partial"

---
apiVersion: v1
kind: Namespace
metadata:
  name: hanzo-vault
  labels:
    name: hanzo-vault
    pci-zone: "3"
    pci-scope: "true"
    environment: cde
```

---

## 5. Data Flow for Card Payment

### Step-by-Step: Customer Saves Card and Makes Payment

```
Step  Source              Destination          Data in Transit               Protocol
----  ------              -----------          ---------------               --------
 1    Browser             checkout.js          Card form rendered            HTTPS
                          (embedded iframe)    (isolated origin)

 2    checkout.js         Vault CDE            Raw PAN, exp, CVC            TLS 1.3
                          :8443                (direct connection)           (scoped
                          POST /vault/cards                                  cert)

 3    Vault CDE           checkout.js          tok_abc123...,               TLS 1.3
                                               brand=visa,
                                               last4=4242,
                                               expMonth=12,
                                               expYear=2028

 4    checkout.js         Commerce API         tok_abc123...,               HTTPS
                          (Zone 1)             amount=9900,
                                               currency=usd

 5    Commerce API        Payments Core        tok_abc123...,               HTTPS
      (Zone 1)            (Zone 2)             amount=9900,                 (internal
                          POST /pay            currency=usd,                 LB)
                                               merchantId=m_xyz

 6    Payments Core       Vault CDE            tok_abc123...                mTLS
      (Zone 2)            (Zone 3)             (detokenize request)         SPIFFE
                          POST /vault/cards                                  x509
                          /{token}/detokenize

 7    Vault CDE           Payments Core        Raw PAN                      mTLS
      (Zone 3)            (Zone 2)             (in response body,           (same
                                               never persisted              conn)
                                               in Zone 2)

 8    Payments Core       Acquirer/PSP         Network token or PAN,        HTTPS
      (Zone 2)            (external)           amount, currency,            (processor
                                               merchant ref                 API)

 9    Acquirer/PSP        Payments Core        Authorization result,        HTTPS
      (external)          (Zone 2)             auth code, decline reason

10    Payments Core       Commerce API         Payment result,              HTTPS
      (Zone 2)            (Zone 1)             status=succeeded,            (internal
                                               last4=4242                    LB)

11    Commerce API        Browser              Payment confirmation,        HTTPS
      (Zone 1)                                 receipt, order status
```

### Data at Rest in Each Zone

| Zone | What is Stored | Encryption | PAN Present? |
|------|---------------|------------|--------------|
| Zone 1 | tok_*, brand, last4, exp, payment status | TLS in transit, DB-level encryption | NO |
| Zone 2 | tok_*, payment intents, transaction logs | TLS in transit, DB-level encryption | NO |
| Zone 3 | Encrypted PAN (AES-256-GCM), key IDs, fingerprints | Envelope encryption (HSM master key -> DEK -> PAN) | YES (encrypted) |

### Checkout.js Isolation

The checkout.js component operates similarly to Stripe Elements:

- Renders in an **isolated iframe** on a separate origin (`vault.hanzo.ai`)
- The parent page (merchant site) CANNOT access iframe contents (same-origin policy)
- Raw PAN is captured inside the iframe and sent directly to Vault CDE
- The iframe returns only the token to the parent page via `postMessage`
- The merchant's JavaScript never has access to raw card numbers

```
+------------------------------------------+
|  Merchant Page (merchant.com)            |
|                                          |
|  +------------------------------------+  |
|  | checkout.js iframe                 |  |
|  | Origin: vault.hanzo.ai            |  |
|  |                                    |  |
|  |  [Card Number] [Exp] [CVC]        |  |
|  |                                    |  |
|  |  PAN -> TLS -> Vault CDE :8443    |  |
|  |  tok_* <- TLS <- Vault CDE        |  |
|  |                                    |  |
|  +----+-------------------------------+  |
|       | postMessage({token: "tok_*"})    |
|       v                                  |
|  merchant.js receives tok_* only         |
+------------------------------------------+
```

---

## 6. Audit and Compliance Controls

### Audit Event Types

From `audit/logger.go`, the vault records these immutable event types:

| Event Type | Trigger | PCI Requirement |
|------------|---------|-----------------|
| `tokenize` | PAN encrypted and token issued | Req 3.4, 10.2 |
| `detokenize` | PAN decrypted and returned | Req 3.4, 10.2 |
| `delete` | Card record purged | Req 3.1, 10.2 |
| `rotate` | Token identifier replaced | Req 3.6, 10.2 |
| `metadata` | Non-sensitive card info accessed | Req 10.2 |
| `key_generate` | New DEK created | Req 3.5, 3.6 |
| `key_rotate` | DEK rotated (old retired) | Req 3.6 |
| `key_destroy` | DEK permanently destroyed | Req 3.6 |
| `auth_failure` | Failed authentication or authorization | Req 10.2.4, 10.2.5 |

### Audit Record Structure

Every audit event captures (from `audit.Event`):

```
Field       Description                          Example
-----       -----------                          -------
id          Unique event ID                      evt_1042
timestamp   UTC timestamp                        2026-02-23T14:30:00Z
type        Event type                           detokenize
actor       Authenticated identity (SPIFFE ID)   spiffe://hanzo.ai/hanzo-payments/payments
tenantId    Tenant isolation key                 tenant_abc123
token       Affected vault token (if any)        tok_9f3a...
keyId       Affected key ID (if any)             key_7e2b...
success     Whether operation succeeded          true
error       Error message (if failed)            vault/auth: forbidden
ip          Source IP address                    10.244.1.15
details     Additional context                   rotated from tok_old...
```

### Tamper-Evident Storage

| Control | Implementation |
|---------|----------------|
| **Append-only** | Audit DB table uses INSERT-only permissions. No UPDATE or DELETE grants. |
| **WORM storage** | Audit logs replicated to S3-compatible object storage with Object Lock (compliance mode, 1-year retention). |
| **Integrity** | Each record includes HMAC-SHA256 chain hash linking to previous record. |
| **Replication** | Real-time streaming to compliance SIEM (separate security domain). |
| **Retention** | Minimum 1 year online, 7 years archived (PCI DSS Req 10.7). |

### Audit Database Location

The audit database runs INSIDE the CDE (Zone 3) because audit records reference
token identifiers and actor identities that constitute sensitive operational data.
A read replica streams to the compliance SIEM outside the CDE for monitoring.

```
+-------------------+          +-------------------+          +-------------------+
| Vault CDE         |          | Audit Replica     |          | Compliance SIEM   |
| (Zone 3)          |  WAL     | (Zone 3)          |  Stream  | (Separate domain) |
|                   | stream   |                   |  (TLS)   |                   |
| vault-service --> | -------> | audit-postgres    | -------> | Alerting          |
| INSERT only       |          | (read replica)    |          | Dashboards        |
+-------------------+          +-------------------+          | Retention         |
                                                              +-------------------+
```

### Vulnerability Management

| Control | Cadence | Owner |
|---------|---------|-------|
| Automated vulnerability scanning (containers) | Continuous (CI/CD pipeline) | Platform team |
| Internal network vulnerability scan | Quarterly | Security team |
| External network vulnerability scan (ASV) | Quarterly | QSA-approved ASV |
| Penetration test (application + network) | Annually | Third-party pen test firm |
| Critical/high patch SLA | 30 days from disclosure | Platform team |
| CDE-specific patch SLA | 14 days for critical, 30 days for high | Vault team |

### Key Ceremony Controls

| Control | Requirement |
|---------|-------------|
| Dual control | Minimum 2 authorized key custodians present |
| Split knowledge | No single person knows the complete key |
| Video recording | Entire ceremony recorded and archived (7 years) |
| Witness | Independent witness (auditor role) observes |
| Air-gapped workstation | Key generation on isolated machine (no network) |
| Tamper-evident bags | Key components stored in tamper-evident containers |
| Access log | Physical access log for HSM room |

### Evidence Collection

| Evidence | Frequency | Storage |
|----------|-----------|---------|
| SOC compliance snapshots (K8s state, NetworkPolicy, RBAC) | Daily (automated) | Compliance S3 bucket (WORM) |
| Firewall/NetworkPolicy rule review | Quarterly | Audit trail |
| Access reviews (who has CDE access) | Quarterly | IAM export |
| Penetration test report | Annually | Encrypted archive |
| Key ceremony recording | Per ceremony | Physical safe + encrypted backup |
| Vulnerability scan results | Per scan | Compliance SIEM |

---

## 7. HSM Integration Architecture

### Key Hierarchy

```
+---------------------------------------------------------------+
|                        HSM (FIPS 140-2 Level 3)               |
|                                                               |
|  +---------------------------+                                |
|  |  Master Key (MK)          |  <- Never leaves HSM           |
|  |  AES-256                  |  <- Generated in key ceremony  |
|  |  Rotation: annual         |  <- Dual-control required      |
|  +------------+--------------+                                |
|               |                                               |
+---------------------------------------------------------------+
                | Wraps/Unwraps
                v
+---------------------------------------------------------------+
|  Data Encryption Keys (DEKs)                                  |
|                                                               |
|  +------------------+  +------------------+  +-------------+  |
|  | DEK v1 (retired) |  | DEK v2 (retired) |  | DEK v3      |  |
|  | key_7e2b...      |  | key_a1c4...      |  | key_f9d0... |  |
|  | AES-256-GCM      |  | AES-256-GCM      |  | AES-256-GCM |  |
|  | Created 2025-Q1  |  | Created 2025-Q3  |  | ACTIVE      |  |
|  +------------------+  +------------------+  +-------------+  |
|                                                               |
|  Stored as: HSM_Encrypt(MK, DEK_plaintext) -> wrapped_DEK    |
|  Rotation: quarterly                                          |
+---------------------------------------------------------------+
                | Encrypts/Decrypts
                v
+---------------------------------------------------------------+
|  Cardholder Data                                              |
|                                                               |
|  PAN: AES-256-GCM(DEK, plaintext_pan) -> ciphertext          |
|  Stored as: { keyId: "key_f9d0...", ciphertext: "base64..." }|
|  (from store.Card struct in store/store.go)                   |
+---------------------------------------------------------------+
```

### Envelope Encryption Flow

```
TOKENIZE (encrypt):
  1. vault-service receives raw PAN
  2. vault-service calls HSM: unwrap(MK, wrapped_active_DEK) -> DEK plaintext
  3. vault-service encrypts: AES-256-GCM(DEK, PAN) -> ciphertext
  4. vault-service stores: { keyId, ciphertext } (DEK plaintext zeroed from memory)
  5. vault-service returns: tok_* token

DETOKENIZE (decrypt):
  1. vault-service receives tok_* token
  2. vault-service looks up: { keyId, ciphertext } from store
  3. vault-service calls HSM: unwrap(MK, wrapped_DEK[keyId]) -> DEK plaintext
  4. vault-service decrypts: AES-256-GCM(DEK, ciphertext) -> PAN
  5. vault-service returns PAN over mTLS (DEK plaintext zeroed from memory)
```

### HSM Interface

| Property | Value |
|----------|-------|
| **Production** | AWS CloudHSM (FIPS 140-2 Level 3) |
| **Development** | SoftHSM2 (PKCS#11 compatible, NOT for production) |
| **Interface** | PKCS#11 v2.40 |
| **Connection** | Local Unix socket or TCP to HSM cluster |
| **Supported Operations** | C_GenerateKey, C_WrapKey, C_UnwrapKey, C_Encrypt, C_Decrypt |
| **Authentication** | HSM partition credentials (PIN-based) |

### Key Rotation Schedule

| Key Type | Rotation Period | Procedure | Downtime |
|----------|----------------|-----------|----------|
| Master Key (MK) | Annual | Key ceremony (dual-control, video-recorded) | Zero (old MK retained for unwrap) |
| Data Encryption Keys (DEKs) | Quarterly | Automated via `key_admin` role | Zero (old DEKs retained for decrypt) |
| SPIFFE SVIDs | 1 hour | Automatic (SPIRE agent) | Zero |
| TLS certificates (ingress) | 90 days | Automated (cert-manager) | Zero |

### DEK Rotation Process

When `KeyManager.GenerateNewKey()` is called (from `crypto/keys.go`):

```
1. Generate 32 random bytes (AES-256 key)               -- crypto/rand.Reader
2. Generate key ID: "key_" + 16 random bytes (hex)      -- GenerateKeyID()
3. Wrap new DEK with HSM Master Key                      -- HSM C_WrapKey
4. Mark current active DEK as "retired"                  -- KeyStatus = KeyRetired
5. Store wrapped DEK with metadata                       -- KeyMeta{Status: KeyActive}
6. Set new DEK as active                                 -- km.activeKeyID = newID
7. Audit log: key_rotate event                           -- audit.EventKeyRotate

Old DEKs remain available for DECRYPT (retired status).
Old DEKs can be permanently destroyed via DestroyKey() (key_admin role only).
Data encrypted with a destroyed key is irrecoverable.
```

### Emergency Key Rotation Runbook (Key Compromise)

If a DEK or Master Key compromise is suspected:

```
SEVERITY: P0 -- IMMEDIATE RESPONSE

1. DETECT
   - Alert from SIEM, anomalous detokenize patterns, or external notification
   - Confirm scope: which key ID(s) are affected

2. CONTAIN (< 15 minutes)
   - Revoke SPIFFE SVIDs for any compromised workloads
   - Apply emergency NetworkPolicy blocking all vault ingress:
     kubectl apply -f emergency-lockdown.yaml -n hanzo-vault
   - Notify incident commander and key custodians

3. ROTATE (< 1 hour for DEK, < 4 hours for MK)
   FOR DEK COMPROMISE:
   a. Generate new DEK via key_admin:
      POST /vault/keys/generate (key_admin role)
   b. Re-encrypt all cards using compromised DEK:
      Run re-encryption batch job (reads with old DEK, writes with new DEK)
   c. Mark compromised DEK as destroyed:
      POST /vault/keys/{keyId}/destroy (key_admin role)

   FOR MASTER KEY COMPROMISE:
   a. Initiate emergency key ceremony (dual-control)
   b. Generate new MK in HSM
   c. Re-wrap all DEKs with new MK
   d. Destroy old MK in HSM
   e. This requires physical access to HSM

4. VERIFY
   - Confirm all data is accessible with new keys
   - Review audit logs for unauthorized access during compromise window
   - Verify NetworkPolicy restored to normal

5. NOTIFY
   - Notify acquiring bank and card brands within 24 hours (PCI requirement)
   - File incident report per PCI DSS Req 12.10
   - Engage forensic investigator (PFI) if breach confirmed

6. POST-INCIDENT
   - Root cause analysis within 72 hours
   - Update key ceremony procedures if needed
   - Document lessons learned in compliance archive
```

### Emergency Lockdown NetworkPolicy

```yaml
# Apply with: kubectl apply -f emergency-lockdown.yaml -n hanzo-vault
# This blocks ALL traffic to the vault except health checks from kubelet.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-emergency-lockdown
  namespace: hanzo-vault
  annotations:
    pci.hanzo.ai/reason: "Emergency lockdown -- key compromise response"
spec:
  podSelector:
    matchLabels:
      app: vault-service
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress:
    # Allow only HSM access for key rotation
    - to:
        - podSelector:
            matchLabels:
              app: hsm-proxy
      ports:
        - protocol: TCP
          port: 2223
```

---

## Appendix A: PCI DSS v4.0 Requirement Mapping

| PCI DSS Requirement | How Addressed |
|---------------------|---------------|
| **1 -- Network Security Controls** | Three-zone architecture, K8s NetworkPolicies, default-deny |
| **2 -- Secure Configurations** | Minimal container images, no default credentials, hardened K8s |
| **3 -- Protect Stored Account Data** | AES-256-GCM encryption, HSM-backed keys, envelope encryption |
| **4 -- Protect Data in Transit** | TLS 1.3 (public), mTLS with SPIFFE (internal), no plaintext channels |
| **5 -- Malware Protection** | Read-only container filesystems, no shell in CDE containers |
| **6 -- Secure Development** | Code review, SAST/DAST in CI, dependency scanning |
| **7 -- Restrict Access** | RBAC with 4 roles (tokenizer, operator, key_admin, auditor) |
| **8 -- Identify and Authenticate** | SPIFFE/SPIRE workload identity, mTLS, no shared credentials |
| **9 -- Physical Access** | HSM in secure facility, key ceremony controls |
| **10 -- Log and Monitor** | Immutable audit log, SIEM integration, WORM retention |
| **11 -- Security Testing** | Quarterly scans, annual pen test, continuous container scanning |
| **12 -- Organizational Policies** | Incident response runbook, key ceremony procedures, access reviews |

## Appendix B: Vault Source Code References

| Component | Source File | PCI Relevance |
|-----------|-------------|---------------|
| HTTP endpoints + RBAC enforcement | `api/cards.go` | Req 7 (access control at API layer) |
| Role definitions + permission matrix | `auth/rbac.go` | Req 7 (least privilege roles) |
| AES-256-GCM encryption/decryption | `crypto/encrypt.go` | Req 3.4 (render PAN unreadable) |
| Key lifecycle management | `crypto/keys.go` | Req 3.5, 3.6 (key management) |
| Token generation + PAN fingerprinting | `crypto/tokenize.go` | Req 3.4 (tokenization) |
| Encrypted card storage + tenant isolation | `store/store.go` | Req 3.4, 7 (storage + isolation) |
| Immutable audit event logging | `audit/logger.go` | Req 10 (audit trails) |
| Service entrypoint + route registration | `cmd/vault/main.go` | Req 1 (network boundaries) |
