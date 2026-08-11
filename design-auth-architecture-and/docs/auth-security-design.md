# SecureGate Auth Architecture & Security Model

## 1. Overview

SecureGate is a centralized authentication/authorization gateway that sits in front of platform microservices (metrics-ingest, pulsealert, statushub). It handles OAuth2 flows, issues JWTs, enforces RBAC, manages API keys, and applies rate limits.

```
Client → SecureGate → [metrics-ingest | pulsealert | statushub]
               ↑
        Auth decisions: JWT validation, RBAC check, rate limit
```

## 2. JWT Authentication Flow

### 2.1 Token Types

| Token | Purpose | Lifetime | Storage |
|-------|---------|----------|---------|
| Access Token | Authorize API calls | 15 min | In-memory only |
| Refresh Token | Obtain new access tokens | 7 days | HttpOnly secure cookie |
| ID Token | Identity claims (OIDC) | 15 min | Client-side (if needed) |

### 2.2 OAuth2 Supported Grants

- **Authorization Code + PKCE** — browser-based SPAs and web apps
- **Client Credentials** — service-to-service communication
- **Refresh Token** — token rotation for all grants

### 2.3 Auth Code + PKCE Flow

```
1. Client → /authorize?response_type=code&client_id=X&code_challenge=SHA256(verifier)&redirect_uri=U&scope=S
2. User authenticates (login UI or external IdP)
3. SecureGate → 302 redirect_uri?code=AUTH_CODE
4. Client → POST /token { grant_type=authorization_code, code, code_verifier, client_id, redirect_uri }
5. SecureGate validates, issues: { access_token, refresh_token, id_token, expires_in }
6. On expiry: Client → POST /token { grant_type=refresh_token, refresh_token }
7. SecureGate rotates refresh_token, issues new access_token
```

### 2.4 Client Credentials Flow (service-to-service)

```
1. Service → POST /token { grant_type=client_credentials, client_id, client_secret, scope }
2. SecureGate validates credentials, issues short-lived access_token (15 min)
3. No refresh_token issued
```

### 2.5 JWT Structure

**Access Token Header:**
```json
{ "alg": "RS256", "typ": "JWT", "kid": "sg-key-2024-01" }
```

**Access Token Payload:**
```json
{
  "iss": "securegate",
  "sub": "user-uuid-or-service-id",
  "aud": ["metrics-ingest", "pulsealert", "statushub"],
  "exp": 1700000000,
  "iat": 1699999100,
  "jti": "unique-token-id",
  "scope": "metrics:read alerts:write",
  "roles": ["editor"],
  "org_id": "org-uuid",
  "tenant_id": "tenant-uuid"
}
```

### 2.6 Token Lifecycle

```
Issue → Active → [expired] → Refresh Window (grace 60s) → Revoked/Invalid
                                              ↓
                                        New token issued
```

- **Revocation:** Tokens are revocable via a deny-list stored in Redis (TTL = token remaining TTL). On logout or security event, `jti` is added.
- **Rotation:** Each refresh_token can be used exactly once. Reuse of a previously-rotated refresh_token revokes the entire token family (refresh token rotation with replay detection).
- **Key Rotation:** Signing keys rotated quarterly. Old `kid` remains valid for 24h after rotation for grace-period verification.

## 3. RBAC Permission Model

### 3.1 Roles

| Role | Scope | Description |
|------|-------|-------------|
| `system:admin` | Global | Full platform administration, user management, key management |
| `org:admin` | Organization | Manage org settings, invite/remove members, assign roles within org |
| `editor` | Project/Org | Create, update, delete resources; manage alerts and dashboards |
| `viewer` | Project/Org | Read-only access to resources, dashboards, and status pages |
| `service` | Service | Machine-to-machine; scoped by client_credentials, no UI access |
| `api-consumer` | API Key | Limited scope defined per API key; no interactive login |

### 3.2 Permissions (resource:action)

| Permission | system:admin | org:admin | editor | viewer | service | api-consumer |
|------------|:---:|:---:|:---:|:---:|:---:|:---:|
| `metrics:read` | ✓ | ✓ | ✓ | ✓ | scoped | scoped |
| `metrics:write` | ✓ | ✓ | ✓ | — | scoped | scoped |
| `metrics:delete` | ✓ | — | — | — | — | — |
| `alerts:read` | ✓ | ✓ | ✓ | ✓ | scoped | scoped |
| `alerts:write` | ✓ | ✓ | ✓ | — | scoped | scoped |
| `alerts:execute` | ✓ | ✓ | ✓ | — | scoped | — |
| `status:read` | ✓ | ✓ | ✓ | ✓ | ✓ | scoped |
| `status:write` | ✓ | ✓ | ✓ | — | scoped | scoped |
| `users:manage` | ✓ | ✓ | — | — | — | — |
| `keys:manage` | ✓ | ✓ | — | — | — | — |
| `roles:manage` | ✓ | ✓ | — | — | — | — |
| `system:config` | ✓ | — | — | — | — | — |

### 3.3 Permission Resolution

1. Extract `roles` and `scope` from JWT claims
2. Resolve role → permission mapping (table above)
3. Intersect with `scope` claim (scopes further restrict permissions)
4. For API keys: permissions = role permissions ∩ key-defined scopes
5. Cache resolved permission set in Redis (TTL = token remaining life)

### 3.4 Enforcement Pattern

Every upstream request passes through:
```
 authenticate → extract_token → validate_signature → check_revocation
   → resolve_roles → check_permission(resource, action) → apply_rate_limit → proxy
```

## 4. API Key Management

### 4.1 Key Lifecycle

```
Create → Active → [Rotated → Active(new), Deprecated(old, 24h grace)] → Revoked → Deleted
```

- Keys are prefixed: `sg_live_...` / `sg_test_...` for environment isolation
- SHA-256 hash stored; raw key shown only once at creation
- Each key has: owner, roles, scopes, rate_limit_override, expires_at, metadata

### 4.2 Key Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/api-keys` | Bearer JWT | Create new API key |
| GET | `/v1/api-keys` | Bearer JWT | List keys (paginated) |
| GET | `/v1/api-keys/:id` | Bearer JWT | Get key metadata (never raw key) |
| POST | `/v1/api-keys/:id/rotate` | Bearer JWT | Rotate key (grace period for old) |
| DELETE | `/v1/api-keys/:id` | Bearer JWT | Revoke key immediately |

## 5. Rate Limiting Strategy

### 5.1 Multi-Layer Model

| Layer | Key | Limit | Window | Scope |
|-------|-----|-------|--------|-------|
| Global | — | 10,000 req | 1 min | All traffic |
| Per-Client | `client_id` | 1,000 req | 1 min | OAuth clients |
| Per-User | `sub` | 500 req | 1 min | Authenticated users |
| Per-API-Key | `key_id` | Custom/default: 100 req | 1 min | API key callers |
| Per-Endpoint | `method:path` | Varies | 1 min | Expensive endpoints |

### 5.2 Algorithm: Sliding Window Counter (Redis)

- Two Redis counters per key: current window and previous window
- Weighted count = `prev_count × (1 - elapsed/window) + curr_count`
- If weighted count ≥ limit → 429 Too Many Requests

### 5.3 Rate Limit Headers

```
X-RateLimit-Limit: 500
X-RateLimit-Remaining: 432
X-RateLimit-Reset: 1700000060
Retry-After: 28
```

### 5.4 Burst Allowance

Short bursts (up to 2× limit) are permitted for ≤2 seconds using a token-bucket overlay. This accommodates legitimate batch patterns without sustained abuse.

## 6. API Contracts

### 6.1 Auth Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/authorize` | Start auth code flow |
| POST | `/v1/token` | Exchange code/refresh for tokens |
| POST | `/v1/revoke` | Revoke a token |
| GET | `/v1/.well-known/openid-configuration` | OIDC discovery |
| GET | `/v1/.well-known/jwks.json` | Public key set |
| GET | `/v1/userinfo` | User profile from token |
| POST | `/v1/logout` | End session, revoke tokens |

### 6.2 Gateway Proxy

| Method | Path | Description |
|--------|------|-------------|
| * | `/gw/metrics/**` | Proxy to metrics-ingest (requires `metrics:*`) |
| * | `/gw/alerts/**` | Proxy to pulsealert (requires `alerts:*`) |
| * | `/gw/status/**` | Proxy to statushub (requires `status:*`) |

### 6.3 Standard Error Response

```json
{
  "error": "forbidden",
  "error_code": "SG_PERMISSION_DENIED",
  "message": "Insufficient permissions: requires metrics:write",
  "request_id": "req-uuid",
  "timestamp": "2024-01-15T10:00:00Z"
}
```

| HTTP | Error Code | Meaning |
|------|-----------|---------|
| 401 | `SG_TOKEN_INVALID` | Missing, malformed, or expired token |
| 403 | `SG_PERMISSION_DENIED` | Valid token, insufficient role/scope |
| 429 | `SG_RATE_LIMITED` | Rate limit exceeded |
| 401 | `SG_KEY_REVOKED` | API key has been revoked |

## 7. Threat Model

### 7.1 Threats & Mitigations

| Threat | Severity | Mitigation |
|--------|----------|------------|
| **Token theft (XSS)** | High | Access tokens never in cookies; short 15-min TTL; refresh rotation with replay detection |
| **Token theft (MITM)** | High | TLS 1.3 enforced; HSTS with preload; no mixed content |
| **Refresh token replay** | High | Single-use rotation; family revocation on reuse detection; bind to client fingerprint |
| **CSRF on auth endpoints** | Medium | PKCE required for auth code flow; state parameter validated; SameSite=Strict cookies |
| **Brute-force credentials** | Medium | Account lockout after 5 failures (15-min lock); exponential backoff; CAPTCHA trigger |
| **API key leakage** | Medium | Keys shown once; prefix allows secret scanning; rotation with grace; scoped narrowly |
| **Privilege escalation** | High | Roles assigned only by `org:admin`+; no self-role-assignment; permission resolution is intersection (never union); audit log all role changes |
| **Excessive data access** | Medium | Tokens scoped to `org_id`/`tenant_id`; services enforce tenant isolation; no cross-tenant queries |
| **DDoS / abuse** | High | Global rate limit; per-IP rate limit (unauth); per-client/user/key limits; 429 with backoff |
| **Compromised signing key** | Critical | Keys in HSM/KMS; automated quarterly rotation; old `kid` revoked on compromise; token re-issuance on key rotation |
| **Supply chain (IdP)** | Medium | Support multiple IdPs; IdP token validation strict; fallback to local auth |
| **Logging sensitive data** | Medium | Never log tokens, keys, or secrets; PII redacted; request IDs for tracing |

### 7.2 Security Invariants

1. No token shall be valid beyond its `exp` claim, regardless of cache state
2. A revoked token must be rejected within 100ms of revocation (Redis deny-list)
3. API keys are never stored in plaintext; only SHA-256 hashes persisted
4. Role assignment requires a role equal or higher than the assigned role
5. All gateway egress to upstream services uses mutual TLS
6. Every auth decision (grant, deny, revoke) emits an audit event

### 7.3 Audit Events

Every security-relevant action produces an immutable audit record:

```json
{
  "event_id": "evt-uuid",
  "timestamp": "2024-01-15T10:00:00Z",
  "actor": { "sub": "user-uuid", "ip": "203.0.113.1", "user_agent": "..." },
  "action": "token.issued",
  "resource": { "type": "access_token", "id": "jti-value" },
  "outcome": "success",
  "metadata": { "grant_type": "authorization_code", "scope": "metrics:read" }
}
```

## 8. Deployment Security

- **Secrets:** All keys/tokens in Vault or KMS; environment variables for non-secret config only
- **Network:** SecureGate in private subnet; only ALB/WAF exposed publicly; mTLS to upstream services
- **WAF:** OWASP Top 10 rule set; geo-blocking optional; request size limit 1MB
- **Observability:** Auth metrics (issue rate, failure rate, latency); alert on anomaly (>3σ failure spike)
- **Hardening:** CSP headers, X-Content-Type-Options: nosniff, no Server header, strict Referer-Policy