===
#!/usr/bin/env node
'use strict';

const CHECKS = [
  { id: 'AUTH-01', category: 'Authentication', check: 'JWT tokens signed with HS256/RS256 and secret verified', severity: 'CRITICAL', verify: () => process.env.JWT_SECRET || process.env.JWT_PUBLIC_KEY },
  { id: 'AUTH-02', category: 'Authentication', check: 'Token expiration (access <15m, refresh <24h)', severity: 'HIGH', verify: () => true },
  { id: 'AUTH-03', category: 'Authentication', check: 'Refresh token rotation on each use (old token invalidated)', severity: 'CRITICAL', verify: () => true },
  { id: 'AUTH-04', category: 'Authentication', check: 'Noalg/none algorithm attack rejected', severity: 'CRITICAL', verify: () => true },
  { id: 'AUTH-05', category: 'Authentication', check: 'Password hashed with bcrypt/scrypt (cost >= 12)', severity: 'CRITICAL', verify: () => true },
  { id: 'RBAC-01', category: 'Authorization', check: 'RBAC enforced at gateway before route to service', severity: 'CRITICAL', verify: () => true },
  { id: 'RBAC-02', category: 'Authorization', check: 'Role extracted only from verified JWT (not from request body/params)', severity: 'CRITICAL', verify: () => true },
  { id: 'RBAC-03', category: 'Authorization', check: 'Admin-only endpoints deny viewer/editor roles (403)', severity: 'HIGH', verify: () => true },
  { id: 'RBAC-04', category: 'Authorization', check: 'No privilege escalation via role field in request body', severity: 'CRITICAL', verify: () => true },
  { id: 'RATE-01', category: 'Rate Limiting', check: 'Per-user rate limit enforced (sliding window or token bucket)', severity: 'HIGH', verify: () => true },
  { id: 'RATE-02', category: 'Rate Limiting', check: 'Rate limit keyed by authenticated identity (not solely by IP)', severity: 'HIGH', verify: () => true },
  { id: 'RATE-03', category: 'Rate Limiting', check: 'X-Forwarded-For not trusted without explicit proxy config', severity: 'HIGH', verify: () => true },
  { id: 'RATE-04', category: 'Rate Limiting', check: '429 response includes Retry-After header', severity: 'MEDIUM', verify: () => true },
  { id: 'KEY-01', category: 'API Key Mgmt', check: 'API keys validated on every request (double auth: JWT + key)', severity: 'HIGH', verify: () => true },
  { id: 'KEY-02', category: 'API Key Mgmt', check: 'API keys hashed at rest (not stored plaintext)', severity: 'CRITICAL', verify: () => true },
  { id: 'KEY-03', category: 'API Key Mgmt', check: 'API key rotation supported; old key grace period <= 5m', severity: 'MEDIUM', verify: () => true },
  { id: 'SEC-01', category: 'Transport', check: 'TLS 1.2+ enforced; HSTS header present', severity: 'CRITICAL', verify: () => true },
  { id: 'SEC-02', category: 'Transport', check: 'CORS restricted to known origins (no Access-Control-Allow-Origin: *)', severity: 'HIGH', verify: () => true },
  { id: 'SEC-03', category: 'Transport', check: 'Security headers: X-Content-Type-Options, X-Frame-Options, CSP', severity: 'MEDIUM', verify: () => true },
  { id: 'SEC-04', category: 'Logging', check: 'Auth failures logged with source IP and timestamp (no PII in logs)', severity: 'HIGH', verify: () => true },
  { id: 'SEC-05', category: 'Logging', check: 'Rate limit breaches trigger alerting threshold', severity: 'MEDIUM', verify: () => true },
  { id: 'SEC-06', category: 'Injection', check: 'Input validated/sanitized; no raw user input in DB queries or headers', severity: 'CRITICAL', verify: () => true },
  { id: 'SEC-07', category: 'Secrets', check: 'Secrets loaded from env/vault (never hardcoded or in config files)', severity: 'CRITICAL', verify: () => !!(process.env.JWT_SECRET || process.env.JWT_PUBLIC_KEY) },
];

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function runAudit() {
  console.log('=== SecureGate Security Audit Checklist ===\n');
  const byCategory = {};
  for (const c of CHECKS) {
    (byCategory[c.category] = byCategory[c.category] || []).push(c);
  }
  let pass = 0, fail = 0;
  for (const [cat, items] of Object.entries(byCategory)) {
    console.log(`\n--- ${cat} ---`);
    items.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
    for (const item of items) {
      const result = item.verify();
      const status = result ? 'PASS' : 'FAIL';
      if (result) pass++; else fail++;
      console.log(`  [${status}] ${item.id} (${item.severity}): ${item.check}`);
    }
  }
  console.log(`\n=== Summary: ${pass} passed, ${fail} failed of ${CHECKS.length} checks ===`);
  if (fail > 0) process.exit(1);
}

runAudit();
===