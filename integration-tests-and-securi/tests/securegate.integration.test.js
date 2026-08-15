===
const assert = require('assert');
const http = require('http');

const BASE = process.env.GATEWAY_URL || 'http://localhost:8080';
const ADMIN_KEY = process.env.ADMIN_API_KEY || 'ak-admin-test';
const VIEWER_CREDS = { username: 'viewer@test.com', password: 'ViewPass1!' };
const ADMIN_CREDS = { username: 'admin@test.com', password: 'AdminPass1!' };

function request(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const opts = { hostname: url.hostname, port: url.port, path: url.pathname + url.search, method, headers: { 'Content-Type': 'application/json', ...headers } };
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data ? JSON.parse(data) : {} }));
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function login(creds) {
  const res = await request('POST', '/auth/login', creds);
  assert.strictEqual(res.status, 200, `Login failed: ${JSON.stringify(res.body)}`);
  assert.ok(res.body.access_token, 'No access_token returned');
  assert.ok(res.body.refresh_token, 'No refresh_token returned');
  return res.body;
}

async function getWithToken(token, path) {
  return request('GET', path, null, { Authorization: `Bearer ${token}`, 'X-API-Key': ADMIN_KEY });
}

describe('SecureGate Integration Tests', () => {
  let viewerToken, adminToken, viewerRefresh, adminRefresh;

  describe('Authentication Flows', () => {
    it('should login as viewer and receive valid JWT', async () => {
      const tokens = await login(VIEWER_CREDS);
      viewerToken = tokens.access_token;
      viewerRefresh = tokens.refresh_token;
      const parts = viewerToken.split('.');
      assert.strictEqual(parts.length, 3, 'Token is not a valid JWT');
    });

    it('should login as admin and receive valid JWT', async () => {
      const tokens = await login(ADMIN_CREDS);
      adminToken = tokens.access_token;
      adminRefresh = tokens.refresh_token;
    });

    it('should reject invalid credentials with 401', async () => {
      const res = await request('POST', '/auth/login', { username: 'viewer@test.com', password: 'wrong' });
      assert.strictEqual(res.status, 401);
    });

    it('should refresh token with valid refresh token', async () => {
      const res = await request('POST', '/auth/refresh', { refresh_token: viewerRefresh });
      assert.strictEqual(res.status, 200);
      assert.ok(res.body.access_token, 'No new access_token on refresh');
      viewerToken = res.body.access_token;
    });

    it('should reject expired or invalid refresh token', async () => {
      const res = await request('POST', '/auth/refresh', { refresh_token: 'invalid.refresh.token' });
      assert.strictEqual(res.status, 401);
    });

    it('should reject request with no auth header', async () => {
      const res = await request('GET', '/api/metrics/health', null, { 'X-API-Key': ADMIN_KEY });
      assert.strictEqual(res.status, 401);
    });
  });

  describe('RBAC - Role-Based Access Control', () => {
    it('should allow viewer to read metrics', async () => {
      const res = await getWithToken(viewerToken, '/api/metrics/health');
      assert.strictEqual(res.status, 200);
    });

    it('should deny viewer from writing config (403)', async () => {
      const res = await request('PUT', '/api/config/thresholds', { cpu: 90 }, { Authorization: `Bearer ${viewerToken}`, 'X-API-Key': ADMIN_KEY });
      assert.strictEqual(res.status, 403);
    });

    it('should allow admin to write config', async () => {
      const res = await request('PUT', '/api/config/thresholds', { cpu: 90 }, { Authorization: `Bearer ${adminToken}`, 'X-API-Key': ADMIN_KEY });
      assert.strictEqual(res.status, 200);
    });

    it('should allow admin to read metrics', async () => {
      const res = await getWithToken(adminToken, '/api/metrics/health');
      assert.strictEqual(res.status, 200);
    });

    it('should deny viewer from admin-only user listing', async () => {
      const res = await getWithToken(viewerToken, '/api/admin/users');
      assert.strictEqual(res.status, 403);
    });

    it('should allow admin to list users', async () => {
      const res = await getWithToken(adminToken, '/api/admin/users');
      assert.strictEqual(res.status, 200);
    });
  });

  describe('API Key Management', () => {
    it('should reject request with missing API key', async () => {
      const res = await request('GET', '/api/metrics/health', null, { Authorization: `Bearer ${viewerToken}` });
      assert.strictEqual(res.status, 401);
    });

    it('should reject request with invalid API key', async () => {
      const res = await request('GET', '/api/metrics/health', null, { Authorization: `Bearer ${viewerToken}`, 'X-API-Key': 'bogus-key' });
      assert.strictEqual(res.status, 401);
    });

    it('should allow admin to create a new API key', async () => {
      const res = await request('POST', '/api/admin/apikeys', { name: 'test-key', roles: ['viewer'] }, { Authorization: `Bearer ${adminToken}`, 'X-API-Key': ADMIN_KEY });
      assert.strictEqual(res.status, 201);
      assert.ok(res.body.key, 'No key returned');
    });
  });

  describe('Rate Limiting', () => {
    it('should allow requests under rate limit', async () => {
      const res = await getWithToken(viewerToken, '/api/metrics/health');
      assert.strictEqual(res.status, 200);
    });

    it('should return 429 when rate limit is exceeded', async () => {
      const requests = Array(55).fill(null).map(() => getWithToken(viewerToken, '/api/metrics/health'));
      const results = await Promise.allSettled(requests);
      const rateLimited = results.some(r => r.status === 'fulfilled' && r.value.status === 429);
      assert.ok(rateLimited, 'No 429 received; rate limiting may be disabled');
    });

    it('should include rate limit headers in response', async () => {
      const res = await getWithToken(viewerToken, '/api/metrics/health');
      const hasRateHeaders = res.headers['x-ratelimit-limit'] || res.headers['x-ratelimit-remaining'];
      assert.ok(hasRateHeaders, 'Missing X-RateLimit headers');
    });
  });

  describe('Security - Token Tampering', () => {
    it('should reject token with modified payload', async () => {
      const parts = viewerToken.split('.');
      const tampered = parts[0] + '.' + Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(parts[1], 'base64').toString()), role: 'admin' })).toString('base64').replace(/=/g, '') + '.' + parts[2];
      const res = await request('GET', '/api/admin/users', null, { Authorization: `Bearer ${tampered}`, 'X-API-Key': ADMIN_KEY });
      assert.strictEqual(res.status, 401, 'Tampered token was accepted!');
    });

    it('should reject token with corrupted signature', async () => {
      const parts = viewerToken.split('.');
      const corrupted = parts[0] + '.' + parts[1] + '.' + 'a' + parts[2].slice(1);
      const res = await getWithToken(corrupted, '/api/metrics/health');
      assert.strictEqual(res.status, 401, 'Corrupted signature accepted!');
    });

    it('should reject completely fabricated token', async () => {
      const fake = Buffer.from('{"alg":"HS256"}').toString('base64') + '.' + Buffer.from('{"sub":"admin","role":"admin"}').toString('base64') + '.fakesig';
      const res = await getWithToken(fake, '/api/admin/users');
      assert.strictEqual(res.status, 401, 'Fabricated token accepted!');
    });

    it('should reject token with alg:none attack', async () => {
      const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64').replace(/=/g, '');
      const payload = Buffer.from('{"sub":"admin","role":"admin"}').toString('base64').replace(/=/g, '');
      const noneToken = header + '.' + payload + '.';
      const res = await getWithToken(noneToken, '/api/admin/users');
      assert.strictEqual(res.status, 401, 'alg:none attack succeeded!');
    });
  });

  describe('Security - Privilege Escalation', () => {
    it('should not grant admin access via role query param', async () => {
      const res = await request('GET', '/api/admin/users?role=admin', null, { Authorization: `Bearer ${viewerToken}`, 'X-API-Key': ADMIN_KEY });
      assert.ok(res.status === 403 || res.status === 401, 'Privilege escalation via query param!');
    });

    it('should not escalate via body role field override', async () => {
      const res = await request('POST', '/auth/login', { ...VIEWER_CREDS, role: 'admin' });
      const tok = res.body.access_token;
      if (tok) {
        const esc = await request('GET', '/api/admin/users', null, { Authorization: `Bearer ${tok}`, 'X-API-Key': ADMIN_KEY });
        assert.ok(esc.status === 403 || esc.status === 401, 'Body role override escalation!');
      }
    });
  });

  describe('Security - Rate Bypass Attempts', () => {
    it('should not bypass rate limit via X-Forwarded-For spoofing', async () => {
      const reqs = Array(55).fill(null).map((_, i) =>
        request('GET', '/api/metrics/health', null, { Authorization: `Bearer ${viewerToken}`, 'X-API-Key': ADMIN_KEY, 'X-Forwarded-For': `10.0.0.${i % 255}` })
      );
      const results = await Promise.allSettled(reqs);
      const rateLimited = results.some(r => r.status === 'fulfilled' && r.value.status === 429);
      assert.ok(rateLimited, 'Rate bypass via X-Forwarded-For succeeded!');
    });
  });
});
===