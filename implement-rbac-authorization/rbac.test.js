===
const assert = require('assert');
const { HIERARCHY, resolvePermissions, checkPermission, checkAnyPermission, checkAllPermissions, PolicyEngine, rbacMiddleware } = require('./rbac');

// resolvePermissions
assert.deepStrictEqual(resolvePermissions('guest'), ['read:public']);
assert.ok(resolvePermissions('user').includes('read:public'), 'user inherits guest');
assert.ok(resolvePermissions('user').includes('write:own'), 'user has own write');
assert.ok(resolvePermissions('manager').includes('delete:own'), 'manager inherits user + own delete');
assert.ok(resolvePermissions('admin').includes('write:all'), 'admin has write:all');
assert.ok(resolvePermissions('superadmin').includes('admin:system'), 'superadmin has admin:system');
assert.deepStrictEqual(resolvePermissions('unknown'), [], 'unknown role yields empty');

// checkPermission
assert.strictEqual(checkPermission('guest', 'read:public'), true);
assert.strictEqual(checkPermission('guest', 'write:own'), false);
assert.strictEqual(checkPermission('user', 'read:public'), true);
assert.strictEqual(checkPermission('admin', 'write:team'), true);
assert.strictEqual(checkPermission('superadmin', 'admin:system'), true);
assert.strictEqual(checkPermission('user', 'admin:system'), false);

// checkAnyPermission
assert.strictEqual(checkAnyPermission('user', ['admin:system', 'write:own']), true);
assert.strictEqual(checkAnyPermission('guest', ['admin:system', 'write:own']), false);

// checkAllPermissions
assert.strictEqual(checkAllPermissions('user', ['read:public', 'write:own']), true);
assert.strictEqual(checkAllPermissions('user', ['read:public', 'admin:system']), false);

// PolicyEngine
const engine = new PolicyEngine();
engine.addPolicy({ resource: '/admin', action: 'write', effect: 'deny' });
engine.addPolicy({ resource: '/data', action: 'read', effect: 'allow' });
engine.addPolicy({ resource: '/data', action: 'write', effect: (ctx, perms) => perms.includes('write:all') ? 'allow' : 'deny' });

assert.strictEqual(engine.evaluate({ role: 'admin', action: 'write', resource: '/admin' }), false);
assert.strictEqual(engine.evaluate({ role: 'user', action: 'read', resource: '/data' }), true);
assert.strictEqual(engine.evaluate({ role: 'user', action: 'write', resource: '/data' }), false);
assert.strictEqual(engine.evaluate({ role: 'admin', action: 'write', resource: '/data' }), true);
assert.strictEqual(engine.evaluate({ role: 'admin', action: 'read', resource: '/data' }), true);

// rbacMiddleware - permission check
let called = false;
const next = () => { called = true; };
const res = { statusCode: 0, body: null, status(c) { this.statusCode = c; return this; }, json(d) { this.body = d; return this; } };

called = false; res.statusCode = 0; res.body = null;
const mw = rbacMiddleware({ permission: 'write:own' });
mw({ user: { role: 'user' } }, res, next);
assert.strictEqual(called, true, 'user can write:own');

called = false; res.statusCode = 0; res.body = null;
mw({ user: { role: 'guest' } }, res, next);
assert.strictEqual(res.statusCode, 403, 'guest denied write:own');
assert.strictEqual(called, false);

// rbacMiddleware - anyOf
const mwAny = rbacMiddleware({ anyOf: ['admin:system', 'write:own'] });
called = false; res.statusCode = 0;
mwAny({ user: { role: 'user' } }, res, next);
assert.strictEqual(called, true, 'user satisfies anyOf');

called = false; res.statusCode = 0;
mwAny({ user: { role: 'guest' } }, res, next);
assert.strictEqual(res.statusCode, 403, 'guest fails anyOf');

// rbacMiddleware - allOf
const mwAll = rbacMiddleware({ allOf: ['read:public', 'write:own'] });
called = false; res.statusCode = 0;
mwAll({ user: { role: 'user' } }, res, next);
assert.strictEqual(called, true, 'user satisfies allOf');

called = false; res.statusCode = 0;
mwAll({ user: { role: 'guest' } }, res, next);
assert.strictEqual(res.statusCode, 403, 'guest fails allOf');

// rbacMiddleware - policy
const policyMw = new PolicyEngine();
policyMw.addPolicy({ resource: '/secrets', action: 'read', effect: 'deny' });
const mwPolicy = rbacMiddleware({ policy: policyMw });
called = false; res.statusCode = 0;
mwPolicy({ user: { role: 'admin' }, method: 'GET', baseUrl: '/secrets', path: '/' }, res, next);
assert.strictEqual(res.statusCode, 403, 'policy denies /secrets read');

called = false; res.statusCode = 0;
mwPolicy({ user: { role: 'admin' }, method: 'GET', baseUrl: '/data', path: '/x' }, res, next);
assert.strictEqual(called, true, 'policy allows /data read');

// rbacMiddleware sets req.rbac
called = false; res.statusCode = 0;
const reqCtx = { user: { role: 'admin' }, method: 'GET', baseUrl: '/', path: '/test' };
mwPolicy(reqCtx, res, next);
assert.deepStrictEqual(reqCtx.rbac.role, 'admin');
assert.ok(reqCtx.rbac.permissions.includes('write:all'));

// Hierarchy order
for (let i = 1; i < HIERARCHY.length; i++) {
  const lower = resolvePermissions(HIERARCHY[i - 1]);
  const higher = resolvePermissions(HIERARCHY[i]);
  assert.ok(higher.length >= lower.length, `${HIERARCHY[i]} >= ${HIERARCHY[i-1]}`);
  for (const p of lower) assert.ok(higher.includes(p), `${HIERARCHY[i]} inherits ${p} from ${HIERARCHY[i-1]}`);
}

console.log('All RBAC tests passed ✓');