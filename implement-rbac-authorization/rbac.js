===
const HIERARCHY = ['guest', 'user', 'manager', 'admin', 'superadmin'];

const ROLE_PERMISSIONS = {
  guest:    ['read:public'],
  user:     ['read:public', 'read:own', 'write:own'],
  manager:  ['read:public', 'read:own', 'read:team', 'write:own', 'write:team', 'delete:own'],
  admin:    ['read:public', 'read:own', 'read:team', 'read:all', 'write:own', 'write:team', 'write:all', 'delete:own', 'delete:team'],
  superadmin: ['read:public', 'read:own', 'read:team', 'read:all', 'write:own', 'write:team', 'write:all', 'delete:own', 'delete:team', 'delete:all', 'admin:users', 'admin:roles', 'admin:system'],
};

function resolvePermissions(role) {
  const idx = HIERARCHY.indexOf(role);
  if (idx === -1) return [];
  const inherited = HIERARCHY.slice(0, idx);
  const perms = new Set();
  for (const r of inherited) {
    for (const p of ROLE_PERMISSIONS[r] || []) perms.add(p);
  }
  for (const p of ROLE_PERMISSIONS[role] || []) perms.add(p);
  return [...perms];
}

function checkPermission(role, permission) {
  return resolvePermissions(role).includes(permission);
}

function checkAnyPermission(role, permissions) {
  const owned = resolvePermissions(role);
  return permissions.some(p => owned.includes(p));
}

function checkAllPermissions(role, permissions) {
  const owned = resolvePermissions(role);
  return permissions.every(p => owned.includes(p));
}

class PolicyEngine {
  constructor() {
    this.policies = [];
  }

  addPolicy(policy) {
    this.policies.push(policy);
  }

  evaluate(context) {
    const { role, action, resource } = context;
    const permissions = resolvePermissions(role);
    for (const policy of this.policies) {
      if (policy.resource && policy.resource !== resource) continue;
      if (policy.action && policy.action !== action) continue;
      const result = typeof policy.effect === 'function'
        ? policy.effect(context, permissions)
        : policy.effect;
      if (result === 'deny') return false;
      if (result === 'allow') return true;
    }
    return checkPermission(role, `${action}:${resource}`);
  }
}

function rbacMiddleware(options = {}) {
  const { role: staticRole, permission, anyOf, allOf, policy } = options;

  return (req, res, next) => {
    const role = staticRole || req.user?.role || 'guest';

    if (permission) {
      if (!checkPermission(role, permission)) {
        return res.status(403).json({ error: 'Forbidden', required: permission, role });
      }
    }

    if (anyOf && anyOf.length > 0) {
      if (!checkAnyPermission(role, anyOf)) {
        return res.status(403).json({ error: 'Forbidden', requiredAny: anyOf, role });
      }
    }

    if (allOf && allOf.length > 0) {
      if (!checkAllPermissions(role, allOf)) {
        return res.status(403).json({ error: 'Forbidden', requiredAll: allOf, role });
      }
    }

    if (policy) {
      const ctx = {
        role,
        action: req.method.toLowerCase() === 'get' ? 'read' : req.method.toLowerCase() === 'delete' ? 'delete' : 'write',
        resource: req.baseUrl + req.path,
        user: req.user,
        params: req.params,
        query: req.query,
      };
      if (!policy.evaluate(ctx)) {
        return res.status(403).json({ error: 'Forbidden', policy: 'denied', role });
      }
    }

    req.rbac = { role, permissions: resolvePermissions(role) };
    next();
  };
}

module.exports = {
  HIERARCHY,
  ROLE_PERMISSIONS,
  resolvePermissions,
  checkPermission,
  checkAnyPermission,
  checkAllPermissions,
  PolicyEngine,
  rbacMiddleware,
};