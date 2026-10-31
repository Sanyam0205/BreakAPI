import { shortHash } from './util.js';

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];

function normalizePath(p) {
  let path = String(p).trim()
    .replace(/\{\{([^}]+)\}\}/g, '{$1}')
    .replace(/:([A-Za-z_]\w*)/g, '{$1}');
  if (!path.startsWith('/')) path = `/${path}`;
  return path;
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** Guess what an endpoint does from its path and body, to pick which synthetic checks apply. */
export function endpointKind(method, path, bodyExample) {
  const m = method.toUpperCase();
  const p = path.toLowerCase();
  const fields = bodyExample && typeof bodyExample === 'object' ? Object.keys(bodyExample).join(' ').toLowerCase() : '';
  if (m === 'POST' && /(^|\/)(login|signin|sign-in|session|token|authenticate)(\/|$)/.test(p)) return 'login';
  if (m === 'POST' && (/(^|\/)(register|signup|sign-up)(\/|$)/.test(p) || (/(^|\/)users?$/.test(p) && /email/.test(fields)))) return 'signup';
  if (['POST', 'PUT', 'PATCH'].includes(m) && (/(order|checkout|cart|payment|invoice|purchase|basket)/.test(p) || /(quantity|qty|price|amount|total|discount)/.test(fields))) return 'order';
  if (['POST', 'PUT', 'PATCH'].includes(m) && /(profile|account|users?|me)(\/|$)/.test(p)) return 'profile';
  return 'generic';
}

export function makeEndpoint({ method, path, requiresAuth = true, adminOnly, params = [], bodyExample, summary = '' }) {
  const m = method.toUpperCase();
  const p = normalizePath(path);
  const merged = [...params];
  for (const [, name] of p.matchAll(/\{([^}]+)\}/g)) {
    if (!merged.some((x) => x.in === 'path' && x.name === name)) merged.push({ name, in: 'path', required: true, type: 'string' });
  }
  return {
    id: shortHash(`${m} ${p}`),
    method: m,
    path: p,
    summary,
    requiresAuth,
    adminOnly: adminOnly ?? /(^|\/)admin(\/|$)/i.test(p),
    params: merged,
    bodyExample,
    kind: endpointKind(m, p, bodyExample),
    enabled: true,
    // Always off after an import: a spec (possibly someone else's) can never grant write permission.
    // A person turns this on per endpoint, and only for endpoints that are safe to send synthetic data to.
    syntheticWrites: false,
  };
}

function dedupe(endpoints) {
  return [...new Map(endpoints.map((e) => [e.id, e])).values()];
}

function sampleFromSchema(schema0, resolve, depth = 0) {
  const schema = resolve(schema0);
  if (!schema || depth > 5) return null;
  if (schema.example !== undefined) return schema.example;
  if (schema.default !== undefined) return schema.default;
  if (schema.enum) return schema.enum[0];
  if (schema.allOf) {
    return Object.assign({}, ...schema.allOf.map((s) => sampleFromSchema(s, resolve, depth + 1)).filter((v) => v && typeof v === 'object'));
  }
  if (schema.oneOf || schema.anyOf) return sampleFromSchema((schema.oneOf || schema.anyOf)[0], resolve, depth + 1);
  switch (schema.type) {
    case 'object':
      return Object.fromEntries(
        Object.entries(schema.properties || {})
          .filter(([, prop]) => !resolve(prop)?.readOnly)
          .map(([k, prop]) => [k, sampleFromSchema(prop, resolve, depth + 1)]),
      );
    case 'array':
      return [sampleFromSchema(schema.items, resolve, depth + 1)].filter((v) => v !== null);
    case 'integer':
    case 'number':
      return 1;
    case 'boolean':
      return true;
    case 'string':
      return schema.format === 'email' ? 'breakapi-test@example.com' : 'breakapi-test';
    default:
      return schema.properties ? sampleFromSchema({ ...schema, type: 'object' }, resolve, depth + 1) : null;
  }
}

export function importOpenApi(text) {
  let doc;
  try {
    doc = typeof text === 'string' ? JSON.parse(text) : text;
  } catch {
    throw new Error('Could not parse the specification as JSON. YAML is not supported yet — convert it first, e.g. `npx @redocly/cli bundle spec.yaml --ext json`.');
  }
  if (!doc || (!doc.openapi && !doc.swagger) || typeof doc.paths !== 'object') {
    throw new Error('Not an OpenAPI/Swagger document (missing "openapi"/"swagger" or "paths").');
  }

  const resolve = (obj, depth = 0) => {
    if (obj && typeof obj.$ref === 'string' && depth < 10) {
      const target = obj.$ref.replace(/^#\//, '').split('/')
        .reduce((o, k) => o?.[k.replace(/~1/g, '/').replace(/~0/g, '~')], doc);
      return resolve(target, depth + 1);
    }
    return obj;
  };

  const endpoints = [];
  for (const [path, item0] of Object.entries(doc.paths)) {
    const item = resolve(item0) || {};
    for (const m of METHODS) {
      const op = item[m];
      if (!op) continue;
      const params = [...(item.parameters || []), ...(op.parameters || [])]
        .map((p) => resolve(p))
        .filter((p) => p && (p.in === 'path' || p.in === 'query'))
        .map((p) => {
          const schema = resolve(p.schema) || p;
          return {
            name: p.name,
            in: p.in,
            required: !!p.required || p.in === 'path',
            type: schema.type || 'string',
            example: p.example ?? schema.example ?? schema.enum?.[0] ?? schema.default,
          };
        });
      const security = op.security ?? doc.security ?? [];
      const requiresAuth = security.length > 0 && !security.some((s) => Object.keys(s).length === 0);
      const adminOnly = op['x-breakapi-admin'] ?? ((op.tags || []).some((t) => /admin/i.test(t)) || undefined);

      let bodyExample;
      const json = resolve(op.requestBody)?.content?.['application/json'];
      if (json) bodyExample = json.example ?? sampleFromSchema(json.schema, resolve);
      const bodyParam = (op.parameters || []).map((p) => resolve(p)).find((p) => p?.in === 'body');
      if (bodyParam) bodyExample = sampleFromSchema(bodyParam.schema, resolve);

      endpoints.push(makeEndpoint({ method: m, path, requiresAuth, adminOnly, params, bodyExample, summary: op.summary || op.operationId || '' }));
    }
  }

  let baseUrl;
  const server = doc.servers?.[0]?.url;
  if (server && /^https?:\/\//.test(server)) baseUrl = server;
  else if (doc.host) baseUrl = `${doc.schemes?.[0] || 'https'}://${doc.host}${doc.basePath || ''}`;
  return { endpoints: dedupe(endpoints), baseUrl, title: doc.info?.title };
}

export function importPostman(text) {
  let col;
  try {
    col = JSON.parse(text);
  } catch {
    throw new Error('Could not parse the collection as JSON.');
  }
  if (!Array.isArray(col?.item)) throw new Error('Not a Postman collection (missing "item").');

  const endpoints = [];
  let baseUrl;
  const walk = (items, inheritedAuth) => {
    for (const it of items) {
      const auth = it.auth ?? inheritedAuth;
      if (Array.isArray(it.item)) {
        walk(it.item, auth);
        continue;
      }
      if (!it.request) continue;
      const r = typeof it.request === 'string' ? { url: it.request, method: 'GET' } : it.request;
      const reqAuth = r.auth ?? auth;
      const raw = typeof r.url === 'string' ? r.url : r.url?.raw || '';
      const [noQuery, qs] = raw.split('?');
      let path = noQuery.replace(/^\{\{[^}]+\}\}/, '');
      const abs = path.match(/^https?:\/\/[^/]+/);
      if (abs) {
        baseUrl ??= abs[0];
        path = path.slice(abs[0].length);
      }
      const params = qs
        ? qs.split('&').filter(Boolean).map((kv) => {
          const [name, v = ''] = kv.split('=');
          return { name: safeDecode(name), in: 'query', required: true, type: 'string', example: /^\{\{/.test(v) ? undefined : safeDecode(v) };
        })
        : [];
      let bodyExample;
      if (r.body?.mode === 'raw') {
        try { bodyExample = JSON.parse(r.body.raw); } catch { /* not JSON */ }
      }
      endpoints.push(makeEndpoint({ method: r.method || 'GET', path: path || '/', requiresAuth: reqAuth?.type !== 'noauth', params, bodyExample, summary: it.name || '' }));
    }
  };
  walk(col.item, col.auth);
  return { endpoints: dedupe(endpoints), baseUrl, title: col.info?.name };
}

/** One endpoint per line: `METHOD /path/{id}?q=x [public] [admin]`. */
export function importManual(text) {
  const endpoints = [];
  for (const [i, line0] of String(text).split('\n').entries()) {
    const line = line0.replace(/\s#.*$|^#.*$/, '').trim();
    if (!line) continue;
    const [method, rawPath, ...flags] = line.split(/\s+/);
    if (!METHODS.includes(method?.toLowerCase()) || !rawPath?.startsWith('/')) {
      throw new Error(`Line ${i + 1}: expected "METHOD /path [public] [admin]"`);
    }
    const [path, qs] = rawPath.split('?');
    const params = qs
      ? qs.split('&').filter(Boolean).map((kv) => {
        const [name, v] = kv.split('=');
        return { name, in: 'query', required: true, type: 'string', example: v || undefined };
      })
      : [];
    endpoints.push(makeEndpoint({ method, path, requiresAuth: !flags.includes('public'), adminOnly: flags.includes('admin') || undefined, params }));
  }
  if (!endpoints.length) throw new Error('No endpoints found.');
  return { endpoints: dedupe(endpoints) };
}

export function importSpec(format, content) {
  if (format === 'openapi') return importOpenApi(content);
  if (format === 'postman') return importPostman(content);
  if (format === 'manual') return importManual(content);
  throw new Error(`Unknown import format "${format}".`);
}
