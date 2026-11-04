// Client for the simulation backend's control API (the breakapi-sim repo). The URL and key come only
// from server configuration. Nothing in a visitor's request can change where these calls go.

export class SimError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const CATALOG_TTL_MS = 5 * 60_000;
const SANDBOX_ID = /^sbx_[A-Za-z0-9_-]{16}$/;

export function createSimClient({ url, key, timeoutMs = 10_000 }) {
  const base = url.replace(/\/$/, '');

  const call = async (method, path, body, { timeout = timeoutMs } = {}) => {
    let res;
    try {
      res = await fetch(`${base}/_control${path}`, {
        method,
        headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', accept: 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        // Never follow a redirect: it would carry the control key to wherever it points.
        redirect: 'error',
        signal: AbortSignal.timeout(timeout),
      });
    } catch {
      throw new SimError(503, 'The simulation backend could not be reached. Try again in a moment.');
    }
    if (res.status === 204) return null;
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      // The sim's own messages are short and safe; anything unexpected becomes a generic one.
      const message = res.status === 400 || res.status === 404 ? data?.error?.message : null;
      throw new SimError(res.status === 401 ? 503 : res.status, message || 'The simulation backend refused the request.');
    }
    return data;
  };

  const sandboxPath = (id, suffix = '') => {
    if (!SANDBOX_ID.test(String(id))) throw new SimError(404, 'No such sandbox.');
    return `/sandboxes/${id}${suffix}`;
  };

  let catalog = null;
  let catalogAt = 0;

  return {
    host: new URL(base).host,
    /** The vulnerability catalog and presets, cached for a few minutes. */
    async catalog() {
      if (!catalog || Date.now() - catalogAt > CATALOG_TTL_MS) {
        catalog = await call('GET', '/catalog', undefined, { timeout: 5000 });
        catalogAt = Date.now();
      }
      return catalog;
    },
    create: (vulns, seed) => call('POST', '/sandboxes', { vulns, ...(seed ? { seed } : {}) }),
    get: (id) => call('GET', sandboxPath(id)),
    configure: (id, vulns) => call('PUT', sandboxPath(id, '/config'), { vulns }),
    reset: (id) => call('POST', sandboxPath(id, '/reset')),
    remove: (id) => call('DELETE', sandboxPath(id)),
    spec: (id) => call('GET', sandboxPath(id, '/openapi.json')),
  };
}
