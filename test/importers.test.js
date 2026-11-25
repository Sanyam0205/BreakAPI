import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { importSpec } from '../src/importers.js';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const find = (r, method, path) => r.endpoints.find((e) => e.method === method && e.path === path);

test('OpenAPI 3: the demo spec imports with auth, admin and path-parameter flags', () => {
  const r = importSpec('openapi', read('../demo/openapi.json'));
  assert.equal(r.endpoints.length, 14);
  assert.equal(r.baseUrl, 'http://localhost:4010');
  assert.equal(find(r, 'GET', '/api/health').requiresAuth, false);
  assert.equal(find(r, 'GET', '/api/me').requiresAuth, true);
  assert.equal(find(r, 'GET', '/api/admin/users').adminOnly, true);
  assert.deepEqual(find(r, 'GET', '/api/users/{id}').params.map((p) => p.name), ['id']);
});

test('OpenAPI: $ref parameters and bodies, x-breakapi-admin, and Swagger 2 host/basePath', () => {
  const r = importSpec('openapi', JSON.stringify({
    swagger: '2.0', host: 'api.example.test', schemes: ['https'], basePath: '/v1',
    parameters: { Id: { name: 'id', in: 'path', required: true, type: 'integer' } },
    definitions: { Item: { type: 'object', properties: { name: { type: 'string' }, qty: { type: 'integer' }, id: { type: 'integer', readOnly: true } } } },
    security: [{ key: [] }],
    paths: {
      '/items/{id}': { get: { parameters: [{ $ref: '#/parameters/Id' }], 'x-breakapi-admin': true } },
      '/items': { post: { parameters: [{ in: 'body', name: 'b', schema: { $ref: '#/definitions/Item' } }], security: [] } },
    },
  }));
  assert.equal(r.baseUrl, 'https://api.example.test/v1');
  const get = find(r, 'GET', '/items/{id}');
  assert.equal(get.adminOnly, true);
  assert.equal(get.params[0].name, 'id');
  const post = find(r, 'POST', '/items');
  assert.equal(post.requiresAuth, false);
  assert.deepEqual(post.bodyExample, { name: 'breakapi-test', qty: 1 }); // readOnly fields are left out
});

test('Postman: placeholders resolve, noauth is public, folders inherit auth', () => {
  const r = importSpec('postman', read('../testdata/demo-postman.json'));
  assert.equal(r.endpoints.length, 9);
  assert.equal(find(r, 'GET', '/api/health').requiresAuth, false);
  assert.equal(find(r, 'GET', '/api/me').requiresAuth, true);
  assert.ok(r.endpoints.every((e) => !e.path.includes('{{')));
  assert.equal(find(r, 'GET', '/api/search').params[0].name, 'q');
});

test('manual list imports with flags and reports the bad line', () => {
  const r = importSpec('manual', read('../testdata/demo-manual.txt'));
  assert.equal(r.endpoints.length, 8);
  assert.equal(find(r, 'GET', '/api/health').requiresAuth, false);
  assert.throws(() => importSpec('manual', 'GET /ok\nFETCH /nope'), /Line 2/);
  assert.throws(() => importSpec('manual', '# only a comment'), /No endpoints/);
});

test('bad input gives a clear error', () => {
  assert.throws(() => importSpec('openapi', read('../testdata/invalid-spec.yaml')), /YAML is not supported/);
  assert.throws(() => importSpec('openapi', read('../testdata/not-a-spec.json')), /Not an OpenAPI/);
  assert.throws(() => importSpec('postman', read('../testdata/not-a-spec.json')), /Not a Postman collection/);
  assert.throws(() => importSpec('postman', 'not json'), /Could not parse/);
  assert.throws(() => importSpec('csv', 'x'), /Unknown import format/);
});

test('no import ever grants synthetic writes', () => {
  const all = [
    importSpec('openapi', read('../demo/openapi.json')),
    importSpec('postman', read('../testdata/demo-postman.json')),
    importSpec('manual', 'POST /orders\nPUT /orders/{id}\nPATCH /me'),
  ];
  for (const r of all) assert.ok(r.endpoints.every((e) => e.syntheticWrites === false));
});
