import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, statSync, existsSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store, StoreError } from '../src/store.js';

const tmp = () => mkdtempSync(join(tmpdir(), 'breakapi-store-'));
const mode = (f) => statSync(f).mode & 0o777;

test('a corrupt data file fails closed: friendly error, file untouched, no overwrite', () => {
  const dir = tmp();
  const file = join(dir, 'db.json');
  writeFileSync(file, '{"projects": {"p1": ');
  assert.throws(() => new Store(dir), (e) => e instanceof StoreError && e.message.includes(file) && /not been changed/.test(e.message) && /No backup/.test(e.message));
  assert.equal(readFileSync(file, 'utf8'), '{"projects": {"p1": ');
  assert.ok(!existsSync(`${file}.bak`), 'a corrupt file is never copied over the backup');
  writeFileSync(file, '[]');
  assert.throws(() => new Store(dir), StoreError);
  rmSync(dir, { recursive: true, force: true });
});

test('the error points at an existing backup', () => {
  const dir = tmp();
  writeFileSync(join(dir, 'db.json'), '{ nope');
  writeFileSync(join(dir, 'db.json.bak'), '{"projects":{},"scans":{}}');
  assert.throws(() => new Store(dir), /backup from an earlier good state is at .*db\.json\.bak/);
  rmSync(dir, { recursive: true, force: true });
});

test('a good file is backed up byte for byte at start, owner-only; encrypted fields stay encrypted', () => {
  const dir = tmp();
  const file = join(dir, 'db.json');
  writeFileSync(file, JSON.stringify({ projects: { p: { accounts: [{ secretEnc: 'ciphertext-blob' }] } }, scans: {} }), { mode: 0o600 });
  new Store(dir);
  assert.equal(readFileSync(`${file}.bak`, 'utf8'), readFileSync(file, 'utf8'));
  assert.equal(mode(`${file}.bak`), 0o600);
  assert.ok(!readFileSync(`${file}.bak`, 'utf8').includes('"secret"'));
  rmSync(dir, { recursive: true, force: true });
});

test('saving keeps the previous complete file as the backup, and the file stays owner-only', () => {
  const dir = tmp();
  const file = join(dir, 'db.json');
  const s = new Store(dir, { backupEveryMs: 0 });
  s.data.projects.a = { n: 1 };
  s.saveNow();
  s.data.projects.b = { n: 2 };
  s.saveNow();
  assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')).projects, { a: { n: 1 }, b: { n: 2 } });
  assert.deepEqual(JSON.parse(readFileSync(`${file}.bak`, 'utf8')).projects, { a: { n: 1 } });
  assert.equal(mode(file), 0o600);
  assert.equal(mode(`${file}.bak`), 0o600);
  rmSync(dir, { recursive: true, force: true });
});

test('the backup is not rewritten on every save', () => {
  const dir = tmp();
  const s = new Store(dir); // default interval: minutes
  s.data.projects.a = { n: 1 };
  s.saveNow(); // first write: nothing to back up yet
  s.data.projects.b = { n: 2 };
  s.saveNow();
  s.data.projects.c = { n: 3 };
  s.saveNow();
  // taken when the second save replaced the file holding only `a`; the third save left it alone
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'db.json.bak'), 'utf8')).projects, { a: { n: 1 } });
  rmSync(dir, { recursive: true, force: true });
});

test('the server exits with the friendly message, not a stack trace', () => {
  const dir = tmp();
  writeFileSync(join(dir, 'db.json'), 'garbage');
  const r = spawnSync(process.execPath, ['src/main.js'], { cwd: new URL('..', import.meta.url).pathname, env: { ...process.env, BREAKAPI_DATA: dir, BREAKAPI_PORT: '0' }, encoding: 'utf8', timeout: 20000 });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /cannot start: the data file .*db\.json is unreadable/);
  assert.ok(!/at .*\.js:\d+/.test(r.stderr), 'no stack trace');
  assert.equal(readFileSync(join(dir, 'db.json'), 'utf8'), 'garbage');
  rmSync(dir, { recursive: true, force: true });
});
