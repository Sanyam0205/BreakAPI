import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GuardedClient } from '../src/client.js';
import { HARD_LIMITS } from '../src/scope.js';
import { VERSION } from '../src/version.js';
import pkg from '../package.json' with { type: 'json' };

const make = (controls) => new GuardedClient({
  project: { authorization: {}, target: { baseUrl: 'http://127.0.0.1:1' }, controls },
  scan: {}, control: {}, onLog() {}, onResponse() {},
});

test('stored timeout and error-streak controls are capped even if hand-edited', () => {
  const c = make({ timeoutMs: 1e9, stopOnErrorStreak: 1e9 });
  assert.equal(c.timeoutMs, HARD_LIMITS.timeoutMs);
  assert.equal(c.stopOnErrorStreak, HARD_LIMITS.stopOnErrorStreak);
});

test('missing or nonsense controls fall back to safe values, so a scan still stops on errors', () => {
  const c = make({});
  assert.equal(c.timeoutMs, 10_000);
  assert.equal(c.stopOnErrorStreak, 10);
  const z = make({ timeoutMs: 0, stopOnErrorStreak: 0 });
  assert.equal(z.timeoutMs, 1000);
  assert.equal(z.stopOnErrorStreak, 1);
});

test('the version constant matches package.json', () => {
  assert.equal(VERSION, pkg.version);
});
