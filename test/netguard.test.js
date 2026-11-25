import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyAddress, addressRefusal, hostRefusal } from '../src/netguard.js';

const open = { allowLocalTargets: true, allowPrivateTargets: true };
const prod = { allowLocalTargets: false, allowPrivateTargets: false };

test('IPv6 forms embedding an IPv4 address are classified by that address', () => {
  const cases = {
    '::ffff:a9fe:a9fe': 'metadata', // hex form WHATWG produces for ::ffff:169.254.169.254
    '::ffff:169.254.169.254': 'metadata',
    '0:0:0:0:0:ffff:a9fe:a9fe': 'metadata',
    '::ffff:7f00:1': 'loopback',
    '::7f00:1': 'loopback', // IPv4-compatible
    '64:ff9b::a9fe:a9fe': 'metadata', // NAT64
    '64:ff9b::a00:1': 'private',
    '2002:a9fe:a9fe::1': 'metadata', // 6to4
    '2002:7f00:1::': 'loopback',
    '2002:a9fe::1': 'linklocal', // compressed spelling: embeds 169.254.0.0
    '2002:808:808::1': 'public',
    '::ffff:808:808': 'public',
    '64:ff9b::808:808': 'public',
  };
  for (const [ip, kind] of Object.entries(cases)) assert.equal(classifyAddress(ip), kind, ip);
});

test('reserved IPv4 ranges are classified reserved and always refused', () => {
  for (const ip of ['224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255', '198.18.0.1', '198.19.255.1', '192.0.0.5', '::ffff:e000:1', '2001:0:4136:e378:8000:63bf:3fff:fdd2', '2001::1', '64:ff9b:1::a00:1', '2002:e000:1::']) {
    assert.equal(classifyAddress(ip), 'reserved', ip);
    assert.ok(addressRefusal(ip, open), ip);
  }
  assert.equal(classifyAddress('198.17.0.1'), 'public');
  assert.equal(classifyAddress('192.0.2.1'), 'public');
});

test('metadata via mapped literal is refused even when local and private are allowed', () => {
  assert.ok(addressRefusal('::ffff:a9fe:a9fe', open));
  assert.ok(hostRefusal('[::ffff:a9fe:a9fe]', open));
  assert.ok(hostRefusal('[::ffff:7f00:1]', prod));
  assert.equal(hostRefusal('[::ffff:808:808]', prod), null);
});

test('existing classes are unchanged', () => {
  assert.equal(classifyAddress('::1'), 'loopback');
  assert.equal(classifyAddress('::'), 'unspecified');
  assert.equal(classifyAddress('fe80::1'), 'linklocal');
  assert.equal(classifyAddress('fd12::1'), 'private');
  assert.equal(classifyAddress('2606:4700::1111'), 'public');
  assert.equal(classifyAddress('not-an-ip'), 'invalid');
});
