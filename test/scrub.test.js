import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeScrubber } from '../src/scanner.js';

const secret = 'tok+en/with=chars%and "quotes" 12345';
const scrub = makeScrubber([{ authType: 'bearer', secret }]);

const forms = {
  raw: secret,
  'URL-encoded (component)': encodeURIComponent(secret),
  'URL-encoded (whole URI)': encodeURI(secret),
  'base64 padded': Buffer.from(secret).toString('base64'),
  'base64 unpadded': Buffer.from(secret).toString('base64').replace(/=+$/, ''),
  base64url: Buffer.from(secret).toString('base64url'),
  'JSON-escaped': JSON.stringify(secret).slice(1, -1),
};

for (const [name, form] of Object.entries(forms)) {
  test(`scrubber removes the secret in ${name} form, in nested strings`, () => {
    const out = JSON.stringify(scrub({ title: `x ${form} y`, evidence: [{ body: `{"a":"${form}"}`, requestHeaders: { h: form } }] }));
    assert.ok(!out.includes(form), `${name} form survived`);
  });
}

test('scrubber leaves short secrets and unrelated text alone, and masks cookie values', () => {
  assert.deepEqual(makeScrubber([{ authType: 'bearer', secret: 'short' }])({ a: 'a short note' }), { a: 'a short note' });
  const c = makeScrubber([{ authType: 'cookie', secret: 'sid=abcdefghij1234; theme=dark' }]);
  assert.ok(!c('Cookie: sid=abcdefghij1234').includes('abcdefghij1234'));
  assert.equal(scrub('nothing secret here'), 'nothing secret here');
});
