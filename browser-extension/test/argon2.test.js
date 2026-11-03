import test from 'node:test';
import assert from 'node:assert/strict';
import { argon2, blake2b, TYPES } from '../src/argon2.js';

const hex = (u8) => Buffer.from(u8).toString('hex');
const fill = (n, b) => new Uint8Array(n).fill(b);

test('BLAKE2b matches node for several lengths', async () => {
  const { createHash } = await import('node:crypto');
  for (const n of [0, 1, 3, 127, 128, 129, 255, 256, 1000]) {
    const data = new Uint8Array(n).map((_, i) => (i * 7 + 3) & 255);
    assert.equal(hex(blake2b(data, 64)), createHash('blake2b512').update(data).digest('hex'), `length ${n}`);
  }
});

// RFC 9106 section 5: password 0x01 x32, salt 0x02 x16, secret 0x03 x8, AD 0x04 x12, t=3, m=32 KiB, p=4, 32-byte tag.
const base = { t: 3, m: 32, p: 4, len: 32, secret: fill(8, 3), ad: fill(12, 4) };
const vectors = {
  argon2d: '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
  argon2i: 'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
  argon2id: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
};
for (const [name, expected] of Object.entries(vectors)) {
  test(`RFC 9106 ${name} test vector`, () => {
    const tag = argon2(fill(32, 1), fill(16, 2), { ...base, type: TYPES[name] });
    assert.equal(hex(tag), expected);
  });
}
