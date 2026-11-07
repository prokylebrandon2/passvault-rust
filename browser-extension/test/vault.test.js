import test from 'node:test';
import assert from 'node:assert/strict';
import { openVault, parseHeader } from '../src/vault.js';
import { sealVault, sealBundle } from './helpers.js';
import { parseOtp, totpCode, secondsLeft, groupCode } from '../src/totp.js';
import { urlMatches, hostOf } from '../src/match.js';

const entry = { id: 'a', title: 'GitHub', username: 'me', password: 'pw', url: 'https://github.com', otp: 'JBSWY3DPEHPK3PXP', notes: '' };

test('opens a vault with and without a key file', async () => {
  const kf = new Uint8Array(64).fill(7);
  const withKf = await sealVault([entry], 'correct horse', kf);
  assert.equal(parseHeader(withKf).keyFile, true);
  const back = await openVault(withKf, 'correct horse', kf);
  assert.equal(back.length, 1);
  assert.equal(back[0].title, 'GitHub');
  assert.equal(back[0].otp, 'JBSWY3DPEHPK3PXP');
  await assert.rejects(openVault(withKf, 'wrong', kf), { code: 'wrong-credentials' });
  await assert.rejects(openVault(withKf, 'correct horse', null), { code: 'key-file-required' });

  const plain = await sealVault([entry], 'password1', null);
  assert.equal((await openVault(plain, 'password1', null)).length, 1);
  await assert.rejects(openVault(plain, 'password1', kf), { code: 'key-file-not-used' });
});

test('rejects tampering and non-vault files', async () => {
  const v = await sealVault([entry], 'password1', null);
  const flipped = v.slice();
  flipped[flipped.length - 1] ^= 1;
  await assert.rejects(openVault(flipped, 'password1', null), { code: 'wrong-credentials' });
  const hdr = v.slice();
  hdr[9] ^= 1; // the header is authenticated
  await assert.rejects(openVault(hdr, 'password1', null));
  assert.throws(() => parseHeader(new TextEncoder().encode('not a vault file at all, no no no no no no no no no')), { code: 'not-a-vault' });
  const absurd = v.slice();
  new DataView(absurd.buffer).setUint32(10, 0xffffffff);
  assert.throws(() => parseHeader(absurd), { code: 'corrupt' });
});

test('opens a Silk backup (key slot + vault file) with and without a key file', async () => {
  const kf = new Uint8Array(64).fill(7);
  const withKf = await sealBundle([entry], 'correct horse', kf);
  assert.equal(parseHeader(withKf).kind, 'silk');
  assert.equal(parseHeader(withKf).keyFile, true);
  const back = await openVault(withKf, 'correct horse', kf);
  assert.equal(back.length, 1);
  assert.equal(back[0].title, 'GitHub');
  assert.equal(back[0].otp, 'JBSWY3DPEHPK3PXP');
  await assert.rejects(openVault(withKf, 'wrong', kf), { code: 'wrong-credentials' });
  await assert.rejects(openVault(withKf, 'correct horse', new Uint8Array(64)), { code: 'wrong-credentials' });
  await assert.rejects(openVault(withKf, 'correct horse', null), { code: 'key-file-required' });

  const plain = await sealBundle([entry], 'password1', null);
  assert.equal(parseHeader(plain).keyFile, false);
  assert.equal((await openVault(plain, 'password1', null)).length, 1);
  await assert.rejects(openVault(plain, 'password1', kf), { code: 'key-file-not-used' });
  // Old .pvlt files keep working next to the new kind.
  assert.equal(parseHeader(await sealVault([entry], 'password1', null)).kind, 'legacy');
});

test('rejects a tampered or truncated Silk backup', async () => {
  const b = await sealBundle([entry], 'password1', null);
  const SLOT_END = 5 + 91;
  const slot = b.slice();
  slot[5 + 20] ^= 1; // a salt byte: the key slot header is authenticated
  await assert.rejects(openVault(slot, 'password1', null), { code: 'wrong-credentials' });
  const wrapped = b.slice();
  wrapped[SLOT_END - 1] ^= 1; // the wrapped VEK
  await assert.rejects(openVault(wrapped, 'password1', null), { code: 'wrong-credentials' });
  const vault = b.slice();
  vault[vault.length - 1] ^= 1; // the vault file body: the password is right, the file was changed
  await assert.rejects(openVault(vault, 'password1', null), { code: 'corrupt' });
  const revision = b.slice();
  revision[SLOT_END + 13] ^= 1; // the revision is authenticated too
  await assert.rejects(openVault(revision, 'password1', null), { code: 'corrupt' });
  assert.throws(() => parseHeader(b.slice(0, 60)), { code: 'not-a-vault' });
  const wrongVersion = b.slice();
  wrongVersion[4] = 9;
  assert.throws(() => parseHeader(wrongVersion), { code: 'not-a-vault' });
  const absurd = b.slice();
  new DataView(absurd.buffer).setUint32(5 + 10, 0xffffffff);
  assert.throws(() => parseHeader(absurd), { code: 'corrupt' });
});

// RFC 6238 appendix B vectors (8 digits). The seeds are the ASCII strings "1234567890" repeated to 20, 32 and 64 bytes.
const b32 = (str) => {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of Buffer.from(str)) bits += c.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
};
const seed = (n) => '1234567890'.repeat(7).slice(0, n);

test('TOTP matches the RFC 6238 vectors', async () => {
  const link = (n, algo) => `otpauth://totp/x?secret=${b32(seed(n))}&digits=8${algo ? `&algorithm=${algo}` : ''}`;
  const sha1 = parseOtp(link(20));
  const sha256 = parseOtp(link(32, 'SHA256'));
  const sha512 = parseOtp(link(64, 'SHA512'));
  assert.equal(await totpCode(sha1, 59), '94287082');
  assert.equal(await totpCode(sha1, 1111111109), '07081804');
  assert.equal(await totpCode(sha1, 20000000000), '65353130');
  assert.equal(await totpCode(sha256, 59), '46119246');
  assert.equal(await totpCode(sha512, 59), '90693936');
  assert.equal(secondsLeft(sha1, 59), 1);
  assert.equal(groupCode('123456'), '123 456');
  assert.equal(groupCode('12345678'), '1234 5678');
});

test('OTP input handling', () => {
  assert.equal(parseOtp(''), null);
  assert.equal(parseOtp('not base32 !!'), null);
  assert.deepEqual(parseOtp('jbsw y3dp-ehpk 3pxp').secret, parseOtp('JBSWY3DPEHPK3PXP').secret);
  assert.equal(parseOtp('otpauth://totp/Acme:me?issuer=Acme&secret=JBSWY3DPEHPK3PXP&period=60').period, 60);
  assert.equal(parseOtp('otpauth://totp/x'), null);
});

test('URL matching follows the app', () => {
  assert.ok(urlMatches('github.com', 'https://github.com/login'));
  assert.ok(urlMatches('https://www.github.com/a?b', 'https://gist.github.com/'));
  assert.ok(urlMatches('https://github.com:8443', 'https://www.github.com/'));
  assert.ok(!urlMatches('https://github.com', 'https://evilgithub.com/'));
  assert.ok(!urlMatches('https://github.com', 'https://github.com.evil.io/'));
  assert.ok(!urlMatches('', 'https://github.com'));
  assert.ok(!urlMatches('androidapp://com.example.app', 'https://example.com'));
  assert.ok(!urlMatches('https://github.com', 'chrome://settings'));
  assert.equal(hostOf('https://user@Example.com:81/x'), 'example.com');
});
