// Builds a vault file exactly the way core/src/vault.rs does, so the extension can be tested without the app.
import { argon2, TYPES } from '../src/argon2.js';

export async function sealVault(entries, password, keyFile, kdf = { t: 1, m: 64, p: 1 }) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const header = new Uint8Array(31);
  header.set([0x50, 0x56, 0x4c, 0x54, 1, keyFile ? 1 : 0]);
  const dv = new DataView(header.buffer);
  dv.setUint32(6, kdf.t);
  dv.setUint32(10, kdf.m);
  header[14] = kdf.p;
  header.set(salt, 15);

  const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
  let ikm = await sha(new TextEncoder().encode(password));
  if (keyFile) {
    const both = new Uint8Array(64);
    both.set(ikm, 0);
    both.set(await sha(keyFile), 32);
    ikm = await sha(both);
  }
  const key = argon2(ikm, salt, { ...kdf, len: 32, type: TYPES.argon2id });
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const body = new TextEncoder().encode(JSON.stringify({ entries }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: 128 }, k, body));
  const out = new Uint8Array(31 + 12 + ct.length);
  out.set(header, 0);
  out.set(nonce, 31);
  out.set(ct, 43);
  return out;
}
