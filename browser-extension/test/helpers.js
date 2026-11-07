// Builds vault files exactly the way the app does (core/src/vault.rs for old files, core/src/backup.rs +
// keyslot.rs + interim.rs for backups), so the extension can be tested without the app.
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

/** A Silk backup: "SKBK" | 1 | key slot[91] | vault file. The VEK is random; the Argon2id key only wraps it. */
export async function sealBundle(entries, password, keyFile, kdf = { t: 1, m: 64, p: 1 }, revision = 1) {
  const sha = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
  const gcm = async (key, iv, aad, data) => {
    const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, data));
  };
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  };

  // key slot
  const vek = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const slotHeader = new Uint8Array(31);
  slotHeader.set([0x53, 0x4b, 0x56, 0x4b, 1, keyFile ? 1 : 0]);
  const sdv = new DataView(slotHeader.buffer);
  sdv.setUint32(6, kdf.t);
  sdv.setUint32(10, kdf.m);
  slotHeader[14] = kdf.p;
  slotHeader.set(salt, 15);
  let ikm = await sha(new TextEncoder().encode(password));
  if (keyFile) ikm = await sha(concat(ikm, await sha(keyFile)));
  const kek = argon2(ikm, salt, { ...kdf, len: 32, type: TYPES.argon2id });
  const slotNonce = crypto.getRandomValues(new Uint8Array(12));
  const slot = concat(slotHeader, slotNonce, await gcm(kek, slotNonce, slotHeader, vek));

  // archive with one member, then the vault file
  const name = new TextEncoder().encode('vault.json');
  const body = new TextEncoder().encode(JSON.stringify({ entries }));
  const head = new Uint8Array(4 + 2);
  new DataView(head.buffer).setUint32(0, 1);
  new DataView(head.buffer).setUint16(4, name.length);
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, body.length);
  const archive = concat(head, name, len, body);
  const vaultHeader = new Uint8Array(14);
  vaultHeader.set([0x53, 0x4b, 0x49, 0x4d, 1, 0]);
  new DataView(vaultHeader.buffer).setBigUint64(6, BigInt(revision));
  const vaultNonce = crypto.getRandomValues(new Uint8Array(12));
  const vault = concat(vaultHeader, vaultNonce, await gcm(vek, vaultNonce, vaultHeader, archive));

  return concat(new Uint8Array([0x53, 0x4b, 0x42, 0x4b, 1]), slot, vault);
}
