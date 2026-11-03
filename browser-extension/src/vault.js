// Opens a PassVault file (core/src/vault.rs): "PVLT" | version | flags | t | memKiB | p | salt[16],
// then nonce[12] and AES-256-GCM(ciphertext + tag). The key is
// Argon2id( SHA-256(password) [then SHA-256(that || SHA-256(key file))] ) with the header's salt.
import { argon2, TYPES } from './argon2.js';

const HEADER_LEN = 31;
const NONCE_LEN = 12;
const TAG_LEN = 16;

export class VaultError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export function parseHeader(f) {
  if (f.length < HEADER_LEN + NONCE_LEN + TAG_LEN || f[0] !== 0x50 || f[1] !== 0x56 || f[2] !== 0x4c || f[3] !== 0x54 || f[4] !== 1) {
    throw new VaultError('not-a-vault', "This isn't a PassVault file.");
  }
  const dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  const t = dv.getUint32(6);
  const m = dv.getUint32(10);
  const p = f[14];
  // Same limits as the app: a crafted file must not be able to exhaust memory.
  if (t < 1 || t > 32 || m < 8 || m > 1 << 18 || p < 1 || p > 16) {
    throw new VaultError('corrupt', 'The vault file is damaged.');
  }
  return { keyFile: (f[5] & 1) === 1, t, m, p, salt: f.slice(15, 31) };
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function deriveKey(password, keyFile, header, onProgress) {
  let ikm = await sha256(new TextEncoder().encode(password));
  if (keyFile) {
    const kf = await sha256(keyFile);
    const both = new Uint8Array(64);
    both.set(ikm, 0);
    both.set(kf, 32);
    ikm = await sha256(both);
  }
  return argon2(ikm, header.salt, { t: header.t, m: header.m, p: header.p, len: 32, type: TYPES.argon2id }, onProgress);
}

/** Decrypts the file and returns the list of logins. Throws VaultError with a code the UI can act on. */
export async function openVault(file, password, keyFile, onProgress) {
  const header = parseHeader(file);
  if (header.keyFile && !keyFile) throw new VaultError('key-file-required', 'This vault needs its key file. Choose it and try again.');
  if (!header.keyFile && keyFile) throw new VaultError('key-file-not-used', "This vault doesn't use a key file. Clear the key file and try again.");
  const key = await deriveKey(password, keyFile, header, onProgress);
  const aad = file.subarray(0, HEADER_LEN);
  const nonce = file.subarray(HEADER_LEN, HEADER_LEN + NONCE_LEN);
  const body = file.subarray(HEADER_LEN + NONCE_LEN);
  let plain;
  try {
    const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, body));
  } catch {
    throw new VaultError('wrong-credentials', 'Wrong password or key file. Check both and try again.');
  }
  let doc;
  try {
    doc = JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw new VaultError('corrupt', 'The vault file is damaged.');
  }
  plain.fill(0);
  return (doc.entries || []).map((e) => ({
    id: String(e.id ?? ''),
    title: String(e.title ?? ''),
    username: String(e.username ?? ''),
    password: String(e.password ?? ''),
    url: String(e.url ?? ''),
    otp: String(e.otp ?? ''),
    notes: String(e.notes ?? ''),
  }));
}

export function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export const fromBase64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
