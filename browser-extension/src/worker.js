// Argon2 takes a few seconds, so the unlock runs here and the popup stays responsive.
import { openVault, VaultError } from './vault.js';

self.onmessage = async (ev) => {
  const { file, password, keyFile } = ev.data;
  try {
    const entries = await openVault(file, password, keyFile, (f) => self.postMessage({ progress: f }));
    self.postMessage({ entries });
  } catch (e) {
    self.postMessage({ error: e instanceof VaultError ? { code: e.code, message: e.message } : { code: 'failed', message: 'Couldn’t open the vault.' } });
  }
};
