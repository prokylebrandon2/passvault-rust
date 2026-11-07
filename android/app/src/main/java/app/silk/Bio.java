package app.silk;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Wraps the VEK (the vault encryption key, see core/src/keyslot.rs) with a Keystore key that needs a strong biometric (or the phone lock screen credential on Android 11+) for every use. Everything is gated by available(). */
@SuppressLint("NewApi")
final class Bio {
    // Shared with ui.rs.
    static final int ENROLL = 1, UNLOCK = 2;
    static final int OK = 0, CANCELLED = 1, FAILED = 2, INVALIDATED = 3;

    private static final String ALIAS = "silk_bio_v1";
    private static final String PREFS = "silk_bio";
    private static final int ERR_CANCELED = 5, ERR_USER_CANCELED = 10; // BiometricConstants

    private final Activity act;

    Bio(Activity a) {
        act = a;
    }

    private SharedPreferences prefs() {
        return act.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    boolean available() {
        if (Build.VERSION.SDK_INT < 29) return false;
        BiometricManager bm = act.getSystemService(BiometricManager.class);
        if (bm == null) return false;
        int r = Build.VERSION.SDK_INT >= 30
                ? bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                : bm.canAuthenticate();
        return r == BiometricManager.BIOMETRIC_SUCCESS;
    }

    boolean enrolled() {
        SharedPreferences p = prefs();
        return p.contains("ct") && p.contains("iv");
    }

    private SecretKey key(boolean create) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Key k = ks.getKey(ALIAS, null);
        if (k != null) return (SecretKey) k;
        if (!create) throw new IllegalStateException("no key");
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true) // per-use auth: no validity window
                .setInvalidatedByBiometricEnrollment(true);
        if (Build.VERSION.SDK_INT >= 30) {
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        }
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        g.init(b.build());
        return g.generateKey();
    }

    private interface Done {
        void ok(Cipher c);
        void end(int status);
    }

    private void auth(Cipher cipher, String title, Done d) {
        BiometricPrompt.Builder b = new BiometricPrompt.Builder(act).setTitle(title);
        if (Build.VERSION.SDK_INT >= 30) {
            // Fingerprint, or the phone's lock screen PIN, pattern or password. Back out of the prompt to use the master password.
            b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        } else {
            b.setNegativeButton("Use master password", act.getMainExecutor(), (dlg, which) -> d.end(CANCELLED));
        }
        b.build().authenticate(new BiometricPrompt.CryptoObject(cipher), new CancellationSignal(),
                act.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                        d.ok(r.getCryptoObject().getCipher());
                    }

                    @Override
                    public void onAuthenticationError(int code, CharSequence msg) {
                        d.end(code == ERR_CANCELED || code == ERR_USER_CANCELED ? CANCELLED : FAILED);
                    }
                });
    }

    private static String b64(byte[] b) {
        return Base64.encodeToString(b, Base64.NO_WRAP);
    }

    private static byte[] b64d(String s) {
        return Base64.decode(s, Base64.NO_WRAP);
    }

    /** Takes ownership of vaultKey and wipes it when done. Result arrives via Native.onBio. */
    void enroll(final byte[] vaultKey) {
        act.runOnUiThread(() -> {
            try {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, key(true));
                auth(c, "Turn on biometric unlock", new Done() {
                    @Override
                    public void ok(Cipher cipher) {
                        int status = FAILED;
                        try {
                            byte[] ct = cipher.doFinal(vaultKey);
                            boolean saved = prefs().edit().putString("ct", b64(ct)).putString("iv", b64(cipher.getIV())).commit();
                            status = saved ? OK : FAILED;
                        } catch (Exception ignored) {
                        } finally {
                            Arrays.fill(vaultKey, (byte) 0);
                        }
                        if (status != OK) disable();
                        Native.onBio(ENROLL, status, null);
                    }

                    @Override
                    public void end(int status) {
                        Arrays.fill(vaultKey, (byte) 0);
                        disable();
                        Native.onBio(ENROLL, status, null);
                    }
                });
            } catch (Exception e) {
                Arrays.fill(vaultKey, (byte) 0);
                disable();
                Native.onBio(ENROLL, FAILED, null);
            }
        });
    }

    /** Result arrives via Native.onBio with the VEK on success. */
    void unlock() {
        act.runOnUiThread(() -> {
            if (!enrolled()) {
                Native.onBio(UNLOCK, FAILED, null);
                return;
            }
            try {
                final byte[] ct = b64d(prefs().getString("ct", ""));
                final byte[] iv = b64d(prefs().getString("iv", ""));
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, key(false), new GCMParameterSpec(128, iv));
                auth(c, "Unlock Silk", new Done() {
                    @Override
                    public void ok(Cipher cipher) {
                        byte[] k = null;
                        try {
                            k = cipher.doFinal(ct);
                            Native.onBio(UNLOCK, OK, k);
                        } catch (Exception e) {
                            Native.onBio(UNLOCK, FAILED, null);
                        } finally {
                            if (k != null) Arrays.fill(k, (byte) 0);
                        }
                    }

                    @Override
                    public void end(int status) {
                        Native.onBio(UNLOCK, status, null);
                    }
                });
            } catch (KeyPermanentlyInvalidatedException | IllegalStateException e) {
                disable(); // biometrics changed, or the key is gone
                Native.onBio(UNLOCK, INVALIDATED, null);
            } catch (Exception e) {
                Native.onBio(UNLOCK, FAILED, null);
            }
        });
    }

    void disable() {
        prefs().edit().clear().commit();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            ks.deleteEntry(ALIAS);
        } catch (Exception ignored) {
        }
    }
}
