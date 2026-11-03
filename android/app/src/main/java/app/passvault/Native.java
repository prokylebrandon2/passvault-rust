package app.passvault;

/** JNI entry points implemented in Rust (libpassvault.so). */
public final class Native {
    static {
        System.loadLibrary("passvault");
    }

    private Native() {}

    /** Autofill: a flattened description of the form in, a JSON decision out. */
    public static native String fill(String requestJson);

    /** Result of a document-picker request. status: 0 ok, 1 cancelled, 2 failed. data/name are null unless ok. */
    public static native void onFile(int code, int status, String name, byte[] data);

    /** Wipes the unlocked vault from memory. */
    public static native void lock();
}
