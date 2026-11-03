package app.passvault;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

/** Locks the vault whenever the screen turns off. */
public class PvApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                try {
                    Native.lock();
                } catch (Throwable ignored) {
                    // library not loaded in this process: nothing to lock
                }
            }
        }, new IntentFilter(Intent.ACTION_SCREEN_OFF));
    }
}
