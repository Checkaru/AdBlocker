package com.example.adblocker; // change to match your package

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private TextView statusText;
    private TextView blockedText;
    private Button   startButton;
    private Button   stopButton;

    // Receives start / stop / stats broadcasts from AdBlockVpnService.
    // Registered in onResume, unregistered in onPause -- no leaks.
    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            if (intent.getAction() == null) return;
            switch (intent.getAction()) {
                case AdBlockVpnService.ACTION_VPN_STARTED:
                    setUiState(true, AdBlockVpnService.blockedCount.get());
                    break;
                case AdBlockVpnService.ACTION_VPN_STOPPED:
                    setUiState(false, 0);
                    break;
                case AdBlockVpnService.ACTION_STATS_UPDATE:
                    int n = intent.getIntExtra(AdBlockVpnService.EXTRA_BLOCKED, 0);
                    blockedText.setText("Blocked this session: " + n);
                    break;
            }
        }
    };

    // Modern replacement for the deprecated startActivityForResult().
    // Must be registered as a field, before onCreate() runs.
    private final ActivityResultLauncher<Intent> vpnConsent =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == RESULT_OK) startVpnService();
                        else Toast.makeText(this, "VPN permission denied",
                                Toast.LENGTH_SHORT).show();
                    });

    // -------------------------------------------------------------------------
    // Activity lifecycle
    // -------------------------------------------------------------------------

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText  = findViewById(R.id.statusText);
        blockedText = findViewById(R.id.blockedText);
        startButton = findViewById(R.id.startButton);
        stopButton  = findViewById(R.id.stopButton);

        startButton.setOnClickListener(v -> requestConsent());
        stopButton.setOnClickListener(v -> stopVpnService());
    }

    @Override
    protected void onResume() {
        super.onResume();

        // Register for all three service broadcasts.
        IntentFilter filter = new IntentFilter();
        filter.addAction(AdBlockVpnService.ACTION_VPN_STARTED);
        filter.addAction(AdBlockVpnService.ACTION_VPN_STOPPED);
        filter.addAction(AdBlockVpnService.ACTION_STATS_UPDATE);

        // API 33+ requires an explicit export flag. NOT_EXPORTED means
        // only our own app can deliver to this receiver -- correct here
        // since the broadcasts are also sent with setPackage().
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(statusReceiver, filter);
        }

        // Sync with real state in case we missed broadcasts while paused
        // (e.g., user opens app after VPN was already running).
        boolean running = AdBlockVpnService.isRunning;
        setUiState(running, running ? AdBlockVpnService.blockedCount.get() : 0);
    }

    @Override
    protected void onPause() {
        super.onPause();
        unregisterReceiver(statusReceiver);
    }

    // -------------------------------------------------------------------------
    // VPN consent & control
    // -------------------------------------------------------------------------

    private void requestConsent() {
        // prepare() returns an Intent if we need to show the consent dialog,
        // or null if the user already approved this app as a VPN provider.
        Intent consentIntent = VpnService.prepare(this);
        if (consentIntent != null) vpnConsent.launch(consentIntent);
        else startVpnService();
    }

    private void startVpnService() {
        startService(new Intent(this, AdBlockVpnService.class)
                .setAction(AdBlockVpnService.ACTION_START));
        // Optimistic UI: show "Loading" while the blocklist downloads.
        // ACTION_VPN_STARTED broadcast will correct it when the tunnel is up.
        statusText.setText("Loading blocklist\u2026");
        blockedText.setText("");
        startButton.setEnabled(false);
        stopButton.setEnabled(false);
    }

    private void stopVpnService() {
        startService(new Intent(this, AdBlockVpnService.class)
                .setAction(AdBlockVpnService.ACTION_STOP));
    }

    // -------------------------------------------------------------------------
    // UI state
    // -------------------------------------------------------------------------

    private void setUiState(boolean running, int blocked) {
        statusText.setText(running ? "Ad Blocker is running" : "Ad Blocker is off");
        blockedText.setText(running ? "Blocked this session: " + blocked : "");
        startButton.setEnabled(!running);
        stopButton.setEnabled(running);
    }
}
