package com.example.adblocker; // change to match your package

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import java.util.List;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private TextView statusText, upstreamText, stoppedCount, seenCount, streamText, healthText;
    private Button   toggleButton;

    private int cAmber, cText, cMuted, cInk;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Runnable tick = new Runnable() {
        @Override public void run() {
            render();
            ui.postDelayed(this, 1000);
        }
    };

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context ctx, Intent intent) {
            render();
        }
    };

    private final ActivityResultLauncher<Intent> vpnConsent =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == RESULT_OK) startVpnService();
                        else Toast.makeText(this, "Blocking needs VPN permission to see DNS",
                                Toast.LENGTH_SHORT).show();
                    });

    // -------------------------------------------------------------------------

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        cAmber = getColor(R.color.amber);
        cText  = getColor(R.color.text);
        cMuted = getColor(R.color.muted);
        cInk   = getColor(R.color.ink);

        statusText   = findViewById(R.id.statusText);
        upstreamText = findViewById(R.id.upstreamText);
        stoppedCount = findViewById(R.id.stoppedCount);
        seenCount    = findViewById(R.id.seenCount);
        streamText   = findViewById(R.id.streamText);
        healthText   = findViewById(R.id.healthText);
        toggleButton = findViewById(R.id.toggleButton);

        toggleButton.setOnClickListener(v -> {
            if (AdBlockVpnService.isRunning) stopVpnService();
            else requestConsent();
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        IntentFilter f = new IntentFilter();
        f.addAction(AdBlockVpnService.ACTION_VPN_STARTED);
        f.addAction(AdBlockVpnService.ACTION_VPN_STOPPED);
        f.addAction(AdBlockVpnService.ACTION_STATS_UPDATE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, f, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(statusReceiver, f);
        }
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        super.onPause();
        unregisterReceiver(statusReceiver);
        ui.removeCallbacks(tick);
    }

    // -------------------------------------------------------------------------
    // VPN control
    // -------------------------------------------------------------------------

    private void requestConsent() {
        Intent consent = VpnService.prepare(this);
        if (consent != null) vpnConsent.launch(consent);
        else startVpnService();
    }

    private void startVpnService() {
        startService(new Intent(this, AdBlockVpnService.class)
                .setAction(AdBlockVpnService.ACTION_START));
        statusText.setText("STARTING");
        upstreamText.setText("finding a resolver that answers");
        toggleButton.setEnabled(false);
    }

    private void stopVpnService() {
        startService(new Intent(this, AdBlockVpnService.class)
                .setAction(AdBlockVpnService.ACTION_STOP));
    }

    // -------------------------------------------------------------------------
    // Render
    // -------------------------------------------------------------------------

    private void render() {
        boolean on = AdBlockVpnService.isRunning;

        statusText.setText(on ? "BLOCKING" : "OFF");
        statusText.setTextColor(on ? cText : cMuted);

        upstreamText.setText(on
                ? "resolving via " + AdBlockVpnService.upstreamInfo
                : "tap below to start");

        stoppedCount.setText(String.valueOf(AdBlockVpnService.blockedCount.get()));
        seenCount.setText(String.valueOf(AdBlockVpnService.queriesSeen.get()));

        // Loud when there's something to do, quiet once it's working.
        toggleButton.setEnabled(true);
        toggleButton.setText(on ? "Stop" : "Start blocking");
        toggleButton.setBackgroundResource(on ? R.drawable.pill_outline : R.drawable.pill_filled);
        toggleButton.setTextColor(on ? cMuted : cInk);

        renderStream(on);
        renderHealth(on);
    }

    /** The live feed. Every domain the tunnel saw, newest first, with its verdict. */
    private void renderStream(boolean on) {
        List<AdBlockVpnService.Event> events = AdBlockVpnService.recent();

        if (events.isEmpty()) {
            streamText.setTextColor(cMuted);
            streamText.setText(on ? "waiting for the first lookup" : "");
            return;
        }

        SpannableStringBuilder sb = new SpannableStringBuilder();
        for (AdBlockVpnService.Event e : events) {
            String d = e.domain.length() > 34 ? e.domain.substring(0, 33) + "\u2026" : e.domain;
            int start = sb.length();
            sb.append(e.blocked ? "\u00d7  " : "\u00b7  ").append(d).append("\n");
            sb.setSpan(new ForegroundColorSpan(e.blocked ? cAmber : cMuted),
                    start, sb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }
        streamText.setText(sb);
    }

    /** Kept from the debugging build -- it's how we found the DNS bug, so it stays. */
    private void renderHealth(boolean on) {
        if (!on) { healthText.setText(""); return; }
        healthText.setText(String.format(Locale.US,
                "answered %d   timeouts %d   errors %d",
                AdBlockVpnService.answered.get(),
                AdBlockVpnService.timeouts.get(),
                AdBlockVpnService.errors.get()));
    }
}
