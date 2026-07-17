package com.example.adblocker; // change to match your package

import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class AdBlockVpnService extends VpnService {

    private static final String TAG = "AdBlockVpn";

    // Intent actions
    public static final String ACTION_START        = "com.example.adblocker.START";
    public static final String ACTION_STOP         = "com.example.adblocker.STOP";

    // Broadcast actions the Activity listens for
    public static final String ACTION_VPN_STARTED  = "com.example.adblocker.VPN_STARTED";
    public static final String ACTION_VPN_STOPPED  = "com.example.adblocker.VPN_STOPPED";
    public static final String ACTION_STATS_UPDATE = "com.example.adblocker.STATS_UPDATE";
    public static final String EXTRA_BLOCKED       = "blocked_count";

    private static final String TUN_ADDRESS  = "10.0.0.2";
    private static final String FAKE_DNS     = "10.0.0.1";
    private static final String UPSTREAM_DNS = "8.8.8.8";

    // Static fields read directly by MainActivity to sync UI on resume
    // without needing a bound service or a broadcast.
    public static volatile boolean     isRunning    = false;
    public static final AtomicInteger  blockedCount = new AtomicInteger(0);

    private ParcelFileDescriptor tunInterface;
    private Thread               vpnThread;
    private Set<String>          blocklist = new HashSet<>();

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationHelper.createChannel(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }

        // Android requires startForeground() within 5 seconds of startService().
        // Do it right here on the main thread, before we touch the background thread.
        startFgCompat(NotificationHelper.build(this, 0, /* loading= */ true));
        startVpn();
        return START_STICKY;
    }

    /** Handles the API-34 foreground service type requirement. */
    private void startFgCompat(android.app.Notification n) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NotificationHelper.NOTIFICATION_ID, n,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NotificationHelper.NOTIFICATION_ID, n);
        }
    }

    @Override
    public void onRevoke() {
        // Called by the OS when another VPN app takes over, or the user
        // revokes permission from system settings.
        stopVpn();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    // -------------------------------------------------------------------------
    // VPN thread
    // -------------------------------------------------------------------------

    private void startVpn() {
        if (vpnThread != null) return; // already running
        blockedCount.set(0);
        vpnThread = new Thread(this::runVpn, "AdBlockVpnThread");
        vpnThread.start();
    }

    private void runVpn() {
        DatagramSocket upstream = null;
        try {
            // Blocklist loads before the tunnel opens -- so the download itself
            // doesn't travel through our own VPN.
            blocklist = new BlocklistManager(this).load();
            Log.i(TAG, "Blocklist ready: " + blocklist.size() + " domains");

            // Swap the "Loading…" notification for the live one.
            NotificationHelper.update(this, 0);

            Builder builder = new Builder();
            builder.setSession("AdBlocker")
                    .addAddress(TUN_ADDRESS, 32)
                    .addDnsServer(FAKE_DNS)
                    .addRoute(FAKE_DNS, 32);

            tunInterface = builder.establish();
            if (tunInterface == null) {
                // This happens if the user revoked consent between prepare() and now.
                Log.e(TAG, "establish() returned null -- consent gone");
                stopSelf();
                return;
            }
            Log.i(TAG, "Tunnel up");

            isRunning = true;
            broadcast(ACTION_VPN_STARTED);

            FileInputStream  in  = new FileInputStream(tunInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(tunInterface.getFileDescriptor());

            upstream = new DatagramSocket();
            protect(upstream);          // keep upstream traffic out of the tunnel
            upstream.setSoTimeout(5000);

            byte[] buf = new byte[32767];
            // read() blocks until a packet arrives. Closing tunInterface (in
            // stopVpn) makes read() throw IOException, which is the clean exit.
            while (!Thread.interrupted()) {
                int len = in.read(buf);
                if (len > 0) handlePacket(buf, len, out, upstream);
            }
        } catch (Exception e) {
            Log.i(TAG, "VPN loop ended: " + e.getMessage());
        } finally {
            if (upstream != null) upstream.close();
            closeTun();
            isRunning = false;
            stopForeground(true);
            broadcast(ACTION_VPN_STOPPED);
            stopSelf();
        }
    }

    // -------------------------------------------------------------------------
    // Packet handling
    // -------------------------------------------------------------------------

    private void handlePacket(byte[] packet, int length,
                              FileOutputStream out, DatagramSocket upstream) {
        try {
            // Check IPv4
            if ((packet[0] & 0xF0) >> 4 != 4) return;

            int ipHeaderLen = (packet[0] & 0x0F) * 4;

            // Check UDP (protocol 17)
            if ((packet[9] & 0xFF) != 17) return;

            int udp     = ipHeaderLen;
            int dstPort = ((packet[udp + 2] & 0xFF) << 8) | (packet[udp + 3] & 0xFF);
            if (dstPort != 53) return; // only intercept DNS

            int udpLen   = ((packet[udp + 4] & 0xFF) << 8) | (packet[udp + 5] & 0xFF);
            int dnsStart = udp + 8;
            int dnsLen   = udpLen - 8;
            if (dnsLen <= 12) return;  // DNS header only, no question section

            String domain = DnsPacket.extractDomain(packet, dnsStart, dnsLen);
            if (domain == null) return;

            if (isBlocked(domain)) {
                Log.d(TAG, "BLOCKED " + domain);
                int n = blockedCount.incrementAndGet();

                // Update the notification every 20 blocks so it doesn't
                // flood the NotificationManager.
                if (n % 20 == 0) NotificationHelper.update(this, n);

                // Return NXDOMAIN -- the app thinks the domain doesn't exist.
                byte[] dnsResp = DnsPacket.buildNxDomain(packet, dnsStart, dnsLen);
                byte[] reply   = DnsPacket.buildResponsePacket(packet, ipHeaderLen, dnsResp);
                out.write(reply);

                // Tell the UI.
                Intent i = new Intent(ACTION_STATS_UPDATE).setPackage(getPackageName());
                i.putExtra(EXTRA_BLOCKED, n);
                sendBroadcast(i);

            } else {
                forwardAndReply(packet, ipHeaderLen, dnsStart, dnsLen, out, upstream);
            }
        } catch (Exception e) {
            Log.w(TAG, "Dropped packet: " + e.getMessage());
        }
    }

    /**
     * Match domain and every parent so one blocklist entry covers all subdomains.
     * "doubleclick.net" -> also blocks "ad3.doubleclick.net".
     */
    private boolean isBlocked(String domain) {
        String d = domain;
        while (d != null) {
            if (blocklist.contains(d)) return true;
            int dot = d.indexOf('.');
            d = (dot == -1) ? null : d.substring(dot + 1);
        }
        return false;
    }

    /**
     * Forward a non-blocked query to the real resolver and relay its answer back.
     * Synchronous (one at a time). Suitable for personal use; a production build
     * would use a thread pool or coroutines to handle concurrent lookups.
     */
    private void forwardAndReply(byte[] packet, int ipHeaderLen,
                                 int dnsStart, int dnsLen,
                                 FileOutputStream out, DatagramSocket upstream) {
        try {
            byte[] query = new byte[dnsLen];
            System.arraycopy(packet, dnsStart, query, 0, dnsLen);

            InetAddress server = InetAddress.getByName(UPSTREAM_DNS);
            upstream.send(new DatagramPacket(query, dnsLen, server, 53));

            byte[] buf  = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            upstream.receive(resp);

            byte[] dnsResp = Arrays.copyOf(buf, resp.getLength());
            byte[] reply   = DnsPacket.buildResponsePacket(packet, ipHeaderLen, dnsResp);
            out.write(reply);
        } catch (SocketTimeoutException e) {
            Log.w(TAG, "Upstream DNS timed out");
        } catch (Exception e) {
            Log.w(TAG, "Forward failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void broadcast(String action) {
        // setPackage() restricts delivery to this app only -- no other app
        // can receive or inject these broadcasts.
        sendBroadcast(new Intent(action).setPackage(getPackageName()));
    }

    private void stopVpn() {
        Thread t = vpnThread;
        vpnThread = null;
        if (t != null) t.interrupt();
        closeTun(); // closing the file descriptor unblocks in.read()
    }

    private void closeTun() {
        ParcelFileDescriptor pfd = tunInterface;
        tunInterface = null;
        if (pfd != null) {
            try { pfd.close(); } catch (Exception ignored) {}
        }
    }
}
