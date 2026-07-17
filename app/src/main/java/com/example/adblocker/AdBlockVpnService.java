package com.example.adblocker; // change to match your package

import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public class AdBlockVpnService extends VpnService {

    private static final String TAG = "AdBlockVpn";

    public static final String ACTION_START        = "com.example.adblocker.START";
    public static final String ACTION_STOP         = "com.example.adblocker.STOP";
    public static final String ACTION_VPN_STARTED  = "com.example.adblocker.VPN_STARTED";
    public static final String ACTION_VPN_STOPPED  = "com.example.adblocker.VPN_STOPPED";
    public static final String ACTION_STATS_UPDATE = "com.example.adblocker.STATS_UPDATE";
    public static final String EXTRA_BLOCKED       = "blocked_count";

    private static final String TUN_ADDRESS  = "10.0.0.2";
    private static final String FAKE_DNS     = "10.0.0.1";
    /** Tried only if the network hands us nothing usable. */
    private static final String[] FALLBACK_DNS = {"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"};

    private static final int DNS_TIMEOUT_MS = 4000;
    private static final int POOL_SIZE      = 16; // concurrent DNS lookups

    public static volatile boolean    isRunning    = false;
    public static final AtomicInteger blockedCount = new AtomicInteger(0);

    // --- live diagnostics, read by MainActivity ---
    public static final AtomicInteger packetsRead = new AtomicInteger(0);
    public static final AtomicInteger queriesSeen = new AtomicInteger(0);
    public static final AtomicInteger forwarded   = new AtomicInteger(0);
    public static final AtomicInteger answered    = new AtomicInteger(0);
    public static final AtomicInteger timeouts    = new AtomicInteger(0);
    public static final AtomicInteger errors      = new AtomicInteger(0);
    public static volatile String upstreamInfo = "-";
    public static volatile String lastDomain = "-";
    public static volatile String lastError  = "-";

    public static void resetStats() {
        blockedCount.set(0); packetsRead.set(0); queriesSeen.set(0);
        forwarded.set(0); answered.set(0); timeouts.set(0); errors.set(0);
        lastDomain = "-"; lastError = "-";
    }

    /**
     * Domains that are never blocked, even if a blocklist contains them.
     * Add anything here that a blocklist breaks -- parent matching applies,
     * so "example.com" also allows "api.example.com".
     */
    private static final Set<String> ALLOWLIST = new HashSet<>();
    static {
        // Uncomment or add entries if a blocklist breaks an app you need.
        // ALLOWLIST.add("app-measurement.com");   // Firebase Analytics
        // ALLOWLIST.add("crashlytics.com");       // Firebase Crashlytics
    }

    private ParcelFileDescriptor tunInterface;
    private Thread               vpnThread;
    private ExecutorService      dnsPool;
    private volatile InetAddress upstream;    // the resolver that actually answers
    private volatile Network     underlying;  // the real (non-VPN) network
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
        startFgCompat(NotificationHelper.build(this, 0, true));
        startVpn();
        return START_STICKY;
    }

    private void startFgCompat(android.app.Notification n) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NotificationHelper.NOTIFICATION_ID, n,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NotificationHelper.NOTIFICATION_ID, n);
        }
    }

    @Override
    public void onRevoke() { stopVpn(); stopSelf(); }

    @Override
    public void onDestroy() { stopVpn(); super.onDestroy(); }

    // -------------------------------------------------------------------------
    // VPN thread
    // -------------------------------------------------------------------------

    private void startVpn() {
        if (vpnThread != null) return;
        resetStats();
        vpnThread = new Thread(this::runVpn, "AdBlockVpnThread");
        vpnThread.start();
    }

    private void runVpn() {
        try {
            blocklist = new BlocklistManager(this).load();
            Log.i(TAG, "Blocklist ready: " + blocklist.size() + " domains");
            NotificationHelper.update(this, 0);

            // Do this BEFORE establish(): with no tunnel up yet, these probes
            // go out over the normal network with nothing to interfere.
            underlying = pickUnderlying();
            upstream   = pickUpstream(underlying);
            if (upstream == null) {
                upstreamInfo = "none reachable";
                lastError = "no DNS server answered";
                Log.e(TAG, "No upstream DNS answered -- refusing to start");
                stopSelf();
                return;
            }
            upstreamInfo = upstream.getHostAddress();
            Log.i(TAG, "Upstream DNS: " + upstreamInfo);

            Builder builder = new Builder();
            if (underlying != null) builder.setUnderlyingNetworks(new Network[]{underlying});
            builder.setSession("AdBlocker")
                    .setMtu(1500)
                    .addAddress(TUN_ADDRESS, 32)
                    .addDnsServer(FAKE_DNS)
                    .addRoute(FAKE_DNS, 32);

            tunInterface = builder.establish();
            if (tunInterface == null) {
                Log.e(TAG, "establish() returned null -- consent gone");
                stopSelf();
                return;
            }
            Log.i(TAG, "Tunnel up");

            isRunning = true;
            broadcast(ACTION_VPN_STARTED);

            FileInputStream  in  = new FileInputStream(tunInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(tunInterface.getFileDescriptor());

            // Forwarding runs off this thread so a slow lookup can never stop
            // us reading the next packet from the tunnel.
            dnsPool = Executors.newFixedThreadPool(POOL_SIZE);

            byte[] buf = new byte[32767];
            while (!Thread.interrupted()) {
                int len = in.read(buf);
                if (len > 0) { packetsRead.incrementAndGet(); handlePacket(buf, len, out); }
            }
        } catch (Exception e) {
            lastError = String.valueOf(e.getMessage());
            Log.i(TAG, "VPN loop ended: " + e.getMessage());
        } finally {
            if (dnsPool != null) dnsPool.shutdownNow();
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

    private void handlePacket(byte[] packet, int length, FileOutputStream out) {
        try {
            if ((packet[0] & 0xF0) >> 4 != 4) return;   // IPv4 only
            int ipHeaderLen = (packet[0] & 0x0F) * 4;
            if ((packet[9] & 0xFF) != 17) return;       // UDP only

            int udp     = ipHeaderLen;
            int dstPort = ((packet[udp + 2] & 0xFF) << 8) | (packet[udp + 3] & 0xFF);
            if (dstPort != 53) return;                  // DNS only

            int udpLen   = ((packet[udp + 4] & 0xFF) << 8) | (packet[udp + 5] & 0xFF);
            int dnsStart = udp + 8;
            int dnsLen   = udpLen - 8;
            if (dnsLen <= 12) return;

            String domain = DnsPacket.extractDomain(packet, dnsStart, dnsLen);
            if (domain == null) return;
            queriesSeen.incrementAndGet();
            lastDomain = domain;

            if (isBlocked(domain)) {
                // Fast path: answer inline, no network needed.
                Log.d(TAG, "BLOCKED " + domain);
                int n = blockedCount.incrementAndGet();
                if (n % 20 == 0) NotificationHelper.update(this, n);

                byte[] dnsResp = DnsPacket.buildNxDomain(packet, dnsStart, dnsLen);
                byte[] reply   = DnsPacket.buildResponsePacket(packet, ipHeaderLen, dnsResp);
                synchronized (out) { out.write(reply); }

                Intent i = new Intent(ACTION_STATS_UPDATE).setPackage(getPackageName());
                i.putExtra(EXTRA_BLOCKED, n);
                sendBroadcast(i);
            } else {
                // Copy before handing off -- the read loop reuses `packet`.
                final byte[] copy = Arrays.copyOf(packet, length);
                final int ihl = ipHeaderLen, ds = dnsStart, dl = dnsLen;
                forwarded.incrementAndGet();
                dnsPool.execute(() -> forwardAndReply(copy, ihl, ds, dl, out));
            }
        } catch (Exception e) {
            errors.incrementAndGet();
            lastError = String.valueOf(e.getMessage());
            Log.w(TAG, "Dropped packet: " + e.getMessage());
        }
    }

    /** Allowlist wins over the blocklist. Both match parent domains. */
    private boolean isBlocked(String domain) {
        if (matches(ALLOWLIST, domain)) return false;
        return matches(blocklist, domain);
    }

    /** True if the domain or any parent of it is in the set. */
    private static boolean matches(Set<String> set, String domain) {
        String d = domain;
        while (d != null) {
            if (set.contains(d)) return true;
            int dot = d.indexOf('.');
            d = (dot == -1) ? null : d.substring(dot + 1);
        }
        return false;
    }

    /**
     * Forward one query upstream and relay the answer back.
     *
     * Each query gets its OWN socket. The previous design shared a single
     * socket across every query: once any lookup timed out, its late answer
     * was handed back as the NEXT query's answer, and every lookup after that
     * stayed one behind -- DNS died permanently until the VPN restarted.
     * A private socket per query makes that impossible, and the transaction-ID
     * check below rejects any stray packet regardless.
     */
    private void forwardAndReply(byte[] packet, int ipHeaderLen,
                                 int dnsStart, int dnsLen, FileOutputStream out) {
        DatagramSocket sock = null;
        try {
            sock = new DatagramSocket();
            bindOutside(sock);                   // keep it out of our own tunnel
            sock.setSoTimeout(DNS_TIMEOUT_MS);

            byte[] query = new byte[dnsLen];
            System.arraycopy(packet, dnsStart, query, 0, dnsLen);
            sock.send(new DatagramPacket(query, dnsLen, upstream, 53));

            byte[] buf = new byte[4096];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            sock.receive(resp);

            // Bytes 0-1 are the transaction ID; it must match what we asked.
            if (resp.getLength() < 12 || buf[0] != query[0] || buf[1] != query[1]) {
                Log.w(TAG, "Transaction ID mismatch, dropped");
                return;
            }

            byte[] dnsResp = Arrays.copyOf(buf, resp.getLength());
            byte[] reply   = DnsPacket.buildResponsePacket(packet, ipHeaderLen, dnsResp);
            synchronized (out) { out.write(reply); }
            answered.incrementAndGet();
        } catch (SocketTimeoutException e) {
            // Stay silent -- the app's own resolver retries. Normal on a
            // congested link, and it no longer poisons anything.
            timeouts.incrementAndGet();
        } catch (Exception e) {
            errors.incrementAndGet();
            lastError = String.valueOf(e.getMessage());
            Log.w(TAG, "Forward failed: " + e.getMessage());
        } finally {
            if (sock != null) sock.close();
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Keep a socket off our own tunnel. protect() marks it to bypass the VPN;
     * binding it to the underlying network is the stronger guarantee, since
     * our own app is otherwise placed on the VPN network like everyone else.
     */
    private void bindOutside(DatagramSocket sock) {
        protect(sock);
        Network n = underlying;
        if (n != null) {
            try { n.bindSocket(sock); } catch (Exception ignored) {}
        }
    }

    /** The real internet-capable network behind us -- wifi or cellular, never a VPN. */
    private Network pickUnderlying() {
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            for (Network n : cm.getAllNetworks()) {
                NetworkCapabilities c = cm.getNetworkCapabilities(n);
                if (c == null) continue;
                if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                if (!c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
                return n;
            }
        } catch (Exception e) {
            Log.w(TAG, "pickUnderlying: " + e.getMessage());
        }
        return null;
    }

    /**
     * Find a resolver that actually answers on THIS network.
     *
     * The network's own DHCP-provided servers come first: many ISPs drop
     * traffic to outside resolvers, which is exactly what killed the previous
     * build -- it hardcoded 8.8.8.8 and every single lookup timed out.
     * Public resolvers are only a fallback.
     */
    private InetAddress pickUpstream(Network net) {
        List<InetAddress> candidates = new ArrayList<>();

        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            if (net != null) {
                LinkProperties lp = cm.getLinkProperties(net);
                if (lp != null) {
                    for (InetAddress a : lp.getDnsServers()) {
                        if (a instanceof Inet4Address && !candidates.contains(a)) candidates.add(a);
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "reading system DNS: " + e.getMessage());
        }

        for (String f : FALLBACK_DNS) {
            try {
                InetAddress a = InetAddress.getByName(f);
                if (!candidates.contains(a)) candidates.add(a);
            } catch (Exception ignored) {}
        }

        for (InetAddress c : candidates) {
            if (answers(c, net)) {
                Log.i(TAG, "upstream chosen: " + c.getHostAddress());
                return c;
            }
            Log.w(TAG, "no answer from " + c.getHostAddress());
        }
        return null;
    }

    /** One real lookup against a candidate resolver. */
    private boolean answers(InetAddress server, Network net) {
        DatagramSocket s = null;
        try {
            s = new DatagramSocket();
            protect(s);
            if (net != null) { try { net.bindSocket(s); } catch (Exception ignored) {} }
            s.setSoTimeout(2500);

            byte[] q = DnsPacket.buildQuery("example.com", 0x4A21);
            s.send(new DatagramPacket(q, q.length, server, 53));

            byte[] buf = new byte[512];
            DatagramPacket r = new DatagramPacket(buf, buf.length);
            s.receive(r);
            return r.getLength() >= 12 && buf[0] == q[0] && buf[1] == q[1];
        } catch (Exception e) {
            return false;
        } finally {
            if (s != null) s.close();
        }
    }

    private void broadcast(String action) {
        sendBroadcast(new Intent(action).setPackage(getPackageName()));
    }

    private void stopVpn() {
        Thread t = vpnThread;
        vpnThread = null;
        if (t != null) t.interrupt();
        closeTun();
    }

    private void closeTun() {
        ParcelFileDescriptor pfd = tunInterface;
        tunInterface = null;
        if (pfd != null) {
            try { pfd.close(); } catch (Exception ignored) {}
        }
    }
}
