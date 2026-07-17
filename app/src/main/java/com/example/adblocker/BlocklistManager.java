package com.example.adblocker; // change to match your app's package name

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Downloads, caches and parses the blocklist.
 *
 * Call load() from a background thread only -- it may hit the network.
 */
public class BlocklistManager {

    private static final String TAG = "AdBlockList";

    // StevenBlack's unified hosts list: ~130k ad/tracking/malware domains.
    private static final String LIST_URL =
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

    private static final String CACHE_FILE = "blocklist.txt";
    private static final long MAX_CACHE_AGE_MS = 24L * 60 * 60 * 1000; // refresh daily

    // Hostnames that appear in hosts files but must never be blocked.
    private static final Set<String> IGNORED = new HashSet<>(Arrays.asList(
            "localhost", "localhost.localdomain", "local", "broadcasthost",
            "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
            "ip6-allnodes", "ip6-allrouters", "ip6-allhosts"
    ));

    private final Context context;

    public BlocklistManager(Context context) {
        this.context = context.getApplicationContext();
    }

    /**
     * Freshness ladder:
     *   fresh cache      -> use it
     *   stale / no cache -> try to download a new copy
     *   download failed  -> use the stale cache if one exists
     *   nothing at all   -> tiny built-in list so blocking still works
     */
    public Set<String> load() {
        File cache = new File(context.getFilesDir(), CACHE_FILE);

        boolean fresh = cache.exists()
                && System.currentTimeMillis() - cache.lastModified() < MAX_CACHE_AGE_MS;

        if (!fresh) {
            try {
                download(cache);
            } catch (IOException e) {
                Log.w(TAG, "Download failed: " + e.getMessage());
            }
        }

        if (cache.exists()) {
            try (InputStream in = new FileInputStream(cache)) {
                Set<String> parsed = parse(in);
                if (!parsed.isEmpty()) {
                    Log.i(TAG, "Loaded " + parsed.size() + " domains from cache");
                    return parsed;
                }
            } catch (IOException e) {
                Log.w(TAG, "Cache read failed: " + e.getMessage());
            }
        }

        Log.w(TAG, "Falling back to built-in mini list");
        return new HashSet<>(Arrays.asList(
                "doubleclick.net", "googlesyndication.com", "google-analytics.com"));
    }

    private void download(File cache) throws IOException {
        Log.i(TAG, "Downloading blocklist...");
        File tmp = new File(cache.getPath() + ".tmp");

        HttpURLConnection conn = (HttpURLConnection) new URL(LIST_URL).openConnection();
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(15_000);
        try (InputStream in = conn.getInputStream();
             FileOutputStream out = new FileOutputStream(tmp)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        } finally {
            conn.disconnect();
        }

        // Only replace the old cache once the new file has arrived completely,
        // so a broken download can never destroy a working list.
        if (!tmp.renameTo(cache)) {
            throw new IOException("Could not move temp file into place");
        }
        Log.i(TAG, "Blocklist saved (" + cache.length() / 1024 + " KB)");
    }

    /**
     * Handles both formats:
     *   hosts:  "0.0.0.0 ads.example.com"   (StevenBlack style)
     *   plain:  "ads.example.com"           (OISD style, one domain per line)
     */
    private Set<String> parse(InputStream in) throws IOException {
        Set<String> domains = new HashSet<>(200_000); // avoid rehashing mid-load
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(in, StandardCharsets.UTF_8), 1 << 16);

        String line;
        while ((line = reader.readLine()) != null) {
            int hash = line.indexOf('#');
            if (hash != -1) {
                line = line.substring(0, hash); // strip comments, inline ones too
            }
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }

            String[] tokens = line.split("\\s+");
            // More than one token -> hosts format, skip the IP column.
            int first = tokens.length > 1 ? 1 : 0;

            for (int i = first; i < tokens.length; i++) {
                String d = tokens[i].toLowerCase(Locale.ROOT);
                if (d.indexOf('.') == -1 || IGNORED.contains(d) || looksLikeIp(d)) {
                    continue;
                }
                domains.add(d);
            }
        }
        return domains;
    }

    /** True for tokens made only of digits, dots and colons (bare IPs). */
    private static boolean looksLikeIp(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c < '0' || c > '9') && c != '.' && c != ':') {
                return false; // contains letters -> a real domain name
            }
        }
        return true;
    }
}
