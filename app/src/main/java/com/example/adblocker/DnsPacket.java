package com.example.adblocker; // change to match your app's package name

/**
 * Static helpers for the two things we do with DNS at the byte level:
 *   1. read the domain name out of a query
 *   2. build the reply packet we write back into the tunnel
 *
 * Everything here works on raw IPv4 + UDP + DNS bytes. No allocations we
 * can avoid, because this runs once per DNS query.
 */
public final class DnsPacket {

    private DnsPacket() {}

    /**
     * Pull the queried domain out of a DNS message.
     *
     * A DNS query starts with a 12-byte header, then the QNAME: a series of
     * labels, each one a length byte followed by that many ASCII bytes,
     * terminated by a zero byte. "ads.example.com" is encoded as
     * [3]"ads"[7]"example"[3]"com"[0].
     *
     * @param packet    the full IP packet
     * @param dnsStart  index where the DNS message begins
     * @param dnsLength length of the DNS message
     * @return lower-cased domain, or null if malformed/empty
     */
    public static String extractDomain(byte[] packet, int dnsStart, int dnsLength) {
        int pos = dnsStart + 12; // skip the DNS header
        int end = dnsStart + dnsLength;
        StringBuilder domain = new StringBuilder();

        while (pos < end) {
            int labelLen = packet[pos] & 0xFF;
            if (labelLen == 0) {
                break; // reached the end of the name
            }
            // Compression pointers (top two bits set) never appear in a
            // query's question section, so we don't need to follow them here.
            if ((labelLen & 0xC0) != 0) {
                return null;
            }
            pos++;
            if (pos + labelLen > end) {
                return null; // runs past the packet -> malformed
            }
            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(packet, pos, labelLen)); // labels are ASCII
            pos += labelLen;
        }
        return domain.length() == 0 ? null : domain.toString().toLowerCase();
    }

    /**
     * Turn a DNS query into an NXDOMAIN ("no such domain") response by
     * flipping a few header bits and echoing the question back. Apps treat
     * this as "the domain doesn't exist" and give up -- the ad never loads.
     *
     * @return a standalone DNS response message
     */
    public static byte[] buildNxDomain(byte[] packet, int dnsStart, int dnsLength) {
        byte[] dns = new byte[dnsLength];
        System.arraycopy(packet, dnsStart, dns, 0, dnsLength);

        // Flags (bytes 2-3): QR=1 (response), RD=1, RA=1, RCODE=3 (NXDOMAIN)
        dns[2] = (byte) 0x81;
        dns[3] = (byte) 0x83;

        // Zero all the record counts except QDCOUNT (bytes 4-5) which we keep,
        // so the echoed question stays valid.
        dns[6] = 0; dns[7] = 0;   // ANCOUNT
        dns[8] = 0; dns[9] = 0;   // NSCOUNT
        dns[10] = 0; dns[11] = 0; // ARCOUNT
        return dns;
    }

    /**
     * Wrap a DNS response payload back into a full IP+UDP packet that we can
     * write into the tunnel. We reuse the original packet's IP header, swap
     * the source/destination so it flows back to the app, fix the length
     * fields, and recompute the IP checksum.
     *
     * @param original    the incoming query packet (for its IP header)
     * @param ipHeaderLen length of that IP header
     * @param dnsResponse the DNS message to send back
     */
    public static byte[] buildResponsePacket(byte[] original, int ipHeaderLen, byte[] dnsResponse) {
        int udpLen = 8 + dnsResponse.length;          // UDP header + payload
        int totalLen = ipHeaderLen + udpLen;
        byte[] out = new byte[totalLen];

        // ---- IP header: copy, then rewrite ----
        System.arraycopy(original, 0, out, 0, ipHeaderLen);

        // Total length (bytes 2-3)
        out[2] = (byte) (totalLen >> 8);
        out[3] = (byte) (totalLen & 0xFF);

        // Swap source (bytes 12-15) and destination (bytes 16-19) addresses,
        // so the reply travels app <- us instead of app -> us.
        for (int i = 0; i < 4; i++) {
            byte tmp = out[12 + i];
            out[12 + i] = out[16 + i];
            out[16 + i] = tmp;
        }

        // Recompute the IP header checksum: zero the field first (bytes 10-11).
        out[10] = 0;
        out[11] = 0;
        int ipChecksum = checksum(out, 0, ipHeaderLen);
        out[10] = (byte) (ipChecksum >> 8);
        out[11] = (byte) (ipChecksum & 0xFF);

        // ---- UDP header ----
        int udp = ipHeaderLen;
        int originalSrcPort = ((original[udp] & 0xFF) << 8) | (original[udp + 1] & 0xFF);
        // Response source port = 53, destination = whatever port the app used.
        out[udp]     = 0;
        out[udp + 1] = 53;
        out[udp + 2] = (byte) (originalSrcPort >> 8);
        out[udp + 3] = (byte) (originalSrcPort & 0xFF);
        out[udp + 4] = (byte) (udpLen >> 8);
        out[udp + 5] = (byte) (udpLen & 0xFF);
        // UDP checksum is optional in IPv4; 0 means "not computed".
        out[udp + 6] = 0;
        out[udp + 7] = 0;

        // ---- payload ----
        System.arraycopy(dnsResponse, 0, out, ipHeaderLen + 8, dnsResponse.length);
        return out;
    }

    /**
     * Standard one's-complement Internet checksum (RFC 1071), used for the
     * IPv4 header. Sum the data as 16-bit words, fold the carries back in,
     * then invert.
     */
    private static int checksum(byte[] data, int offset, int length) {
        long sum = 0;
        int i = offset;
        while (length > 1) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
            length -= 2;
        }
        if (length == 1) { // odd byte left over
            sum += (data[i] & 0xFF) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) (~sum & 0xFFFF);
    }
}
