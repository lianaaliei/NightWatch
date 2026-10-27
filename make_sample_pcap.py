#!/usr/bin/env python3
"""Writes sample.pcap: normal traffic mixed with five synthetic attacks (for demos and tests)."""
import random
import socket
import struct
import sys

random.seed(7)
T0 = 1_700_000_000.0
GW_MAC, VICTIM_MAC, ATT_MAC = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:05", "de:ad:be:ef:00:66"
packets = []  # (ts, bytes)


def mb(m):
    return bytes.fromhex(m.replace(":", ""))


def eth(src, dst, et, body):
    return mb(dst) + mb(src) + struct.pack("!H", et) + body


def ipv4(src, dst, proto, body):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst)) + body


def tcp(sp, dp, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 65535, 0, 0) + data


def udp(sp, dp, data):
    return struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data


def dns_query(name):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def arp_reply(smac, sip, tmac, tip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mb(smac) + socket.inet_aton(sip) + mb(tmac) + socket.inet_aton(tip)


def add(ts, frame):
    packets.append((ts, frame))


def tcp_pkt(ts, smac, dmac, src, dst, sp, dp, flags, data=b""):
    add(ts, eth(smac, dmac, 0x0800, ipv4(src, dst, 6, tcp(sp, dp, flags, data))))


# 1. normal browsing + DNS
for i in range(40):
    t = T0 + i * 1.7
    tcp_pkt(t, VICTIM_MAC, GW_MAC, "10.0.0.5", "93.184.216.34", 40000 + i, 443, 0x02)
    tcp_pkt(t + .01, GW_MAC, VICTIM_MAC, "93.184.216.34", "10.0.0.5", 443, 40000 + i, 0x12)
    add(t + .02, eth(VICTIM_MAC, GW_MAC, 0x0800, ipv4("10.0.0.5", "10.0.0.1", 17, udp(5000 + i, 53, dns_query("www.example.com")))))
add(T0 + 1, eth(GW_MAC, VICTIM_MAC, 0x0806, arp_reply(GW_MAC, "10.0.0.1", VICTIM_MAC, "10.0.0.5")))

# 2. port scan: 10.0.0.66 -> 10.0.0.5
for i, port in enumerate(range(1, 61)):
    tcp_pkt(T0 + 20 + i * 0.05, ATT_MAC, VICTIM_MAC, "10.0.0.66", "10.0.0.5", 51000, port, 0x02)

# 3. SYN flood with spoofed sources
for i in range(300):
    src = f"172.16.{random.randrange(256)}.{random.randrange(1, 255)}"
    tcp_pkt(T0 + 30 + i * 0.01, ATT_MAC, VICTIM_MAC, src, "10.0.0.5", random.randrange(1024, 65535), 80, 0x02)

# 4. ARP spoofing: attacker claims the gateway's IP
add(T0 + 40, eth(ATT_MAC, VICTIM_MAC, 0x0806, arp_reply(ATT_MAC, "10.0.0.1", VICTIM_MAC, "10.0.0.5")))

# 5. DNS tunneling to a fake C2 domain
for i in range(40):
    name = "".join(random.choice("0123456789abcdef") for _ in range(32)) + ".t.evil-c2.example"
    add(T0 + 50 + i * 0.2, eth(VICTIM_MAC, GW_MAC, 0x0800, ipv4("10.0.0.5", "10.0.0.1", 17, udp(6000 + i, 53, dns_query(name)))))

# 6. cleartext credentials
http = b"GET /admin HTTP/1.1\r\nHost: intranet\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n"
tcp_pkt(T0 + 70, VICTIM_MAC, GW_MAC, "10.0.0.5", "10.0.0.20", 41000, 80, 0x18, http)
tcp_pkt(T0 + 71, VICTIM_MAC, GW_MAC, "10.0.0.5", "10.0.0.21", 41001, 21, 0x18, b"USER alice\r\n")
tcp_pkt(T0 + 72, VICTIM_MAC, GW_MAC, "10.0.0.5", "10.0.0.21", 41001, 21, 0x18, b"PASS correcthorse\r\n")

packets.sort(key=lambda x: x[0])
out = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, fr in packets:
        sec = int(ts)
        f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(fr), len(fr)) + fr)
print(f"wrote {out}: {len(packets)} packets")
