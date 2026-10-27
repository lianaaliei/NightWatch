#!/usr/bin/env python3
"""nightwatch - a from-scratch pcap analyzer and mini IDS (pure standard library).

Parses classic .pcap files byte by byte (Ethernet / ARP / IPv4 / TCP / UDP / DNS)
and runs five detectors:
  * port scans          * SYN floods          * ARP spoofing
  * DNS tunneling       * cleartext credentials (HTTP Basic, FTP; passwords are masked)
It only reads capture files. It never touches the network.
"""
import argparse
import base64
import binascii
import json
import math
import re
import socket
import struct
import sys
import time
from collections import Counter, defaultdict, deque


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def ip(b):
    return socket.inet_ntoa(bytes(b))


def entropy(s):
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values()) if s else 0.0


# --------------------------------------------------------------------- parsing
def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magics = {
            b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
            b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9),
        }
        if len(gh) < 24 or gh[:4] not in magics:
            raise SystemExit("not a classic pcap file (pcapng is not supported)")
        end, div = magics[gh[:4]]
        if struct.unpack(end + "I", gh[20:24])[0] != 1:
            raise SystemExit("only Ethernet captures (linktype 1) are supported")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, incl, _orig = struct.unpack(end + "IIII", h)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield sec + frac / div, data


def dns_labels(p):
    """Labels of the first question of a DNS query, or None."""
    if len(p) < 13 or p[2] & 0x80:
        return None
    labels, i = [], 12
    while i < len(p) and p[i]:
        n = p[i]
        if n & 0xC0 or i + 1 + n > len(p):
            return None
        labels.append(p[i + 1:i + 1 + n].decode("ascii", "replace").lower())
        i += 1 + n
    return labels or None


def parse(ts, d):
    if len(d) < 14:
        return None
    et, off = struct.unpack("!H", d[12:14])[0], 14
    if et == 0x8100 and len(d) >= 18:
        et, off = struct.unpack("!H", d[16:18])[0], 18
    if et == 0x0806 and len(d) >= off + 28:
        return {"ts": ts, "proto": "arp", "op": struct.unpack("!H", d[off + 6:off + 8])[0],
                "smac": mac(d[off + 8:off + 14]), "sip": ip(d[off + 14:off + 18])}
    if et != 0x0800 or len(d) < off + 20:
        return None
    ihl, proto = (d[off] & 15) * 4, d[off + 9]
    p = {"ts": ts, "src": ip(d[off + 12:off + 16]), "dst": ip(d[off + 16:off + 20]), "payload": b""}
    l4 = d[off + ihl:]
    if proto == 6 and len(l4) >= 20:
        sport, dport, _seq, _ack, x = struct.unpack("!HHIIH", l4[:14])
        p.update(proto="tcp", sport=sport, dport=dport, flags=x & 0x3F, payload=l4[(x >> 12) * 4:])
    elif proto == 17 and len(l4) >= 8:
        sport, dport, _len, _ck = struct.unpack("!HHHH", l4[:8])
        p.update(proto="udp", sport=sport, dport=dport, payload=l4[8:])
    else:
        return None
    return p


# ------------------------------------------------------------------- detection
class IDS:
    def __init__(self, scan_ports=15, scan_window=10, flood_syns=100, flood_window=5):
        self.scan_ports, self.scan_window = scan_ports, scan_window
        self.flood_syns, self.flood_window = flood_syns, flood_window
        self.alerts, self.seen, self.stats = [], set(), Counter()
        self.scan, self.flood = defaultdict(deque), defaultdict(deque)
        self.arp = {}
        self.dns = defaultdict(lambda: {"names": set(), "ent": [], "len": [], "client": ""})

    def alert(self, key, ts, sev, kind, src, msg):
        if key not in self.seen:
            self.seen.add(key)
            self.alerts.append({"ts": ts, "severity": sev, "type": kind, "src": src, "msg": msg})

    def feed(self, p):
        self.stats["packets"] += 1
        ts = p["ts"]
        if p["proto"] == "arp":
            self.stats["arp"] += 1
            if p["sip"] == "0.0.0.0":
                return
            known = self.arp.setdefault(p["sip"], p["smac"])
            if known != p["smac"]:
                self.alert(("arp", p["sip"], p["smac"]), ts, "high", "arp-spoofing", p["smac"],
                           f"{p['sip']} was {known}, now claimed by {p['smac']}")
            return
        self.stats[p["proto"]] += 1
        if p["proto"] == "tcp":
            self.tcp(p)
        elif p["dport"] == 53:
            self.udp_dns(p)

    def tcp(self, p):
        ts, src, dst = p["ts"], p["src"], p["dst"]
        if p["flags"] & 0x12 == 0x02:  # SYN without ACK
            q = self.scan[src]
            q.append((ts, dst, p["dport"]))
            while ts - q[0][0] > self.scan_window:
                q.popleft()
            targets = {(d, pt) for _, d, pt in q}
            if len(targets) >= self.scan_ports:
                hosts = len({d for d, _ in targets})
                self.alert(("scan", src), ts, "high", "port-scan", src,
                           f"{src} sent SYNs to {len(targets)} ports on {hosts} host(s) within {self.scan_window}s")
            f = self.flood[dst]
            f.append(ts)
            while ts - f[0] > self.flood_window:
                f.popleft()
            if len(f) >= self.flood_syns:
                self.alert(("flood", dst), ts, "high", "syn-flood", dst,
                           f"{len(f)}+ SYNs to {dst} within {self.flood_window}s")
        data = p["payload"]
        if p["dport"] in (80, 8080):
            m = re.search(rb"Authorization: Basic ([A-Za-z0-9+/=]+)", data)
            if m:
                try:
                    user = base64.b64decode(m.group(1)).decode("utf-8", "replace").split(":", 1)[0]
                except (binascii.Error, ValueError):
                    return
                self.alert(("basic", src, dst, user), ts, "medium", "cleartext-credentials", src,
                           f"HTTP Basic auth for user '{user}' sent unencrypted to {dst}:{p['dport']}")
        elif p["dport"] == 21:
            if data.startswith(b"USER "):
                user = data[5:].split(b"\r")[0].decode("utf-8", "replace")
                self.alert(("ftpu", src, dst, user), ts, "medium", "cleartext-credentials", src,
                           f"FTP login '{user}' sent unencrypted to {dst}")
            elif data.startswith(b"PASS "):
                self.alert(("ftpp", src, dst), ts, "medium", "cleartext-credentials", src,
                           f"FTP password (masked: {'*' * 8}) sent unencrypted to {dst}")

    def udp_dns(self, p):
        labels = dns_labels(p["payload"])
        if not labels or len(labels) < 3:
            return
        base, sub = ".".join(labels[-2:]), ".".join(labels[:-2])
        d = self.dns[base]
        if sub in d["names"]:
            return
        d["names"].add(sub)
        d["ent"].append(entropy(labels[0]))
        d["len"].append(len(sub))
        d["client"] = d["client"] or p["src"]
        n = len(d["names"])
        if n >= 20 and sum(d["ent"]) / n > 3.2 and sum(d["len"]) / n >= 16:
            self.alert(("dns", base), p["ts"], "high", "dns-tunneling", d["client"],
                       f"{n} unique high-entropy subdomains of {base} "
                       f"(avg len {sum(d['len']) / n:.0f}, entropy {sum(d['ent']) / n:.1f})")


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="nightwatch - pcap analyzer / mini IDS")
    ap.add_argument("pcap")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--scan-ports", type=int, default=15, help="distinct ports to call it a scan")
    ap.add_argument("--flood-syns", type=int, default=100, help="SYNs per 5s to call it a flood")
    args = ap.parse_args()

    ids = IDS(scan_ports=args.scan_ports, flood_syns=args.flood_syns)
    for ts, data in read_pcap(args.pcap):
        pkt = parse(ts, data)
        if pkt:
            ids.feed(pkt)
    alerts = sorted(ids.alerts, key=lambda a: a["ts"])

    if args.json:
        print(json.dumps({"stats": dict(ids.stats), "alerts": alerts}, indent=2))
    else:
        s = ids.stats
        print(f"{s['packets']} packets  (tcp {s['tcp']}, udp {s['udp']}, arp {s['arp']})")
        col = {"high": "\033[91m", "medium": "\033[93m"} if sys.stdout.isatty() else {}
        for a in alerts:
            t = time.strftime("%H:%M:%S", time.gmtime(a["ts"]))
            print(f"{col.get(a['severity'], '')}[{a['severity'].upper():6}] {t} {a['type']:22}"
                  f"\033[0m" if col else f"[{a['severity'].upper():6}] {t} {a['type']:22}", a["msg"])
        print(f"\n{len(alerts)} alert(s)")
    sys.exit(1 if any(a["severity"] == "high" for a in alerts) else 0)


if __name__ == "__main__":
    main()
