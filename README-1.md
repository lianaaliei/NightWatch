# nightwatch 🦉

A **from-scratch pcap analyzer and mini IDS** in pure Python (standard library only). It decodes capture files byte by byte, with no scapy and no libpcap, and flags common attacks.

## Detectors
| Detector | How it works |
|---|---|
| **Port scan** | one source sends SYNs to many distinct ports inside a sliding window |
| **SYN flood** | burst of SYN-only packets at one destination (works with spoofed sources) |
| **ARP spoofing** | an IP's MAC address changes after first being seen |
| **DNS tunneling** | many unique, long, high-entropy subdomains under one domain |
| **Cleartext credentials** | HTTP Basic auth and FTP logins on the wire (passwords are masked in output) |

## Usage
```bash
python3 make_sample_pcap.py          # builds sample.pcap (normal traffic + 5 attacks)
python3 nightwatch.py sample.pcap    # human-readable alerts
python3 nightwatch.py sample.pcap --json
```
Exit code is `1` when a high-severity alert fires, so it works in CI or cron pipelines. Example output is in `sample-output.txt`.

Tuning: `--scan-ports N` and `--flood-syns N`.

## Limits
Classic `.pcap` with Ethernet only (no pcapng, no TCP stream reassembly). Thresholds are heuristics: tune them on your own traffic.

## Ideas to extend
pcapng support, TLS SNI extraction, TCP reassembly, live capture via `AF_PACKET`, JA3 fingerprints, Sigma-style rules.

## License
MIT
