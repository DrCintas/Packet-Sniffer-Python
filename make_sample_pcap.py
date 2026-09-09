"""Generate a small sample .pcap for local testing/demoing the sniffer.

No real capture file was ever checked into this repo (the original script
hardcoded a Windows-only path, 'C:/example/example.pcap', that doesn't
exist here). This script builds a tiny synthetic capture instead, so both
sniffer.py and the web UI have something to analyze out of the box.

Usage:
    python make_sample_pcap.py [output_path]
"""

import sys

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP


def build_sample_packets():
    packets = []

    # A fake plaintext HTTP-ish login request over TCP (raw payload contains
    # the keyword "password" so the credential-search feature has something
    # to find).
    login_payload = b"POST /login HTTP/1.1\r\nusername=alice&password=hunter2\r\n"
    packets.append(
        IP(src="10.0.0.5", dst="10.0.0.1")
        / TCP(sport=51321, dport=80, seq=1000, ack=2000)
        / login_payload
    )

    # A plain TCP ACK with no payload.
    packets.append(IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=80, dport=51321, seq=2000, ack=1050))

    # A UDP DNS-ish query.
    packets.append(IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=54000, dport=53) / b"example.com A?")

    # A UDP response.
    packets.append(IP(src="8.8.8.8", dst="10.0.0.5") / UDP(sport=53, dport=54000) / b"93.184.216.34")

    return packets


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "samples/sample.pcap"
    wrpcap(out_path, build_sample_packets())
    print(f"Wrote sample capture to {out_path}")
