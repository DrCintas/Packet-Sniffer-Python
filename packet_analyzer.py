"""Core packet-analysis logic shared by the CLI (sniffer.py) and the web UI (app.py).

Extracted from the original sniffer.py so both front-ends can reuse the same,
side-effect-free functions instead of duplicating parsing logic and printing
directly to stdout.
"""

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

CREDENTIAL_KEYWORDS = ["login", "password", "username", "user", "pass"]


def load_pcap(path):
    """Read a .pcap/.pcapng file from disk and return a scapy PacketList."""
    return rdpcap(path)


def get_summary(packets):
    """Return a one-line summary string for every packet."""
    return [pkt.summary() for pkt in packets]


def search_credentials(packets, keywords=None):
    """Scan raw payloads for credential-like keywords.

    Returns a list of dicts: {"packet": index, "keyword": str, "data": str}
    """
    keywords = keywords or CREDENTIAL_KEYWORDS
    findings = []
    for idx, pkt in enumerate(packets):
        if not pkt.haslayer(Raw):
            continue
        load = pkt[Raw].load
        for keyword in keywords:
            if bytes(keyword, "utf-8") in load:
                findings.append(
                    {
                        "packet": idx,
                        "keyword": keyword,
                        "data": load.decode("utf-8", errors="replace"),
                    }
                )
    return findings


def get_ip_src(packets, num_packet):
    """Return the source IP of packet #num_packet, or None if it has no IP layer."""
    pkt = packets[num_packet]
    return pkt[IP].src if pkt.haslayer(IP) else None


def get_ip_dst(packets, num_packet):
    """Return the destination IP of packet #num_packet, or None if it has no IP layer."""
    pkt = packets[num_packet]
    return pkt[IP].dst if pkt.haslayer(IP) else None


def search_tcp_udp(packets, proto):
    """Return per-packet TCP or UDP layer details.

    proto: "TCP" or "UDP" (case-insensitive).
    """
    proto = proto.upper()
    results = []
    for idx, pkt in enumerate(packets):
        if proto == "TCP" and pkt.haslayer(TCP):
            results.append(
                {
                    "packet": idx,
                    "seq": pkt[TCP].seq,
                    "ack": pkt[TCP].ack,
                    "timestamp": float(pkt.time),
                }
            )
        elif proto == "UDP" and pkt.haslayer(UDP):
            results.append(
                {
                    "packet": idx,
                    "payload": str(pkt[UDP].payload),
                    "timestamp": float(pkt.time),
                }
            )
    return results


def get_ip_pairs(packets):
    """Return src/dst IP for every packet that has an IP layer."""
    pairs = []
    for idx, pkt in enumerate(packets):
        if pkt.haslayer(IP):
            pairs.append({"packet": idx, "src": pkt[IP].src, "dst": pkt[IP].dst})
    return pairs
