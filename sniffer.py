#!/usr/bin/env python3

import os
import sys

import packet_analyzer as pa


def resolve_pcap_path():
    """Resolve the pcap path from argv[1], PCAP_PATH env var, or an interactive prompt.

    The original script hardcoded 'C:/example/example.pcap', which only ever
    worked on the author's own Windows machine and had no sample file checked
    into the repo. This keeps the same interactive feel but makes it actually
    runnable anywhere.
    """
    if len(sys.argv) > 1:
        return sys.argv[1]
    if os.environ.get("PCAP_PATH"):
        return os.environ["PCAP_PATH"]
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples", "sample.pcap")
    prompt = f"Path to a .pcap file to analyze [{default}]: "
    entered = input(prompt).strip()
    return entered or default


def check_pcap(packets):
    for line in pa.get_summary(packets):
        print(line)


def search_credentials(packets):
    findings = pa.search_credentials(packets)
    if not findings:
        print("No credential-like keywords found.")
    for finding in findings:
        print("Found a login at packet", finding["packet"], ": ", finding["data"])


def search_IP_src(packets, num_packet):
    src = pa.get_ip_src(packets, num_packet)
    if src is None:
        print(num_packet, "packet has no IP layer")
    else:
        print(num_packet, "packet IP source address: ", src)


def search_IP_dst(packets, num_packet):
    dst = pa.get_ip_dst(packets, num_packet)
    if dst is None:
        print(num_packet, "packet has no IP layer")
    else:
        print(num_packet, "packet IP destination address: ", dst)


def search_TCP_UDP(packets, choice_TU):
    results = pa.search_tcp_udp(packets, choice_TU)
    if not results:
        print(f"No packets with a {choice_TU.upper()} layer")
        return
    if choice_TU.upper() == "TCP":
        for r in results:
            print(
                "Packet",
                r["packet"],
                "---> Response seq: " + str(r["seq"]) + " ack: " + str(r["ack"]) + " timestamp: " + str(r["timestamp"]),
            )
    else:
        for r in results:
            print(
                "Packet",
                r["packet"],
                "---> Payload: " + r["payload"] + " timestamp: " + str(r["timestamp"]),
            )


if __name__ == "__main__":
    pcap_path = resolve_pcap_path()
    try:
        packets = pa.load_pcap(pcap_path)
    except Exception as exc:
        print(f"Could not read pcap file '{pcap_path}': {exc}")
        sys.exit(1)

    while True:
        print("\nWELCOME TO PACKET SNIFFER WITH PYTHON!")
        print("---------------------------------------------------\n")
        print("1) Check the entire pcap file\n2) Look for login usernames or passwords\n3) Check the IP source address of a specific packet")
        print("4) Check the IP destination address of a specific packet\n5) Search which packets have a TCP or UDP layer\n6) Exit")
        pick = input("Please pick a number to choose what you want to do: ")
        if pick == "1":
            check_pcap(packets)
        elif pick == "2":
            search_credentials(packets)
        elif pick == "3":
            number_packet_ip_src = input("Write the number of the packet that you want to know its IP source (starting from 0): ")
            search_IP_src(packets, int(number_packet_ip_src))
        elif pick == "4":
            number_packet_ip_dst = input("Write the number of the packet that you want to know its IP destination (starting from 0): ")
            search_IP_dst(packets, int(number_packet_ip_dst))
        elif pick == "5":
            TCP_UDP = input("Which layers are you looking for? (TCP or UDP): ")
            search_TCP_UDP(packets, TCP_UDP)
        elif pick == "6":
            break
        else:
            print("Please pick a number between 1 and 6")
