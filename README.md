# Packet-Sniffer-Python

An offline `.pcap` analyzer written in Python on top of [Scapy](https://scapy.net/).
It can summarize a capture, search raw payloads for credential-like keywords,
look up the source/destination IP of a given packet, and list TCP/UDP layer
details.

Two ways to use it:

## 1. Web UI (recommended)

A small Flask app lets you upload a capture file in the browser and see the
results as readable tables instead of a text menu.

```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000, upload a `.pcap`/`.pcapng`/`.cap` file, and
view the summary, credential hits, IP addresses, and TCP/UDP tabs.

Don't have a capture file handy? Generate a tiny synthetic one:

```bash
python make_sample_pcap.py            # writes samples/sample.pcap
```

Environment variables (all optional):
- `PORT` -- port to listen on (default `5000`)
- `SECRET_KEY` -- Flask session secret (default is a dev-only placeholder)
- `FLASK_DEBUG` -- set to `1` to enable Flask's debug/reloader mode

## 2. Command-line tool

```bash
pip install -r requirements.txt
python sniffer.py samples/sample.pcap
```

If you omit the path argument, it falls back to the `PCAP_PATH` environment
variable, then prompts interactively (defaulting to `samples/sample.pcap`).
The original version of this script had the path hardcoded to a
Windows-only location (`C:/example/example.pcap`) that never existed in this
repo -- that's fixed now.

Once loaded, pick from the interactive menu:

1. Check the entire pcap file
2. Look for login usernames or passwords
3. Check the IP source address of a specific packet
4. Check the IP destination address of a specific packet
5. Search which packets have a TCP or UDP layer
6. Exit

## Project layout

- `packet_analyzer.py` -- core, side-effect-free packet-parsing functions shared by both front-ends
- `sniffer.py` -- original interactive CLI
- `app.py` -- Flask web UI
- `templates/` -- HTML templates for the web UI
- `make_sample_pcap.py` -- generates `samples/sample.pcap`, a tiny synthetic capture for local testing
- `requirements.txt` -- pinned dependencies (`scapy`, `flask`, `werkzeug`)
