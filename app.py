"""Simple web UI for the packet sniffer.

Lets you upload a .pcap/.pcapng/.cap file in the browser and view the same
analysis the CLI (sniffer.py) offers -- packet summary, credential-keyword
search, IP source/destination lookup, and TCP/UDP layer details -- rendered
as readable HTML instead of an interactive text menu.
"""

import os

from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

import packet_analyzer as pa

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("pcap_file")
    if not uploaded or uploaded.filename == "":
        flash("Please choose a .pcap, .pcapng, or .cap file to upload.")
        return redirect(url_for("index"))
    if not allowed_file(uploaded.filename):
        flash("Unsupported file type. Please upload a .pcap, .pcapng, or .cap file.")
        return redirect(url_for("index"))

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    filename = secure_filename(uploaded.filename)
    saved_path = os.path.join(UPLOAD_DIR, filename)
    uploaded.save(saved_path)

    try:
        packets = pa.load_pcap(saved_path)
    except Exception as exc:
        flash(f"Could not parse '{filename}': {exc}")
        return redirect(url_for("index"))
    finally:
        if os.path.exists(saved_path):
            os.remove(saved_path)

    return render_template(
        "results.html",
        filename=filename,
        total_packets=len(packets),
        summary=pa.get_summary(packets),
        credentials=pa.search_credentials(packets),
        tcp_results=pa.search_tcp_udp(packets, "TCP"),
        udp_results=pa.search_tcp_udp(packets, "UDP"),
        ip_pairs=pa.get_ip_pairs(packets),
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
