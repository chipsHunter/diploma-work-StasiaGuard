#!/usr/bin/env python3
"""StasiaGuard VPN Prometheus Exporter.

Connects to the VPN daemon via Unix socket (IPC), fetches metrics
in JSON format, and serves them as Prometheus text exposition on
HTTP /metrics endpoint.

Usage:
    python3 vpn_exporter.py [--socket /var/run/vpn.sock] [--port 9090]
"""

import argparse
import json
import socket
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

DEFAULT_SOCKET = "/var/run/vpn.sock"
DEFAULT_PORT = 9090

METRIC_DEFS = [
    # (name, help, type)
    ("vpn_active_peers",           "Number of connected VPN peers",              "gauge"),
    ("vpn_bytes_sent_total",       "Total bytes sent through tunnel",            "counter"),
    ("vpn_bytes_received_total",   "Total bytes received through tunnel",        "counter"),
    ("vpn_packets_sent_total",     "Total packets sent",                         "counter"),
    ("vpn_packets_received_total", "Total packets received",                     "counter"),
    ("vpn_handshakes_total",       "Total handshakes completed",                 "counter"),
    ("vpn_handshakes_failed_total","Total handshakes failed",                    "counter"),
    ("vpn_decrypt_errors_total",   "Total decryption errors",                    "counter"),
    ("vpn_replay_rejected_total",  "Total replay attacks rejected",              "counter"),
    ("vpn_rekeys_total",           "Total session rekeys performed",             "counter"),
    ("vpn_padding_overhead_bytes_total", "Total padding overhead in bytes",      "counter"),
    ("vpn_uptime_seconds",         "Daemon uptime in seconds",                   "gauge"),
]

JSON_TO_PROM = {
    "active_peers":           "vpn_active_peers",
    "bytes_sent":             "vpn_bytes_sent_total",
    "bytes_received":         "vpn_bytes_received_total",
    "packets_sent":           "vpn_packets_sent_total",
    "packets_received":       "vpn_packets_received_total",
    "handshakes_total":       "vpn_handshakes_total",
    "handshakes_failed":      "vpn_handshakes_failed_total",
    "decrypt_errors":         "vpn_decrypt_errors_total",
    "replay_rejected":        "vpn_replay_rejected_total",
    "rekeys_total":           "vpn_rekeys_total",
    "padding_overhead_bytes": "vpn_padding_overhead_bytes_total",
    "uptime_seconds":         "vpn_uptime_seconds",
}


def fetch_metrics(socket_path: str) -> dict:
    """Send 'metrics' command to VPN daemon via Unix socket, return JSON."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(socket_path)
        sock.sendall(b'{"command":"metrics"}\n')
        data = sock.recv(8192)
        sock.close()
        return json.loads(data.decode().strip())
    except Exception as e:
        print(f"error: cannot fetch metrics: {e}", file=sys.stderr)
        return {}


def format_prometheus(metrics: dict) -> str:
    """Convert JSON metrics dict to Prometheus text exposition format."""
    lines = []
    for name, help_text, metric_type in METRIC_DEFS:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {metric_type}")

        # Find value from JSON
        for json_key, prom_name in JSON_TO_PROM.items():
            if prom_name == name and json_key in metrics:
                lines.append(f"{name} {metrics[json_key]}")
                break

    lines.append("")
    return "\n".join(lines)


class MetricsHandler(BaseHTTPRequestHandler):
    socket_path = DEFAULT_SOCKET

    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return

        metrics = fetch_metrics(self.socket_path)
        body = format_prometheus(metrics)

        self.send_response(200)
        self.send_header("Content-Type",
                         "text/plain; version=0.0.4; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass  # suppress per-request logs


def main():
    parser = argparse.ArgumentParser(description="StasiaGuard VPN Exporter")
    parser.add_argument("--socket", default=DEFAULT_SOCKET,
                        help="Path to VPN daemon Unix socket")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="HTTP port for /metrics endpoint")
    args = parser.parse_args()

    MetricsHandler.socket_path = args.socket

    server = HTTPServer(("0.0.0.0", args.port), MetricsHandler)
    print(f"exporter listening on :{args.port}/metrics "
          f"(socket: {args.socket})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    main()
