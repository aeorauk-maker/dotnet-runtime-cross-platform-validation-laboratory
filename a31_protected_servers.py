#!/usr/bin/env python3
"""Owned loopback canary collector and token-guarded HTTPS resource.

Only hashes of the canary are persisted. Never run this against external data.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl


def append(path, row):
    with open(path, "a", encoding="utf-8") as out:
        out.write(json.dumps(row, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("collector", "protected"))
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--expected-auth-sha256")
    parser.add_argument("--canary", type=Path)
    parser.add_argument("--fixtures", type=Path)
    args = parser.parse_args()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            return

        def do_POST(self):
            if args.mode != "collector" or self.path != "/collect":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            append(args.log, {"event": "canary_received", "sha256": hashlib.sha256(body).hexdigest(),
                              "length": len(body)})
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            if args.mode != "protected" or self.path != "/private":
                self.send_error(404)
                return
            auth = self.headers.get("Authorization", "")
            allowed = bool(auth) and hashlib.sha256(auth.encode()).hexdigest() == args.expected_auth_sha256
            append(args.log, {"event": "protected_request", "authorized": allowed,
                              "auth_sha256": hashlib.sha256(auth.encode()).hexdigest() if auth else None})
            if not allowed:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="owned-private-resource"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = args.canary.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    if args.mode == "protected":
        if not args.expected_auth_sha256 or not args.canary or not args.fixtures:
            parser.error("protected mode requires auth hash, canary and fixtures")
        cert_path = args.fixtures / "valid_direct_root.cert.pem"
        key_path = args.fixtures / "valid_direct_root.key.pem"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("READY", flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
