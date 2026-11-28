#!/usr/bin/env python3
"""Owned HTTPS NuGet service-index fixture behind a local CONNECT proxy."""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import ssl
from pathlib import Path


def emit(path, **row):
    with open(path, "a", encoding="utf-8") as out:
        out.write(json.dumps(row, sort_keys=True) + "\n")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--tls-port", type=int, required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--capture-auth", type=Path,
                        help="Temporary 0600 capture of first Basic header; caller must delete it")
    parser.add_argument("--nupkg", type=Path,
                        help="Optional inert owned package for the build-target join")
    parser.add_argument("--plain", action="store_true",
                        help="Loopback HTTP protocol self-test; TLS attack runs omit this")
    args = parser.parse_args()
    context = None
    if not args.plain:
        pem_cert = args.fixtures / f"{args.case}.cert.pem"
        pem_key = args.fixtures / f"{args.case}.key.pem"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(pem_cert), str(pem_key))
    expected_host = f"forbidden.test:{args.tls_port}"
    base = f"{'http://127.0.0.1' if args.plain else 'https://forbidden.test'}:{args.tls_port}"
    package_path = "/flat/owned.testpkg/1.0.0/owned.testpkg.1.0.0.nupkg"

    def registration():
        entry = {"@id": f"{base}/registration/owned.testpkg/1.0.0.json",
                 "catalogEntry": {"@id": f"{base}/registration/owned.testpkg/1.0.0.json",
                                  "id": "Owned.TestPkg", "version": "1.0.0",
                                  "authors": "owned-lab", "description": "Inert owned target test",
                                  "dependencyGroups": []},
                 "packageContent": base + package_path}
        page = {"@id": f"{base}/registration/owned.testpkg/1.0.0-1.0.0.json",
                "count": 1, "lower": "1.0.0", "upper": "1.0.0", "items": [entry]}
        return {"count": 1, "items": [page]}

    async def handle_tls(reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            lines = head.decode("iso-8859-1").split("\r\n")
            headers = dict((x.split(":", 1)[0].lower(), x.split(":", 1)[1].strip())
                           for x in lines[1:] if ":" in x)
            request_path = lines[0].split(" ", 2)[1]
            auth = headers.get("authorization", "")
            if auth and args.capture_auth and not args.capture_auth.exists():
                fd = os.open(args.capture_auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as capture:
                    capture.write(auth)
            emit(args.log, event="request", case=args.case, request=lines[0],
                 host=headers.get("host", ""), auth_sha256=hashlib.sha256(auth.encode()).hexdigest()
                 if auth else None, auth_scheme=auth.split(" ", 1)[0] if auth else None)
            if not auth:
                status = "401 Unauthorized"
                body = b""
                extra = "WWW-Authenticate: Basic realm=\"owned-feed\"\r\n"
            else:
                status = "200 OK"
                if args.nupkg is None:
                    body = b'{"version":"3.0.0","resources":[]}'
                    extra = "Content-Type: application/json\r\n"
                elif request_path == "/index.json":
                    body = json.dumps({"version":"3.0.0","resources":[
                        {"@id":f"{base}/flat/", "@type":"PackageBaseAddress/3.0.0"},
                        {"@id":f"{base}/registration/", "@type":"RegistrationsBaseUrl"}]}).encode()
                    extra = "Content-Type: application/json\r\n"
                elif request_path == "/registration/owned.testpkg/index.json":
                    body = json.dumps(registration()).encode()
                    extra = "Content-Type: application/json\r\n"
                elif request_path == "/registration/owned.testpkg/1.0.0-1.0.0.json":
                    body = json.dumps(registration()["items"][0]).encode()
                    extra = "Content-Type: application/json\r\n"
                elif request_path == "/registration/owned.testpkg/1.0.0.json":
                    body = json.dumps(registration()["items"][0]["items"][0]).encode()
                    extra = "Content-Type: application/json\r\n"
                elif request_path == "/flat/owned.testpkg/index.json":
                    body = b'{"versions":["1.0.0"]}'
                    extra = "Content-Type: application/json\r\n"
                elif request_path == package_path:
                    body = args.nupkg.read_bytes()
                    extra = "Content-Type: application/octet-stream\r\n"
                else:
                    status = "404 Not Found"
                    body = b""
                    extra = "Content-Type: text/plain\r\n"
            writer.write((f"HTTP/1.1 {status}\r\n{extra}Content-Length: {len(body)}\r\n"
                          "Connection: close\r\n\r\n").encode() + body)
            await writer.drain()
        except Exception as exc:
            emit(args.log, event="tls_error", case=args.case, error=repr(exc))
        finally:
            writer.close()
            await writer.wait_closed()

    async def pipe(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, BrokenPipeError):
            pass
        finally:
            writer.close()

    async def handle_proxy(reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            first = head.decode("iso-8859-1").split("\r\n", 1)[0]
            emit(args.log, event="connect", case=args.case, request=first)
            if first != f"CONNECT {expected_host} HTTP/1.1":
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            tls_reader, tls_writer = await asyncio.open_connection("127.0.0.1", args.tls_port)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(pipe(reader, tls_writer), pipe(tls_reader, writer))
        except Exception as exc:
            emit(args.log, event="proxy_error", case=args.case, error=repr(exc))
        finally:
            writer.close()
            await writer.wait_closed()

    tls_server = await asyncio.start_server(handle_tls, "127.0.0.1", args.tls_port, ssl=context)
    proxy_server = await asyncio.start_server(handle_proxy, "127.0.0.1", args.proxy_port)
    emit(args.log, event="ready", case=args.case, tls_port=args.tls_port, proxy_port=args.proxy_port)
    print("READY", flush=True)
    async with tls_server, proxy_server:
        await asyncio.gather(tls_server.serve_forever(), proxy_server.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
