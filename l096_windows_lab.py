#!/usr/bin/env python3
"""Owned Windows lab: stock NuGet same-origin credential replay with inert values only."""
import sys
from pathlib import Path

GATEWAY_SOURCE = '''#!/usr/bin/env python3
"""One-coordinate A/B restore order test with no backend challenge hold."""
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time

SDK = sys.argv[1]
TASK_MODE = sys.argv[3] if len(sys.argv) > 3 else "one_invocation"
assert TASK_MODE in ("one_invocation", "separate_processes")
ORDER = sys.argv[4] if len(sys.argv) > 4 else "BA"
assert ORDER in ("AB", "BA")
MODE = f"paired_order_{ORDER.lower()}"
CREDS = "plugin_dual"
PARALLEL = "serial"
AUDIT_PORT = sys.argv[2] if len(sys.argv) > 2 else "same"
assert AUDIT_PORT in ("same", "other")
ROOT = Path(__file__).resolve().parent
RUN = Path(tempfile.mkdtemp(prefix=f"run-{SDK.replace('.', '_')}-{MODE}-{CREDS}-", dir=ROOT))
AUDIT_PACKAGE = "Owned.L096"
AUTH = "Basic " + base64.b64encode(b"feed-a-user:inert-feed-a-secret-096").decode()
B_AUTH = "Basic " + base64.b64encode(b"feed-b-user:inert-feed-b-secret-096").decode()
PLUGIN = Path(os.environ["L096_PLUGIN_DLL"])


def main():
    marker = RUN / "a-authorized.marker"
    marker.unlink(missing_ok=True)
    logs = {role: RUN / f"backend-{role}.jsonl" for role in ("a", "b")}
    for log in logs.values():
        log.unlink(missing_ok=True)
    children = {}
    ports = {}
    backend_env_has_secret = {}
    for role in ("a", "b"):
        backend_env = {key: os.environ[key] for key in
                       ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT")
                       if key in os.environ}
        backend_env["PYTHONDONTWRITEBYTECODE"] = "1"
        backend_env["L096_WAIT_FOR_A"] = "0"
        if role == "a":
            backend_env["L096_EXPECTED_AUTH"] = AUTH
            backend_env["L096_PACKAGE_ID"] = AUDIT_PACKAGE
            if MODE == "audit_no_auth":
                backend_env["L096_A_PUBLIC"] = "1"
        elif CREDS in ("plugin_dual", "config_dual"):
            backend_env["L096_EXPECTED_B_AUTH"] = B_AUTH
        backend_env_has_secret[role] = any(value == AUTH for value in backend_env.values())
        process = subprocess.Popen([sys.executable, str(ROOT / "backend_process.py"), role, str(logs[role]), str(marker)], env=backend_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ports[role] = int(process.stdout.readline().strip())
        children[role] = process

    class Gateway(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            role = "a" if self.path.startswith("/a/") else "b" if self.path.startswith("/b/") else None
            if role is None:
                self.send_error(404)
                return
            upstream = http.client.HTTPConnection("127.0.0.1", ports[role], timeout=35)
            headers = {"X-Gateway-Origin": f"https://localhost:{self.server.server_port}"}
            if self.headers.get("Authorization") is not None:
                headers["Authorization"] = self.headers["Authorization"]
            upstream.request("GET", self.path, headers=headers)
            response = upstream.getresponse()
            body = response.read()
            self.send_response(response.status)
            for name in ("Content-Type", "WWW-Authenticate"):
                value = response.getheader(name)
                if value is not None:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            upstream.close()

    gateway = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(ROOT / "certs/l096-localhost.crt"), str(ROOT / "certs/l096-localhost.key"))
    gateway.socket = tls.wrap_socket(gateway.socket, server_side=True)
    thread = threading.Thread(target=gateway.serve_forever, daemon=True)
    thread.start()
    origin = f"https://localhost:{gateway.server_port}"
    gateway_b = None
    if AUDIT_PORT == "other":
        gateway_b = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        gateway_b.socket = tls.wrap_socket(gateway_b.socket, server_side=True)
        threading.Thread(target=gateway_b.serve_forever, daemon=True).start()
    b_origin = f"https://localhost:{gateway_b.server_port}" if gateway_b else origin
    a = origin + "/a/index.json"
    b = b_origin + "/b/index.json"

    (RUN / "global.json").write_text(json.dumps({"sdk": {"version": SDK, "rollForward": "disable"}}))
    target_framework = "net10.0"
    (RUN / "A.csproj").write_text(f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>{target_framework}</TargetFramework><NuGetAudit>false</NuGetAudit></PropertyGroup><ItemGroup><PackageReference Include="{AUDIT_PACKAGE}" Version="1.0.0" /></ItemGroup></Project>')
    (RUN / "B.csproj").write_text(f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>{target_framework}</TargetFramework><NuGetAudit>true</NuGetAudit></PropertyGroup><ItemGroup><PackageReference Include="{AUDIT_PACKAGE}" Version="1.0.0" /></ItemGroup></Project>')
    local_source = RUN / "local-source"
    local_source.mkdir()
    shutil.copyfile(ROOT / "packages" / f"{AUDIT_PACKAGE}.1.0.0.nupkg", local_source / f"{AUDIT_PACKAGE}.1.0.0.nupkg")
    (RUN / "A.NuGet.Config").write_text(f'<configuration><packageSources><clear/><add key="FeedA" value="{a}"/></packageSources><packageSourceMapping><packageSource key="FeedA"><package pattern="{AUDIT_PACKAGE}"/></packageSource></packageSourceMapping></configuration>')
    (RUN / "B.NuGet.Config").write_text(f'<configuration><packageSources><clear/><add key="Local" value="{local_source}"/></packageSources><packageSourceMapping><packageSource key="Local"><package pattern="{AUDIT_PACKAGE}"/></packageSource></packageSourceMapping><auditSources><clear/><add key="AuditB" value="{b}"/></auditSources></configuration>')
    task_xml = ''.join(f'<MSBuild Projects="{role}.csproj" Targets="Restore" Properties="RestoreConfigFile={role}.NuGet.Config;RestorePackagesPath={role.lower()}-packages"/>' for role in ORDER)
    (RUN / "Orchestrator.proj").write_text(f'<Project><Target Name="Run">{task_xml}</Target></Project>')
    env = os.environ.copy()
    env.pop("NuGetPackageSourceCredentials_FeedA", None)
    env.pop("ARTIFACTS_CREDENTIALPROVIDER_EXTERNAL_FEED_ENDPOINTS", None)
    if CREDS in ("plugin", "plugin_dual"):
        env["NUGET_PLUGIN_PATHS"] = str(PLUGIN)
        endpoint_credentials = [{"endpoint": a, "username": "feed-a-user", "password": "inert-feed-a-secret-096"}]
        if CREDS == "plugin_dual":
            endpoint_credentials.append({"endpoint": b, "username": "feed-b-user", "password": "inert-feed-b-secret-096"})
        env["ARTIFACTS_CREDENTIALPROVIDER_EXTERNAL_FEED_ENDPOINTS"] = json.dumps({"endpointCredentials": endpoint_credentials})
    elif CREDS == "environment":
        env["NUGET_PLUGIN_PATHS"] = ""
        env["NuGetPackageSourceCredentials_FeedA"] = "Username=feed-a-user;Password=inert-feed-a-secret-096"
    else:
        env["NUGET_PLUGIN_PATHS"] = ""
    env["ARTIFACTS_CREDENTIALPROVIDER_SESSIONTOKENCACHE_ENABLED"] = "false"
    env["ARTIFACTS_CREDENTIALPROVIDER_MSAL_FILECACHE_ENABLED"] = "false"
    env["NUGET_PACKAGES"] = str(RUN / "packages")
    env["DOTNET_CLI_HOME"] = str(RUN / "dotnet-home")
    if TASK_MODE == "one_invocation":
        commands = [[shutil.which("dotnet"), "msbuild", "Orchestrator.proj", "/t:Run", "/m:1", "/nr:false", "/v:normal"]]
    else:
        commands = [[shutil.which("dotnet"), "restore", f"{role}.csproj", "--configfile", f"{role}.NuGet.Config", "--packages", f"{role.lower()}-packages", "--verbosity", "normal"] for role in "AB"]
    start = time.time()
    stdout_path = RUN / "restore.stdout"
    stderr_path = RUN / "restore.stderr"
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        exit_codes = []
        process_ids = []
        restore = {}
        for command in commands:
            restore_process = subprocess.Popen(command, cwd=RUN, env=env,
                                               stdout=stdout_file, stderr=stderr_file)
            process_ids.append(restore_process.pid)
            try:
                restore_process.wait(timeout=150)
                exit_codes.append(restore_process.returncode)
            except subprocess.TimeoutExpired:
                restore_process.kill()
                restore_process.wait(timeout=5)
                restore = {"timeout": 150}
                break
            if restore_process.returncode != 0:
                break
        if not restore:
            restore = {"exitCode": exit_codes[-1] if exit_codes else None}
        restore["processIds"] = process_ids
        restore["subprocessExitCodes"] = exit_codes
    restore["stdout"] = stdout_path.read_text(errors="replace")[-12000:]
    restore["stderr"] = stderr_path.read_text(errors="replace")[-3000:]
    time.sleep(2)
    actor = subprocess.run(
        [sys.executable, str(ROOT / "actor_replay.py"), str(logs["b"]), origin + "/a/private", str(ROOT / "certs/l096-ca.crt")],
        env={**{key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATHEXT") if key in os.environ}, "PYTHONDONTWRITEBYTECODE": "1"},
        text=True, capture_output=True, timeout=15)
    actor_result = json.loads(actor.stdout) if actor.returncode == 0 else {"exitCode": actor.returncode, "stderr": actor.stderr[-3000:]}
    gateway.shutdown()
    gateway.server_close()
    if gateway_b:
        gateway_b.shutdown()
        gateway_b.server_close()
    observed = []
    for role in ("a", "b"):
        if logs[role].exists():
            observed.extend(json.loads(line) for line in logs[role].read_text().splitlines())
    for child in children.values():
        child.terminate()
        child.wait(timeout=5)
    b_events = [event for event in observed if event.get("backend") == "b"]
    a_events = [event for event in observed if event.get("backend") == "a"]
    b_has_a = any(event.get("authorization") == AUTH for event in b_events)
    b_has_b = any(event.get("authorization") == B_AUTH for event in b_events)
    a_has_a = any(event.get("authorization") == AUTH for event in a_events)
    expected_disclosure = ORDER == "AB" and AUDIT_PORT == "same"
    actor_ok = (actor_result.get("pass") is True if expected_disclosure else
                actor_result.get("noCredential", {}).get("status") == 401 and
                actor_result.get("wrongCredential", {}).get("status") == 401 and
                actor_result.get("capturedCredential", {}).get("status") == 401)
    package_ok = all((RUN / f"{role}-packages" / "owned.l096" / "1.0.0" /
                      "lib" / "net10.0" / "Owned.L096.dll").exists() for role in ("a", "b"))
    passed = (restore.get("exitCode") == 0 and a_has_a and marker.exists() and
              b_has_a == expected_disclosure and b_has_b and actor_ok and
              not backend_env_has_secret["b"] and package_ok)
    summary = {
        "sdk": SDK, "order": ORDER, "auditPort": AUDIT_PORT,
        "taskMode": TASK_MODE, "backendEnvironmentHasASecret": backend_env_has_secret,
        "aAuthorized": marker.exists(), "aReceivedOwnCredential": a_has_a,
        "bReceivedACredential": b_has_a, "bReceivedOwnCredential": b_has_b,
        "bEventCount": len(b_events), "packageInstalledInBothProjects": package_ok,
        "restoreExitCode": restore.get("exitCode"), "restoreTimeout": restore.get("timeout"),
        "actorReplay": actor_result, "expectedDisclosure": expected_disclosure,
        "elapsedSeconds": round(time.time()-start, 2), "pass": passed,
    }
    print(json.dumps(summary, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
'''

BACKEND_SOURCE = '''#!/usr/bin/env python3
"""Isolated owned NuGet V3 backend; B receives no A credential configuration."""
import http.server
import json
import os
from pathlib import Path
import sys
import time

ROLE = sys.argv[1]
LOG = Path(sys.argv[2])
MARKER = Path(sys.argv[3])
assert ROLE in ("a", "b")
EXPECTED = os.environ.get("L096_EXPECTED_AUTH") if ROLE == "a" else None
EXPECTED_B = os.environ.get("L096_EXPECTED_B_AUTH") if ROLE == "b" else None
PACKAGE_ID = os.environ.get("L096_PACKAGE_ID", "Owned.Nu001").lower()
PACKAGE = Path(__file__).resolve().parent / "packages" / f"{os.environ.get('L096_PACKAGE_ID', 'Owned.Nu001')}.1.0.0.nupkg"
assert (ROLE == "a") == (EXPECTED is not None)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        auth = self.headers.get("Authorization")
        with LOG.open("a") as output:
            output.write(json.dumps({"backend": ROLE, "pid": os.getpid(), "path": path, "authorization": auth}) + "\n")
        if ROLE == "b" and auth is None and os.environ.get("L096_WAIT_FOR_A") == "1":
            limit = time.monotonic() + 8
            while not MARKER.exists() and time.monotonic() < limit:
                time.sleep(0.02)
        if ROLE == "a" and auth == EXPECTED:
            MARKER.write_text("A authenticated")
        a_public_path = ROLE == "a" and os.environ.get("L096_A_PUBLIC") == "1" and path != "/a/private"
        authorized = (auth == EXPECTED or a_public_path) if ROLE == "a" else (auth == EXPECTED_B if EXPECTED_B is not None else auth not in (None, "Basic Og=="))
        if not authorized:
            status = 401
            body = b"denied"
            content_type = "text/plain"
        elif ROLE == "a" and path == "/a/private":
            status = 200
            body = b"A-private-inert-096"
            content_type = "text/plain"
        elif path.endswith("/index.json") and path.count("/") == 2:
            status = 200
            origin = self.headers["X-Gateway-Origin"]
            body = json.dumps({"version": "3.0.0", "resources": [
                {"@id": origin + f"/{ROLE}/registration/", "@type": "RegistrationsBaseUrl/3.6.0"},
                {"@id": origin + f"/{ROLE}/flat/", "@type": "PackageBaseAddress/3.0.0"},
                *([{"@id": origin + "/b/vuln/index.json", "@type": "VulnerabilityInfo/6.7.0"}] if ROLE == "b" else []),
            ]}).encode()
            content_type = "application/json"
        elif ROLE == "b" and path == "/b/vuln/index.json":
            status = 200
            origin = self.headers["X-Gateway-Origin"]
            body = json.dumps([{"@name": "base", "@id": origin + "/b/vuln/base.json", "@updated": "2026-11-27T00:00:00Z"}]).encode()
            content_type = "application/json"
        elif ROLE == "b" and path == "/b/vuln/base.json":
            status = 200
            body = b"{}"
            content_type = "application/json"
        elif ROLE == "a" and path == f"/a/flat/{PACKAGE_ID}/index.json":
            status = 200
            body = b'{"versions":["1.0.0"]}'
            content_type = "application/json"
        elif ROLE == "a" and path == f"/a/flat/{PACKAGE_ID}/1.0.0/{PACKAGE_ID}.1.0.0.nupkg":
            status = 200
            body = PACKAGE.read_bytes()
            content_type = "application/octet-stream"
        else:
            status = 404
            body = b"missing"
            content_type = "text/plain"
        self.send_response(status)
        if status == 401:
            self.send_header("WWW-Authenticate", f'Basic realm="feed-{ROLE.upper()}"')
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(server.server_port, flush=True)
server.serve_forever()
'''

ACTOR_SOURCE = '''#!/usr/bin/env python3
"""B backend operator reuses only the Basic header captured in its own log."""
import hashlib
import json
import os
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.request

log_path, target, ca_cert = sys.argv[1:4]
assert "L096_EXPECTED_AUTH" not in os.environ
assert "ARTIFACTS_CREDENTIALPROVIDER_EXTERNAL_FEED_ENDPOINTS" not in os.environ
events = [json.loads(line) for line in Path(log_path).read_text().splitlines()]
captured = [event.get("authorization") for event in events
            if event.get("backend") == "b"
            and (event.get("authorization") or "").startswith("Basic ")
            and event.get("authorization") != "Basic Og=="]
context = ssl.create_default_context(cafile=ca_cert)

def request(authorization):
    headers = {} if authorization is None else {"Authorization": authorization}
    req = urllib.request.Request(target, headers=headers)
    try:
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
            return {"status": response.status, "body": response.read().decode()}
    except urllib.error.HTTPError as error:
        return {"status": error.code, "body": error.read().decode()}

result = {
    "actorHasASecretInEnvironment": False,
    "bCapturedHeaderCount": len(captured),
    "bCapturedDistinctHeaderHashes": sorted({hashlib.sha256(x.encode()).hexdigest() for x in captured}),
    "noCredential": request(None),
    "wrongCredential": request("Basic d3Jvbmc6d3Jvbmc="),
    "capturedCredential": request(captured[0]) if captured else None,
}
result["pass"] = (
    result["noCredential"]["status"] == 401
    and result["wrongCredential"]["status"] == 401
    and result["capturedCredential"] == {"status": 200, "body": "A-private-inert-096"}
)
result["deniedControlPass"] = (
    result["noCredential"]["status"] == 401
    and result["wrongCredential"]["status"] == 401
    and len(captured) == 0
    and result["capturedCredential"] is None
)
print(json.dumps(result))
'''

CERT_SOURCE = '''"""Generate an ephemeral localhost-only TLS chain for a Windows runner."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = Path(__file__).resolve().parent / "certs"
out.mkdir(exist_ok=True)
now = datetime.now(timezone.utc)
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned L096 ephemeral test CA")])
ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
      .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=1))
      .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
      .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                    content_commitment=False, data_encipherment=False,
                                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                                    encipher_only=False, decipher_only=False), critical=True)
      .sign(ca_key, hashes.SHA256()))
leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True,
                                      content_commitment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=False, crl_sign=False,
                                      encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256()))
(out / "l096-ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
(out / "l096-localhost.crt").write_bytes(leaf.public_bytes(serialization.Encoding.PEM) +
                                          ca.public_bytes(serialization.Encoding.PEM))
(out / "l096-localhost.key").write_bytes(leaf_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()))
print("generated ephemeral localhost TLS chain")
'''


root = Path(__file__).resolve().parent
if len(sys.argv) > 1 and sys.argv[1] == "setup-cert":
    exec(CERT_SOURCE, {"__file__": str(root / "generate_cert.py"), "__name__": "__main__"})
else:
    (root / "backend_process.py").write_text(BACKEND_SOURCE)
    (root / "actor_replay.py").write_text(ACTOR_SOURCE)
    exec(GATEWAY_SOURCE, {"__file__": str(root / "paired_order_gateway.py"), "__name__": "__main__"})
