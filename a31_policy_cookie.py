#!/usr/bin/env python3
"""Run a disposable policy-issued leaf through stock macOS .NET cookie auth.

This script prints only checked summary fields. Raw inert cookie headers stay in
temporary runner files and are never uploaded as artifacts or logged publicly.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "a31_policy_cookie_Program.cs"
INPUT = HERE / "fixture"
KEYCHAIN = "/Library/Keychains/System.keychain"
LABEL = "A31 owned root"


def run(args, *, timeout=30, env=None):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, timeout=timeout, env=env)


def require_ok(args, *, timeout=30, env=None):
    result = run(args, timeout=timeout, env=env)
    if result.returncode:
        raise RuntimeError("command failed: " + args[0] + " " + str(result.returncode))
    return result.stdout


def fingerprint(cert):
    output = require_ok(["openssl", "x509", "-in", str(cert), "-noout",
                         "-fingerprint", "-sha256"])
    return output.strip().split("=", 1)[1].replace(":", "").lower()


source = SOURCE.read_text()
for required in ("CookieSecurePolicy.Always", "Cookie.HttpOnly = true",
                 "Cookie.SameSite = SameSiteMode.Strict", "new CookieContainer()",
                 "Proxy = new WebProxy", "RequireAuthorization()"):
    assert required in source
for forbidden in ("CertificateChainPolicy", "CustomRootTrust",
                  "ServerCertificateValidationCallback", "ConnectCallback"):
    assert forbidden not in source
assert all((INPUT / name).is_file() for name in (
    "root.pem", "issuer.pem", "actor-leaf.key", "attack-issued.pem",
    "allowed-issued.pem", "denied-issued.pem", "direct-root.cert.pem",
    "direct-root.key"))

with tempfile.TemporaryDirectory(prefix="a31-policy-cookie-") as tmp:
    base = Path(tmp)
    fixture = base / "fixtures"
    project = base / "project"
    fixture.mkdir()
    project.mkdir()
    shutil.copy2(SOURCE, project / "Program.cs")
    (project / "ProtectedReplay.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup>'
        '<TargetFramework>net11.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings>'
        '<Nullable>enable</Nullable><NuGetAudit>false</NuGetAudit>'
        '</PropertyGroup></Project>')
    require_ok(["openssl", "x509", "-in", str(INPUT / "root.pem"),
                "-outform", "der", "-out", str(fixture / "root.der")])
    require_ok(["openssl", "x509", "-in", str(INPUT / "issuer.pem"),
                "-outform", "der", "-out", str(fixture / "intermediate.der")])
    require_ok(["openssl", "x509", "-in", str(INPUT / "direct-root.cert.pem"),
                "-outform", "der", "-out", str(fixture / "valid_direct_root.der")])
    pairs = {
        "attack_no_san_forbidden_cn": ("attack-issued.pem", "actor-leaf.key"),
        "denied_forbidden_san": ("denied-issued.pem", "actor-leaf.key"),
        "allowed_san_wrong_host": ("allowed-issued.pem", "actor-leaf.key"),
        "valid_direct_root": ("direct-root.cert.pem", "direct-root.key"),
    }
    for label, (cert, key) in pairs.items():
        require_ok(["openssl", "pkcs12", "-export", "-inkey", str(INPUT / key),
                    "-in", str(INPUT / cert), "-out", str(fixture / (label + ".pfx")),
                    "-passout", "pass:"])
    attack_fingerprint = fingerprint(INPUT / "attack-issued.pem")
    denied_fingerprint = fingerprint(INPUT / "denied-issued.pem")
    attack_text = require_ok(["openssl", "x509", "-in", str(INPUT / "attack-issued.pem"),
                              "-noout", "-text"])
    issuer_text = require_ok(["openssl", "x509", "-in", str(INPUT / "issuer.pem"),
                              "-noout", "-text"])
    assert "Subject Alternative Name" not in attack_text
    assert "CN=forbidden.test" in attack_text or "CN = forbidden.test" in attack_text
    assert "X509v3 Name Constraints: critical" in issuer_text
    assert "DNS:allowed.test" in issuer_text
    env = os.environ.copy()
    env.update(DOTNET_CLI_HOME=str(base / "cli-home"),
               DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
               DOTNET_CLI_TELEMETRY_OPTOUT="1")
    require_ok(["dotnet", "build", str(project / "ProtectedReplay.csproj"),
                "-c", "Release", "--disable-build-servers"], timeout=120, env=env)
    sdk = require_ok(["dotnet", "--version"], env=env).strip()
    runtime_list = require_ok(["dotnet", "--list-runtimes"], env=env)
    assert "Microsoft.NETCore.App 11.0.0 " in runtime_list
    assert "Microsoft.AspNetCore.App 11.0.0 " in runtime_list
    assert run(["security", "find-certificate", "-c", LABEL, KEYCHAIN]).returncode != 0
    pretrust = run(["security", "verify-cert", "-c", str(fixture / "valid_direct_root.der"),
                    "-p", "ssl", "-n", "forbidden.test"], timeout=25)
    assert pretrust.returncode != 0
    added = False
    summary = None
    try:
        require_ok(["sudo", "security", "add-trusted-cert", "-d", "-p", "basic",
                    "-p", "ssl", "-r", "trustRoot", "-k", KEYCHAIN,
                    str(fixture / "root.der")], timeout=60)
        added = True
        require_ok(["security", "verify-cert", "-c", str(fixture / "valid_direct_root.der"),
                    "-p", "ssl", "-n", "forbidden.test"], timeout=25)
        raw = base / "raw-cookie.jsonl"
        err = base / "proxy.log"
        with os.fdopen(os.open(raw, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out, \
             os.fdopen(os.open(err, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stderr:
            process = subprocess.run(["dotnet", str(project / "bin/Release/net11.0/ProtectedReplay.dll"),
                                      str(fixture)], stdout=out, stderr=stderr,
                                     timeout=80, env=env)
        rows = [json.loads(line) for line in raw.read_bytes().splitlines()]
        assert process.returncode == 0
        assert [r["step"] for r in rows] == ["cookie_flags", "auth_baselines", "intercept",
                                              "intercept", "intercept", "replay", "intercept", "verdict"]
        flags, auth, denied, actor, wrong, replay, repeat, verdict = rows
        assert all(flags[k] for k in ("hardened_flags", "secure", "http_only", "same_site_strict"))
        assert (auth["no_cookie_status"], auth["no_owner_proof_status"], auth["issue_status"],
                auth["valid_status"], auth["writes"], auth["jar_contains_issued_cookie"]) == \
               (401, 403, 204, 200, 1, True)
        for row, label in ((denied, "denied_forbidden_san"),
                           (wrong, "allowed_san_wrong_host")):
            assert row["certificate"] == label and row["victim_status"] == 0
            assert not row["captured_cookie"] and not row["raw_server_request"] and row["writes"] == 1
        for row in (actor, repeat):
            assert row["certificate"] == "attack_no_san_forbidden_cn"
            assert row["victim_status"] == 200 and row["captured_cookie"]
            assert row["cookie_equals_issued"] and row["captured_cookie_sha256"] == auth["issued_cookie_sha256"]
            assert "\r\nCookie: G09L016OwnedSession=" in row["raw_server_request"]
            assert "X-Owner-Proof" not in row["raw_server_request"]
        assert actor["writes"] == 1
        assert (replay["wrong_cookie_status"], replay["writes_after_wrong_cookie"],
                replay["attacker_replay_status"], replay["writes"]) == (401, 1, 200, 2)
        assert replay["replay_cookie_sha256"] == auth["issued_cookie_sha256"]
        assert repeat["writes"] == verdict["writes"] == 2 and verdict["pass"]
        assert err.read_bytes().splitlines() == [b"proxy connect=True error=none"] * 10
        summary = {"result": "pass", "sdk": sdk, "runtime": "11.0.0",
                   "actor_leaf_sha256": attack_fingerprint,
                   "admin_signed_denied_leaf_sha256": denied_fingerprint,
                   "artifact_root_sha256": hashlib.sha256((fixture / "root.der").read_bytes()).hexdigest(),
                   "raw_cookie_log_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
                   "strict_cookie_flags": True, "os_root_trust": True,
                   "no_custom_chain_policy_or_validation_callback": True,
                   "byte_forwarding_connect_count": 10,
                   "guard_statuses": {"no_cookie": 401, "no_owner_proof": 403,
                                      "wrong_cookie": 401, "valid": 200,
                                      "captured_replay": 200},
                   "denied_san_and_wrong_host_captured_cookie": False,
                   "writes_before_after_replay": [1, 2], "attack_repeat_passed": True}
    finally:
        if added or run(["security", "find-certificate", "-c", LABEL, KEYCHAIN]).returncode == 0:
            require_ok(["sudo", "security", "delete-certificate", "-c", LABEL, KEYCHAIN],
                        timeout=60)
        assert run(["security", "find-certificate", "-c", LABEL, KEYCHAIN]).returncode != 0
    assert summary is not None
    summary["owned_root_removed"] = True
    print(json.dumps(summary, indent=2))
