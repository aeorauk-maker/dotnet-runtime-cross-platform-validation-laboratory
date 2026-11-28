#!/usr/bin/env python3
"""Disposable stock Blazor Identity publish lifecycle validation.

All accounts and factors are generated inside this job and used on loopback.
Only Boolean outcomes, hashes, and the SDK version are emitted on success.
"""

import base64
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import struct
import subprocess
import time
from urllib.parse import urlsplit

import requests


ROOT = Path.cwd() / "runner-identity-state"
SOURCE = ROOT / "source"
CLONE = ROOT / "clone"
LIVE = ROOT / "live"
DB = Path("Data/app.db")
PORT = 17799
BASE = f"http://127.0.0.1:{PORT}"
HOST = f"owned.example.test:{PORT}"
EMAIL = f"owned-{secrets.token_hex(6)}@example.test"
INITIAL = "I!" + secrets.token_urlsafe(24)
RECOVERED = "R!" + secrets.token_urlsafe(24)
CAPTURED = "C!" + secrets.token_urlsafe(24)


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def run(label, args, cwd=None, timeout=300):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{label}: exit {result.returncode}: {result.stdout[-300:]} {result.stderr[-300:]}")
    return result.stdout.strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def row(path):
    with sqlite3.connect(path) as db:
        return db.execute("SELECT EmailConfirmed, TwoFactorEnabled, PasswordHash, SecurityStamp FROM AspNetUsers WHERE NormalizedEmail=?",
                          (EMAIL.upper(),)).fetchone()


def recovery_codes(path):
    with sqlite3.connect(path) as db:
        found = db.execute("SELECT Value FROM AspNetUserTokens WHERE Name='RecoveryCodes'").fetchone()
    return [] if found is None else found[0].split(";")


def totp(key):
    compact = key.replace(" ", "").upper()
    raw = base64.b32decode(compact + "=" * ((-len(compact)) % 8))
    counter = struct.pack(">Q", int(time.time()) // 30)
    mac = hmac.new(raw, counter, hashlib.sha1).digest()
    index = mac[-1] & 15
    return f"{(struct.unpack('>I', mac[index:index + 4])[0] & 0x7fffffff) % 1000000:06d}"


class Host:
    def __init__(self):
        self.proc = None
        self.log = None

    def start(self, label):
        require(self.proc is None, "host already started")
        self.log = (ROOT / f"{label}.log").open("w")
        env = dict(os.environ, ASPNETCORE_ENVIRONMENT="Production", ASPNETCORE_URLS=BASE)
        self.proc = subprocess.Popen(["dotnet", "Id009Runner.dll"], cwd=LIVE,
                                     env=env, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            if self.proc.poll() is not None:
                break
            try:
                requests.get(BASE + "/", headers={"Host": HOST}, timeout=1)
                return
            except requests.RequestException:
                time.sleep(.15)
        self.stop()
        raise RuntimeError(f"{label}: stock host did not start")

    def stop(self):
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
            self.proc = None
        if self.log is not None:
            self.log.close()
            self.log = None

    def session(self):
        s = requests.Session()
        s.trust_env = False
        return s

    def get(self, session, route):
        return session.get(BASE + route, headers={"Host": HOST},
                           allow_redirects=False, timeout=30)

    def post(self, session, route, data):
        return session.post(BASE + route, headers={"Host": HOST}, data=data,
                            allow_redirects=False, timeout=30)

    def protected(self, session):
        response = self.get(session, "/Account/Manage/ChangePassword")
        return response.status_code == 200 and 'name="Input.OldPassword"' in response.text

    def login(self, password):
        session = self.session()
        response = self.post(session, "/Account/Login",
                             {"_handler": "login", "Input.Email": EMAIL, "Input.Password": password})
        return session, response, self.protected(session)

    def recovery_login(self, password, code):
        session, first, protected = self.login(password)
        require(not protected and "LoginWith2fa" in first.headers.get("Location", ""),
                "password step did not require 2FA")
        answer = self.post(session, "/Account/LoginWithRecoveryCode",
                           {"_handler": "login-with-recovery-code", "Input.RecoveryCode": code})
        return session, answer.status_code, self.protected(session)


def checkpoint(path):
    with sqlite3.connect(path) as db:
        value = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    require(value == (0, 0, 0), "WAL checkpoint did not complete")


def main():
    ROOT.mkdir(exist_ok=False)
    (ROOT / "global.json").write_text('{"sdk":{"version":"11.0.100","rollForward":"disable"}}\n')
    sdk = run("sdk-version", ["dotnet", "--version"], ROOT)
    require(sdk == "11.0.100", "unexpected SDK version")
    run("new", ["dotnet", "new", "blazor", "-au", "Individual", "-o", str(SOURCE),
                "-n", "Id009Runner", "--no-restore"], cwd=ROOT, timeout=180)
    run("gitignore", ["dotnet", "new", "gitignore", "-o", str(SOURCE)], timeout=120)
    source_db = SOURCE / DB
    live_db = LIVE / DB
    with sqlite3.connect(source_db) as db:
        require(db.execute("SELECT COUNT(*) FROM AspNetUsers").fetchone()[0] == 0,
                "shipped DB unexpectedly has users")
    run("initial-restore", ["dotnet", "restore", str(SOURCE), "--ignore-failed-sources"], timeout=300)
    run("initial-publish", ["dotnet", "publish", str(SOURCE), "--no-restore", "-c", "Release", "-o", str(LIVE)], timeout=300)
    host = Host()
    host.start("register-and-enroll")
    try:
        registration = host.session()
        response = host.post(registration, "/Account/Register",
                             {"_handler": "register", "Input.Email": EMAIL,
                              "Input.Password": INITIAL, "Input.ConfirmPassword": INITIAL})
        require(response.status_code == 302, "registration did not redirect")
        confirm_location = response.headers.get("Location", "")
        require("RegisterConfirmation" in confirm_location, "registration confirmation missing")
        parsed = urlsplit(confirm_location)
        page = host.get(registration, parsed.path + "?" + parsed.query)
        match = re.search(r'href="([^"]*Account/ConfirmEmail[^\"]*)"', page.text)
        require(page.status_code == 200 and match, "stock confirmation link missing")
        link = urlsplit(html.unescape(match.group(1)))
        host.get(registration, link.path + "?" + link.query)
        require(row(live_db)[0] == 1, "account not confirmed")
        owner, _, allowed = host.login(INITIAL)
        require(allowed, "initial protected login failed")
        setup = host.get(owner, "/Account/Manage/EnableAuthenticator")
        key_match = re.search(r"<kbd>([^<]+)</kbd>", setup.text)
        require(setup.status_code == 200 and key_match, "stock authenticator setup missing")
        key = key_match.group(1)
        host.post(owner, "/Account/Manage/EnableAuthenticator",
                  {"_handler": "send-code", "Input.Code": totp(key)})
        require(row(live_db)[1] == 1, "2FA enrollment failed")
        require(len(recovery_codes(live_db)) >= 3, "recovery codes missing")
    finally:
        host.stop()
    checkpoint(live_db)
    shutil.copyfile(live_db, source_db)
    source_sha = digest(source_db)
    codes = recovery_codes(source_db)
    code_a, code_b = codes[:2]
    require(row(source_db)[1] == 1, "source 2FA state missing")
    run("git-init", ["git", "init", "-q"], SOURCE)
    run("git-name", ["git", "config", "user.name", "Owned Validation"], SOURCE)
    run("git-email", ["git", "config", "user.email", "owned@lab.invalid"], SOURCE)
    run("git-add", ["git", "add", "."], SOURCE)
    staged = run("git-staged", ["git", "diff", "--cached", "--name-only"], SOURCE)
    require("Data/app.db" in staged.splitlines(), "account DB not tracked")
    run("git-commit", ["git", "commit", "-qm", "owned fixture"], SOURCE)
    commit = run("source-commit", ["git", "rev-parse", "HEAD"], SOURCE)
    require(run("source-status", ["git", "status", "--porcelain"], SOURCE) == "",
            "source changed after commit")
    host.start("consume-and-revoke")
    try:
        owner, status, allowed = host.recovery_login(INITIAL, code_a)
        require(status == 302 and allowed, "initial recovery code failed")
        require(len(recovery_codes(live_db)) == len(codes) - 1, "code not consumed")
        changed = host.post(owner, "/Account/Manage/ChangePassword",
                            {"_handler": "change-password", "Input.OldPassword": INITIAL,
                             "Input.NewPassword": RECOVERED, "Input.ConfirmPassword": RECOVERED})
        require(changed.status_code == 302, "password rotation failed")
        require(not host.login(INITIAL)[2], "old password still accepted")
        _, _, used_allowed = host.recovery_login(RECOVERED, code_a)
        require(not used_allowed, "consumed code still accepted")
        _, valid_status, other_allowed = host.recovery_login(RECOVERED, code_b)
        require(valid_status == 302 and other_allowed, "unused recovery code denied")
        require(len(recovery_codes(live_db)) == len(codes) - 2,
                "second code not consumed")
    finally:
        host.stop()
    checkpoint(live_db)
    changed_sha = digest(live_db)
    require(changed_sha != source_sha, "live DB did not change")
    time.sleep(1.1)
    run("same-commit-clone", ["git", "clone", "-q", str(SOURCE), str(CLONE)], ROOT)
    clone_db = CLONE / DB
    require(run("clone-commit", ["git", "rev-parse", "HEAD"], CLONE) == commit,
            "clone commit mismatch")
    require(digest(clone_db) == source_sha, "clone DB bytes mismatch")
    require(clone_db.stat().st_mtime_ns > live_db.stat().st_mtime_ns,
            "clone DB is not newer than live DB")
    run("clone-restore", ["dotnet", "restore", str(CLONE), "--ignore-failed-sources"], timeout=300)
    run("clone-publish", ["dotnet", "publish", str(CLONE), "--no-restore", "-c", "Release", "-o", str(LIVE)], timeout=300)
    require(digest(live_db) == source_sha, "stock publish did not restore source DB")
    require(len(recovery_codes(live_db)) == len(codes), "stock publish did not restore codes")
    host.start("post-publish-replay")
    try:
        _, _, wrong_allowed = host.recovery_login(INITIAL, "0000-0000")
        require(not wrong_allowed, "wrong code reached protected action")
        actor, replay_status, replay_allowed = host.recovery_login(INITIAL, code_a)
        require(replay_status == 302 and replay_allowed, "consumed code not revived")
        _, _, repeat_allowed = host.recovery_login(INITIAL, code_a)
        require(not repeat_allowed, "replayed code accepted twice")
        reset = host.post(actor, "/Account/Manage/ResetAuthenticator",
                          {"_handler": "reset-authenticator"})
        require(reset.status_code == 302 and row(live_db)[1] == 0,
                "stock authenticator reset failed")
        captured = host.post(actor, "/Account/Manage/ChangePassword",
                             {"_handler": "change-password", "Input.OldPassword": INITIAL,
                              "Input.NewPassword": CAPTURED, "Input.ConfirmPassword": CAPTURED})
        require(captured.status_code == 302, "exclusive password change failed")
    finally:
        host.stop()
    host.start("captured-restart")
    try:
        require(host.login(CAPTURED)[2], "captured password failed after restart")
        require(not host.login(INITIAL)[2], "old password still accepted after capture")
        require(not host.login(RECOVERED)[2], "owner password still accepted after capture")
        require(row(live_db)[1] == 0, "2FA unexpectedly enabled after restart")
    finally:
        host.stop()
    summary = {"sdk": sdk, "same_commit": True, "source_db_sha256": source_sha,
               "changed_db_sha256": changed_sha, "stock_publish_restored_db": True,
               "consumed_code_denied_before": True, "unused_code_valid_before": True,
               "wrong_code_denied_after": True, "consumed_code_replayed_after": True,
               "repeated_code_denied_after": True, "stock_2fa_reset": True,
               "exclusive_password_after_restart": True}
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
