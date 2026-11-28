#!/usr/bin/env python3
"""Disposable stock-publish join for a revoked 2FA cookie after real time."""

import hashlib
import html
import json
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import time
from urllib.parse import urlsplit

from runner_identity_state_deploy import (
    ROOT, SOURCE, CLONE, LIVE, DB, EMAIL, INITIAL, RECOVERED,
    Host, checkpoint, digest, row, run, require, totp,
)


def key_digest(path):
    with sqlite3.connect(path) as db:
        value = db.execute("SELECT Value FROM AspNetUserTokens WHERE Name='AuthenticatorKey'").fetchone()
    require(value is not None, "authenticator key absent")
    return hashlib.sha256(value[0].encode()).hexdigest()


def with_totp(host, password, key):
    session = host.session()
    first = host.post(session, "/Account/Login", {
        "_handler": "login", "Input.Email": EMAIL, "Input.Password": password,
    })
    require("LoginWith2fa" in first.headers.get("Location", ""), "2FA challenge absent")
    second = host.post(session, "/Account/LoginWith2fa", {
        "_handler": "login-with-2fa", "Input.TwoFactorCode": totp(key),
    })
    require(second.status_code == 302 and host.protected(session), "valid TOTP denied")
    return session


def main():
    ROOT.mkdir(exist_ok=False)
    (ROOT / "global.json").write_text('{"sdk":{"version":"11.0.100","rollForward":"disable"}}\n')
    sdk = run("sdk-version", ["dotnet", "--version"], ROOT)
    require(sdk == "11.0.100", "unexpected SDK")
    run("new", ["dotnet", "new", "blazor", "-au", "Individual", "-o", str(SOURCE),
                "-n", "Id009Runner", "--no-restore"], ROOT, timeout=180)
    run("gitignore", ["dotnet", "new", "gitignore", "-o", str(SOURCE)], ROOT, timeout=120)
    source_db, live_db = SOURCE / DB, LIVE / DB
    with sqlite3.connect(source_db) as db:
        require(db.execute("SELECT COUNT(*) FROM AspNetUsers").fetchone()[0] == 0,
                "shipped DB unexpectedly populated")
    run("restore", ["dotnet", "restore", str(SOURCE), "--ignore-failed-sources"], ROOT)
    run("publish-initial", ["dotnet", "publish", str(SOURCE), "--no-restore", "-c", "Release", "-o", str(LIVE)], ROOT)
    host = Host()
    host.start("register-enroll-issue")
    try:
        registration = host.session()
        registered = host.post(registration, "/Account/Register", {
            "_handler": "register", "Input.Email": EMAIL, "Input.Password": INITIAL,
            "Input.ConfirmPassword": INITIAL,
        })
        require(registered.status_code == 302, "registration failed")
        location = urlsplit(registered.headers.get("Location", ""))
        page = host.get(registration, location.path + "?" + location.query)
        match = re.search(r'href="([^"]*Account/ConfirmEmail[^"]*)"', page.text)
        require(page.status_code == 200 and match, "confirmation link absent")
        confirm = urlsplit(html.unescape(match.group(1)))
        host.get(registration, confirm.path + "?" + confirm.query)
        require(row(live_db)[0] == 1, "account unconfirmed")
        owner, _, allowed = host.login(INITIAL)
        require(allowed, "initial protected login failed")
        form = host.get(owner, "/Account/Manage/EnableAuthenticator")
        match = re.search(r"<kbd>([^<]+)</kbd>", form.text)
        require(form.status_code == 200 and match, "authenticator setup absent")
        key = match.group(1)
        host.post(owner, "/Account/Manage/EnableAuthenticator", {
            "_handler": "send-code", "Input.Code": totp(key),
        })
        require(row(live_db)[1] == 1, "2FA enrollment failed")
        original_key_digest = key_digest(live_db)
        former = with_totp(host, INITIAL, key)
        require(any("Identity.Application" in c.name for c in former.cookies),
                "stock auth cookie absent")
        held_cookie_jar = former.cookies.copy()
        issued_at = time.time()
    finally:
        host.stop()
    checkpoint(live_db)
    shutil.copyfile(live_db, source_db)
    source_sha = digest(source_db)
    run("git-init", ["git", "init", "-q"], SOURCE)
    run("git-name", ["git", "config", "user.name", "Owned Validation"], SOURCE)
    run("git-email", ["git", "config", "user.email", "owned@lab.invalid"], SOURCE)
    run("git-add", ["git", "add", "."], SOURCE)
    require("Data/app.db" in run("staged", ["git", "diff", "--cached", "--name-only"], SOURCE).splitlines(),
            "account-bearing DB not tracked")
    run("git-commit", ["git", "commit", "-qm", "owned cookie fixture"], SOURCE)
    commit = run("commit", ["git", "rev-parse", "HEAD"], SOURCE)
    host.start("owner-revocation")
    try:
        require(host.protected(former), "cookie failed before revocation")
        owner = with_totp(host, INITIAL, key)
        changed = host.post(owner, "/Account/Manage/ChangePassword", {
            "_handler": "change-password", "Input.OldPassword": INITIAL,
            "Input.NewPassword": RECOVERED, "Input.ConfirmPassword": RECOVERED,
        })
        require(changed.status_code == 302, "owner rotation failed")
        require(not host.login(INITIAL)[2], "old password accepted after revocation")
    finally:
        host.stop()
    checkpoint(live_db)
    changed_sha = digest(live_db)
    require(changed_sha != source_sha, "live state did not change")
    wait = issued_at + 1862 - time.time()
    if wait > 0:
        time.sleep(wait)
    elapsed = time.time() - issued_at
    require(elapsed >= 1860, "stamp interval not elapsed")
    host.start("post-interval-denial")
    try:
        require(not host.protected(former), "revoked cookie passed after stamp interval")
        owner = with_totp(host, RECOVERED, key)
        require(host.protected(owner), "owner denied after rotation")
    finally:
        host.stop()
    checkpoint(live_db)
    time.sleep(1.1)
    run("same-commit-clone", ["git", "clone", "-q", str(SOURCE), str(CLONE)], ROOT)
    clone_db = CLONE / DB
    require(run("clone-commit", ["git", "rev-parse", "HEAD"], CLONE) == commit,
            "clone commit differs")
    require(digest(clone_db) == source_sha and clone_db.stat().st_mtime_ns > live_db.stat().st_mtime_ns,
            "stale clone file not newer")
    run("clone-restore", ["dotnet", "restore", str(CLONE), "--ignore-failed-sources"], ROOT)
    run("clone-publish", ["dotnet", "publish", str(CLONE), "--no-restore", "-c", "Release", "-o", str(LIVE)], ROOT)
    require(digest(live_db) == source_sha, "stock publish did not restore stale DB")
    former = host.session()
    former.cookies.update(held_cookie_jar)
    host.start("revived-cookie-reset")
    try:
        require(host.protected(former) and host.protected(former), "revoked cookie did not revive")
        anonymous = host.session()
        require(not host.protected(anonymous), "anonymous reached protected form")
        before = row(live_db)
        host.post(anonymous, "/Account/Manage/ResetAuthenticator", {
            "_handler": "reset-authenticator",
        })
        require(row(live_db) == before, "anonymous changed account state")
        reset = host.post(former, "/Account/Manage/ResetAuthenticator", {
            "_handler": "reset-authenticator",
        })
        require(reset.status_code == 302 and row(live_db)[1] == 0,
                "revived cookie did not reset 2FA")
        require(key_digest(live_db) != original_key_digest, "authenticator key unchanged")
    finally:
        host.stop()
    host.start("reset-restart")
    try:
        require(row(live_db)[1] == 0 and host.login(INITIAL)[2],
                "2FA reset not durable")
        require(not host.login(RECOVERED)[2], "owner new password unexpectedly valid")
    finally:
        host.stop()
    summary = {
        "sdk": sdk, "elapsed_seconds": round(elapsed, 1), "same_commit": True,
        "source_db_sha256": source_sha, "revoked_db_sha256": changed_sha,
        "revoked_cookie_denied_after_interval": True,
        "stock_publish_restored_db": True, "revoked_cookie_reauthorized_twice": True,
        "anonymous_reset_denied": True, "cookie_only_2fa_reset": True,
        "reset_durable_after_restart": True,
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
