#!/usr/bin/env python3
"""Disposable same-commit stock publish of the generated empty Identity DB."""

import html
import json
import re
import secrets
import sqlite3
import time
from urllib.parse import urlsplit

from runner_identity_state_deploy import (
    ROOT, SOURCE, CLONE, LIVE, DB, EMAIL, INITIAL,
    Host, checkpoint, digest, row, run, require,
)


def register(host, email, password):
    s = host.session()
    r = host.post(s, "/Account/Register", {
        "_handler": "register", "Input.Email": email,
        "Input.Password": password, "Input.ConfirmPassword": password,
    })
    require(r.status_code == 302 and "RegisterConfirmation" in r.headers.get("Location", ""),
            "registration failed")
    u = urlsplit(r.headers["Location"])
    p = host.get(s, u.path + "?" + u.query)
    m = re.search(r'href="([^"]*Account/ConfirmEmail[^"]*)"', p.text)
    require(p.status_code == 200 and m, "confirmation link absent")
    u = urlsplit(html.unescape(m.group(1)))
    host.get(s, u.path + "?" + u.query)


def count_users(dbpath):
    with sqlite3.connect(dbpath) as db:
        return db.execute("SELECT COUNT(*) FROM AspNetUsers").fetchone()[0]


def main():
    ROOT.mkdir(exist_ok=False)
    (ROOT / "global.json").write_text('{"sdk":{"version":"11.0.100","rollForward":"disable"}}\n')
    sdk = run("sdk-version", ["dotnet", "--version"], ROOT)
    require(sdk == "11.0.100", "unexpected SDK")
    run("new", ["dotnet", "new", "blazor", "-au", "Individual", "-o", str(SOURCE),
                "-n", "Id009Runner", "--no-restore"], ROOT, timeout=180)
    run("gitignore", ["dotnet", "new", "gitignore", "-o", str(SOURCE)], ROOT)
    source_db, live_db = SOURCE / DB, LIVE / DB
    require(count_users(source_db) == 0, "shipped DB nonempty")
    source_sha = digest(source_db)
    run("git-init", ["git", "init", "-q"], SOURCE)
    run("git-name", ["git", "config", "user.name", "Owned Validation"], SOURCE)
    run("git-email", ["git", "config", "user.email", "owned@lab.invalid"], SOURCE)
    run("git-add", ["git", "add", "."], SOURCE)
    require("Data/app.db" in run("staged", ["git", "diff", "--cached", "--name-only"], SOURCE).splitlines(),
            "stock empty DB not tracked")
    run("git-commit", ["git", "commit", "-qm", "initial generated app"], SOURCE)
    commit = run("commit", ["git", "rev-parse", "HEAD"], SOURCE)
    run("restore", ["dotnet", "restore", str(SOURCE), "--ignore-failed-sources"], ROOT)
    run("publish-initial", ["dotnet", "publish", str(SOURCE), "--no-restore", "-c", "Release", "-o", str(LIVE)], ROOT)
    require(digest(live_db) == source_sha, "initial empty DB not published")
    host = Host()
    other_email = f"owned-{secrets.token_hex(6)}@example.test"
    other_password = "I!" + secrets.token_urlsafe(24)
    host.start("register-two")
    try:
        register(host, EMAIL, INITIAL)
        register(host, other_email, other_password)
        require(count_users(live_db) == 2 and row(live_db)[0] == 1, "accounts missing")
        require(host.login(INITIAL)[2], "first account protected login denied")
        other = host.session()
        r = host.post(other, "/Account/Login", {
            "_handler": "login", "Input.Email": other_email, "Input.Password": other_password,
        })
        require(r.status_code == 302 and host.protected(other), "second account protected login denied")
    finally:
        host.stop()
    checkpoint(live_db)
    live_sha = digest(live_db)
    require(live_sha != source_sha, "live DB did not change")
    time.sleep(1.1)
    run("same-commit-clone", ["git", "clone", "-q", str(SOURCE), str(CLONE)], ROOT)
    require(run("clone-commit", ["git", "rev-parse", "HEAD"], CLONE) == commit, "clone commit differs")
    clone_db = CLONE / DB
    require(digest(clone_db) == source_sha and clone_db.stat().st_mtime_ns > live_db.stat().st_mtime_ns,
            "source DB not newer")
    run("clone-restore", ["dotnet", "restore", str(CLONE), "--ignore-failed-sources"], ROOT)
    run("clone-publish", ["dotnet", "publish", str(CLONE), "--no-restore", "-c", "Release", "-o", str(LIVE)], ROOT)
    require(digest(live_db) == source_sha and count_users(live_db) == 0,
            "stock publish did not erase live accounts")
    host.start("account-loss")
    try:
        require(not host.login(INITIAL)[2], "first old account still authenticates")
        other = host.session()
        host.post(other, "/Account/Login", {
            "_handler": "login", "Input.Email": other_email, "Input.Password": other_password,
        })
        require(not host.protected(other), "second old account still authenticates")
        require(count_users(live_db) == 0, "user rows restored unexpectedly")
    finally:
        host.stop()
    host.start("loss-after-restart")
    try:
        require(count_users(live_db) == 0 and not host.login(INITIAL)[2], "account loss not durable")
    finally:
        host.stop()
    summary = {
        "sdk": sdk, "same_commit": True,
        "stock_empty_db_tracked": True, "source_db_sha256": source_sha,
        "changed_live_db_sha256": live_sha, "two_accounts_valid_before": True,
        "stock_publish_restored_empty_db": True, "both_accounts_denied_after": True,
        "zero_user_rows_after": True, "loss_durable_after_restart": True,
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
