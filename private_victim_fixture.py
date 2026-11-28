"""Rotate the owned Bob demo account into a private victim fixture.

This is test setup only. It does not replace any eShop authorization decision.
Run against an isolated native AppHost, never a shared/customer database.
"""

import base64
import hashlib
import json
import os
import secrets
import struct
import subprocess
import sys
import uuid

from native_infra import redis_cmd


def identity_v3_hash(password):
    # ASP.NET Core Identity V3: marker, HMAC-SHA512 PRF, iterations, salt length,
    # 16-byte salt, and a 32-byte PBKDF2 subkey. Integers are big-endian.
    salt = secrets.token_bytes(16)
    subkey = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 100_000, 32)
    payload = b"\x01" + struct.pack(">III", 2, 100_000, len(salt)) + salt + subkey
    return base64.b64encode(payload).decode("ascii")


def psql(sql):
    container = os.environ["G06_POSTGRES_CONTAINER"]
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c",
         'PGPASSWORD="$POSTGRES_PASSWORD" psql -X -v ON_ERROR_STOP=1 -qAt -U "$POSTGRES_USER" -d identitydb'],
        input=sql, capture_output=True, text=True, timeout=20,
    )
    if proc.returncode:
        # psql may echo the SQL (which contains a password hash) on later
        # lines. Keep only its first error category line in public logs.
        first = proc.stderr.strip().splitlines()[:1]
        raise RuntimeError(f"identitydb psql exit {proc.returncode}: {first[0][:160] if first else 'no stderr'}")
    return proc.stdout.strip()


def main():
    password = secrets.token_urlsafe(32)
    password_hash = identity_v3_hash(password)
    stamp = uuid.uuid4().hex
    concurrency = uuid.uuid4().hex
    # All substituted SQL values above are generated within this script and
    # contain only ASCII alphanumerics, underscore, slash, plus, dash or equals.
    victim_id = psql(
        'UPDATE "AspNetUsers" SET '
        f'"PasswordHash" = \'{password_hash}\', '
        f'"SecurityStamp" = \'{stamp}\', '
        f'"ConcurrencyStamp" = \'{concurrency}\', '
        '"AccessFailedCount" = 0, "LockoutEnd" = NULL '
        'WHERE "UserName" = \'bob\' RETURNING "Id";'
    )
    if not victim_id or "\n" in victim_id:
        raise RuntimeError("expected exactly one owned Bob account")

    secret_path = os.environ.get("G06_VICTIM_SECRET_FILE")
    if not secret_path:
        secret_path = os.path.join(os.path.dirname(__file__), f"private-victim-{uuid.uuid4().hex}.json")
    fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"username": "bob", "password": password, "id": victim_id}, f)

    marker = json.dumps({"BuyerId": victim_id, "Items": [{"ProductId": 1, "Quantity": 2}]}, separators=(",", ":"))
    if redis_cmd("SET", victim_id, marker) != "OK":
        raise RuntimeError("victim basket fixture was not seeded")
    print(json.dumps({"victim_id": victim_id, "secret_file": secret_path, "basket_exists": redis_cmd("EXISTS", victim_id) == "1"}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"private victim fixture failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
