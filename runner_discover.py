"""Discover only owned Aspire endpoints; print environment exports, never secrets."""

import os
import pathlib
import re
import subprocess
import time


def resource_env(fragment, variable):
    for item in pathlib.Path("/proc").iterdir():
        if not item.name.isdecimal():
            continue
        try:
            command = (item / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            if fragment not in command:
                continue
            entries = (item / "environ").read_bytes().split(b"\0")
            for entry in entries:
                if entry.startswith(variable.encode() + b"="):
                    return entry.split(b"=", 1)[1].decode()
        except (OSError, PermissionError):
            continue
    return None


def owned_container(prefix):
    names = subprocess.check_output(["docker", "ps", "--format", "{{.Names}}"], text=True).splitlines()
    matches = [name for name in names if name.startswith(prefix + "-")]
    if len(matches) != 1:
        raise RuntimeError(f"expected one owned {prefix} container, found {len(matches)}")
    return matches[0]


def main():
    for _ in range(150):
        issuer = resource_env("Ordering.API", "Identity__Url")
        redirect_base = resource_env("Identity.API", "OrderingApiClient")
        if issuer and redirect_base:
            break
        time.sleep(2)
    else:
        raise RuntimeError("Identity and Ordering process environment not ready")

    redis = owned_container("redis")
    postgres = owned_container("postgres")
    bff = owned_container("mobile-bff")
    ports = subprocess.check_output(["docker", "port", bff, "5000/tcp"], text=True).strip().splitlines()
    ipv4 = [entry for entry in ports if re.fullmatch(r"(?:0\.0\.0\.0|127\.0\.0\.1):([0-9]+)", entry)]
    if len(ipv4) != 1:
        raise RuntimeError("unexpected owned BFF HTTP port mapping")
    port = ipv4[0].rsplit(":", 1)[1]
    values = {
        "G06_IDP": issuer,
        "G06_ORDERING_REDIRECT": redirect_base.rstrip("/") + "/swagger/oauth2-redirect.html",
        "G06_BFF": "http://127.0.0.1:" + port,
        "G06_REDIS_CONTAINER": redis,
        "G06_POSTGRES_CONTAINER": postgres,
    }
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")
    print("Owned Identity, Ordering, Redis, PostgreSQL and mobile BFF discovered")


if __name__ == "__main__":
    main()
