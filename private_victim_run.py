"""Controlled native matrix with separate attacker, victim and instrumentation processes.

Prerequisites: an owned stock eShop AppHost and the shared heavy-lab lease.
Requires the G06_* endpoints/container variables documented in RESUME.md.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

from native_infra import redis_cmd, wait_redis_absent


HERE = Path(__file__).resolve().parent


def child(script, env_extra=None):
    env = os.environ.copy()
    env.update(env_extra or {})
    proc = subprocess.run([sys.executable, str(HERE / script)], env=env,
                          capture_output=True, text=True, timeout=90)
    if proc.returncode:
        # Child stdout can hold fixture metadata; only a bounded stderr tail is
        # safe to emit into a public runner log. No plaintext password is logged.
        tail = " | ".join(proc.stderr.strip().splitlines()[-2:])[:700]
        raise RuntimeError(f"{script} exited {proc.returncode}: {tail}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def actor(case, victim_id):
    # The HTTP actor receives only a victim UUID, never the private credential
    # or infrastructure container names used by the observing test process.
    allowed = {"PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
               "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "G06_IDP", "G06_BFF",
               "G06_ORDERING_REDIRECT"}
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env["G06_VICTIM_ID"] = victim_id
    proc = subprocess.run([sys.executable, str(HERE / "private_victim_actor.py"), case],
                          env=env, capture_output=True, text=True, check=True, timeout=90)
    return json.loads(proc.stdout.strip().splitlines()[-1])


def seed(buyer_id):
    marker = json.dumps({"BuyerId": buyer_id,
                         "Items": [{"ProductId": 1, "Quantity": 2}]}, separators=(",", ":"))
    if redis_cmd("SET", buyer_id, marker) != "OK":
        raise RuntimeError("basket seed failed")
    assert exists(buyer_id)


def exists(buyer_id):
    return redis_cmd("EXISTS", buyer_id) == "1"


def verify(secret_file, check_public=False):
    data = child("private_victim_verify.py", {
        "G06_VICTIM_SECRET_FILE": secret_file,
        "G06_CHECK_PUBLIC_PASSWORD": "1" if check_public else "0",
    })
    assert data["private_victim_login_succeeded"]
    return data


def main():
    fixture = child("private_victim_fixture.py")
    victim_id, secret_file = fixture["victim_id"], fixture["secret_file"]
    print(json.dumps({"stage": "fixture", "private_secret_file_created": True,
                      "basket_exists": exists(victim_id)}), flush=True)

    baseline = verify(secret_file, check_public=True)
    assert baseline["old_public_password_denied"]
    assert baseline["private_victim_subject"] == victim_id
    print(json.dumps({"stage": "victim_denied_public_and_private_valid",
                      "public_denied": True, "private_valid": True,
                      "orders_before": baseline["victim_order_count"]}), flush=True)

    anonymous = actor("anonymous", victim_id)
    assert anonymous["status"] == 401 and exists(victim_id)
    print(json.dumps({"stage": "anonymous_negative", "status": 401,
                      "victim_basket_intact": True}), flush=True)

    bad = actor("invalid_signature", victim_id)
    assert bad["status"] == 401 and exists(victim_id)
    print(json.dumps({"stage": "signature_negative", "status": 401,
                      "victim_basket_intact": True}), flush=True)

    empty = actor("empty_items", victim_id)
    actor_id = empty["actor_id"]
    assert actor_id != victim_id and empty["status"] == 200
    time.sleep(1)
    assert exists(victim_id) and verify(secret_file)["victim_order_count"] == baseline["victim_order_count"]
    print(json.dumps({"stage": "prehandler_negative", "status": 200,
                      "victim_basket_intact": True, "victim_orders_unchanged": True}), flush=True)

    seed(actor_id)
    own = actor("own_valid", victim_id)
    assert own["status"] == 200 and wait_redis_absent(actor_id) and exists(victim_id)
    print(json.dumps({"stage": "own_id_control", "own_basket_deleted": True,
                      "victim_basket_intact": True}), flush=True)

    seed(actor_id)
    cross = actor("cross_valid", victim_id)
    assert cross["status"] == 200 and wait_redis_absent(victim_id) and exists(actor_id)
    after_cross = verify(secret_file)
    assert after_cross["victim_order_count"] == baseline["victim_order_count"] + 1
    baseline_inert_ids = {entry["order_number"] for entry in baseline["inert_actor_order_details"]}
    cross_inert_ids = {entry["order_number"] for entry in after_cross["inert_actor_order_details"]}
    assert len(cross_inert_ids - baseline_inert_ids) == 1
    print(json.dumps({"stage": "cross_valid", "status": 200,
                      "victim_basket_deleted": True,
                      "victim_new_order_with_actor_fields": True,
                      "victim_orders_after": after_cross["victim_order_count"]}), flush=True)

    seed(victim_id)
    failed = actor("cross_invalid_quantity", victim_id)
    assert failed["status"] == 200 and wait_redis_absent(victim_id)
    after_failed = verify(secret_file)
    assert after_failed["victim_order_count"] == after_cross["victim_order_count"]
    assert {entry["order_number"] for entry in after_failed["inert_actor_order_details"]} == cross_inert_ids
    print(json.dumps({"stage": "cross_failed_after_event", "status": 200,
                      "victim_basket_deleted": True,
                      "victim_orders_unchanged": True}), flush=True)

    seed(victim_id)
    repeated = actor("cross_valid", victim_id)
    assert repeated["status"] == 200 and wait_redis_absent(victim_id)
    after_repeat = verify(secret_file)
    assert after_repeat["victim_order_count"] == after_cross["victim_order_count"] + 1
    repeat_inert_ids = {entry["order_number"] for entry in after_repeat["inert_actor_order_details"]}
    assert len(repeat_inert_ids - cross_inert_ids) == 1
    new_order_ids = repeat_inert_ids - baseline_inert_ids
    print(json.dumps({"stage": "cross_repeat", "victim_basket_deleted": True,
                      "victim_orders_after": after_repeat["victim_order_count"]}), flush=True)

    seed(actor_id)
    reverse = child("private_victim_reverse.py", {
        "G06_VICTIM_SECRET_FILE": secret_file,
        "G06_REVERSE_TARGET_ID": actor_id,
    })
    assert reverse["status"] == 200 and reverse["actor_is_private_victim"]
    assert wait_redis_absent(actor_id)
    print(json.dumps({"stage": "reverse_principal_control", "status": 200,
                      "alice_basket_deleted": True}), flush=True)

    # The stock OrderProcessor waits one minute and checks on a 30-second
    # cadence. Observe, but do not require, later simulated payment states.
    deadline = time.monotonic() + int(os.environ.get("G06_GRACE_MAX_SECONDS", "150"))
    later = after_repeat
    while time.monotonic() < deadline:
        statuses = {entry["order_number"]: entry["status"]
                    for entry in later["inert_actor_order_details"]
                    if entry["order_number"] in new_order_ids}
        if len(statuses) == len(new_order_ids) and all(
            status in ("Paid", "Cancelled", "Shipped") for status in statuses.values()
        ):
            break
        time.sleep(10)
        later = verify(secret_file)
    statuses = {entry["order_number"]: entry["status"]
                for entry in later["inert_actor_order_details"]
                if entry["order_number"] in new_order_ids}
    print(json.dumps({"stage": "after_grace_observation", "status_by_order": statuses,
                      "simulated_payment_only": True}), flush=True)

    print(json.dumps({"stage": "complete", "all_assertions_passed": True}), flush=True)


if __name__ == "__main__":
    main()
