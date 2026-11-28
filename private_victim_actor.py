"""Attacker-only HTTP client: no victim password or database/Redis access."""

import json
import os
import sys
import uuid

import requests

from native_http import BFF, body, login, order


def post(token, target, items):
    headers = {"x-requestid": str(uuid.uuid4())}
    if token:
        headers["Authorization"] = "Bearer " + token
    response = requests.post(
        BFF + "/api/orders/?api-version=1.0",
        json={**body(target), "items": items}, headers=headers, timeout=25,
    )
    return response.status_code


def main():
    case = sys.argv[1]
    victim_id = os.environ["G06_VICTIM_ID"]
    if case == "anonymous":
        print(json.dumps({"case": case, "status": post(None, victim_id, body(victim_id)["items"])}))
        return

    token, claims = login("alice", "Pass123$")
    actor_id = claims["sub"]
    if actor_id == victim_id:
        raise RuntimeError("actor and private victim subjects must differ")

    if case == "invalid_signature":
        header, payload, signature = token.split(".")
        token = header + "." + payload + "." + ("a" if signature[0] != "a" else "b") + signature[1:]
        status = post(token, victim_id, body(victim_id)["items"])
    elif case == "empty_items":
        status = post(token, victim_id, [])
    elif case == "own_valid":
        status = order(token, actor_id)[0]
    elif case == "cross_valid":
        status = order(token, victim_id)[0]
    elif case == "cross_invalid_quantity":
        status = order(token, victim_id, 0)[0]
    else:
        raise ValueError("unknown case")

    print(json.dumps({"case": case, "actor_id": actor_id,
                      "target_is_actor": case == "own_valid", "status": status}))


if __name__ == "__main__":
    main()
