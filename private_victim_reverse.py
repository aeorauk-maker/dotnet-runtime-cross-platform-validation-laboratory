"""Reverse principal/body-ID control using the private victim's own token."""

import json
import os

from native_http import login, order


def main():
    with open(os.environ["G06_VICTIM_SECRET_FILE"], encoding="utf-8") as f:
        private = json.load(f)
    token, claims = login(private["username"], private["password"])
    target = os.environ["G06_REVERSE_TARGET_ID"]
    if claims["sub"] == target:
        raise RuntimeError("reverse target must be a distinct principal")
    print(json.dumps({"case": "reverse_private_victim_to_alice",
                      "actor_is_private_victim": claims["sub"] == private["id"],
                      "status": order(token, target)[0]}))


if __name__ == "__main__":
    main()
