"""Victim-side HTTP verifier; reads a private fixture credential, never prints it."""

import json
import os

import requests

from native_http import BFF, login


def main():
    with open(os.environ["G06_VICTIM_SECRET_FILE"], encoding="utf-8") as f:
        private = json.load(f)

    old_password_denied = None
    if os.environ.get("G06_CHECK_PUBLIC_PASSWORD") == "1":
        old_password_denied = False
        try:
            login(private["username"], "Pass123$")
        except (RuntimeError, AssertionError):
            old_password_denied = True

    token, claims = login(private["username"], private["password"])
    if claims["sub"] != private["id"]:
        raise RuntimeError("victim token subject differs from fixture")

    response = requests.get(BFF + "/api/orders/?api-version=1.0",
                            headers={"Authorization": "Bearer " + token}, timeout=15)
    response.raise_for_status()
    orders = response.json()
    matching = []
    for summary in orders:
        detail = requests.get(
            BFF + f"/api/orders/{summary['orderNumber']}?api-version=1.0",
            headers={"Authorization": "Bearer " + token}, timeout=15,
        )
        detail.raise_for_status()
        record = detail.json()
        if record.get("street") == "Inert Street" and any(
            item.get("productName") == "Inert Item" for item in record.get("orderItems", [])
        ):
            matching.append({"order_number": summary["orderNumber"], "status": summary["status"],
                             "total": summary["total"]})

    print(json.dumps({"old_public_password_denied": old_password_denied,
                      "private_victim_subject": claims["sub"],
                      "private_victim_login_succeeded": True,
                      "victim_order_count": len(orders), "inert_actor_order_details": matching}))


if __name__ == "__main__":
    main()
