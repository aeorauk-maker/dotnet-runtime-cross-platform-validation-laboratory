"""HTTP-only eShop test client; deliberately has no database/Redis helpers."""

import base64
import html
import json
import os
import re
import urllib.parse
import uuid

import requests


IDP = os.environ.get("G06_IDP", "http://localhost:5223")
BFF = os.environ.get("G06_BFF", "http://127.0.0.1:50249")
ORDERING_REDIRECT = os.environ.get("G06_ORDERING_REDIRECT", "http://localhost:5224/swagger/oauth2-redirect.html")


def hidden(page, name):
    match = re.search(r'<input[^>]*name="' + re.escape(name) + r'"[^>]*>', page)
    if not match:
        raise RuntimeError(f"missing login field {name}")
    value = re.search(r'value="([^"]*)"', match.group(0))
    return html.unescape(value.group(1)) if value else ""


def login(username, password):
    session = requests.Session()
    query = {
        "client_id": "orderingswaggerui",
        "redirect_uri": ORDERING_REDIRECT,
        "response_type": "token",
        "scope": "orders",
        "state": "g06-l016-" + username,
        "nonce": str(uuid.uuid4()),
    }
    response = session.get(IDP + "/connect/authorize", params=query, timeout=15)
    assert response.status_code == 200 and "/Account/Login" in response.url, (response.status_code, response.url)
    data = {
        "ReturnUrl": hidden(response.text, "ReturnUrl"),
        "__RequestVerificationToken": hidden(response.text, "__RequestVerificationToken"),
        "Username": username,
        "Password": password,
        "RememberLogin": "false",
        "button": "login",
    }
    response = session.post(IDP + "/Account/Login", data=data, allow_redirects=False, timeout=15)
    for _ in range(8):
        location = response.headers.get("Location", "")
        if "access_token=" in location:
            fragment = urllib.parse.urlsplit(location).fragment
            token = urllib.parse.parse_qs(fragment)["access_token"][0]
            claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
            return token, claims
        if not location:
            raise RuntimeError(f"login stopped: {response.status_code}, {response.url}")
        response = session.get(urllib.parse.urljoin(response.url, location), allow_redirects=False, timeout=15)
    raise RuntimeError("login redirect loop")


def body(buyer, quantity=1):
    return {
        "userId": buyer,
        "userName": "Inert Buyer",
        "city": "Owned City",
        "street": "Inert Street",
        "state": "Owned State",
        "country": "GB",
        "zipCode": "OWNED",
        "paymentToken": "pm_owned_inert",
        "buyer": "Inert Buyer",
        "items": [{
            "id": "1", "productId": 1, "productName": "Inert Item",
            "unitPrice": 1, "oldUnitPrice": 1, "quantity": quantity,
            "pictureUrl": "/inert.png",
        }],
    }


def order(token, buyer, quantity=1):
    response = requests.post(
        BFF + "/api/orders/?api-version=1.0",
        headers={"Authorization": "Bearer " + token, "x-requestid": str(uuid.uuid4())},
        json=body(buyer, quantity), timeout=25,
    )
    return response.status_code, response.text[:150]
