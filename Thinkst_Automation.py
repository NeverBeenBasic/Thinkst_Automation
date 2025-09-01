#!/usr/bin/env python3
"""Automated phishing response for Thinkst Canary alerts.

Given a webhook payload containing a *Cloned Site* URL, this script will:

1. Resolve the cloned host to its IPv4 addresses.
2. Filter out private/reserved/allow‑listed addresses.
3. Ensure a Conditional Access named location exists and add the malicious IPs.
4. Query Azure AD sign‑in logs for users authenticating from those IPs.
5. Revoke the users' sessions and reset their passwords (forcing change at next sign‑in).

Prerequisites
------------
* Azure AD application with permissions `User.ReadWrite.All` and
  `Policy.ReadWrite.ConditionalAccess` using the client‑credentials flow.
* Environment variables: ``AZURE_TENANT_ID``, ``AZURE_CLIENT_ID``, ``AZURE_CLIENT_SECRET``.
* Python package ``requests``.

Example
-------
```bash
python scripts/Thinkst_Automation.py --webhook webhook.json \
    --named-location-name "Phishing - Blocked IPs" --allow 203.0.113.0/24
```

The script prints a JSON summary of actions taken.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import socket
import string
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional

import requests

GRAPH_URL = "https://graph.microsoft.com/v1.0"


def get_env(name: str, fallback: Optional[str] = None) -> str:
    value = os.getenv(name, fallback)
    if not value:
        raise SystemExit(f"Missing required environment variable {name}")
    return value


def get_access_token(tenant: str, client_id: str, client_secret: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    resp = requests.post(url, data=data, timeout=10)
    resp.raise_for_status()
    return resp.json()["access_token"]


def graph_request(method: str, url: str, token: str, **kwargs) -> requests.Response:
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {token}"
    headers.setdefault("Content-Type", "application/json")
    return requests.request(method, url, headers=headers, timeout=20, **kwargs)


def graph_paged(url: str, token: str) -> List[dict]:
    results: List[dict] = []
    while url:
        resp = graph_request("GET", url, token)
        resp.raise_for_status()
        data = resp.json()
        results.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return results


def resolve_host(host: str) -> List[str]:
    ips = set()
    try:
        for info in socket.getaddrinfo(host, None):
            addr = info[4][0]
            try:
                ipaddress.IPv4Address(addr)
                ips.add(addr)
            except ipaddress.AddressValueError:
                continue
    except OSError:
        pass
    return sorted(ips)


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.IPv4Address(ip)
    return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)


def ip_in_any_cidr(ip: str, cidrs: Iterable[str]) -> bool:
    addr = ipaddress.IPv4Address(ip)
    for cidr in cidrs:
        try:
            if addr in ipaddress.IPv4Network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def ensure_named_location(token: str, named_location_id: Optional[str], named_location_name: str) -> dict:
    if named_location_id:
        url = f"{GRAPH_URL}/identity/conditionalAccess/namedLocations/{named_location_id}"
        resp = graph_request("GET", url, token)
        resp.raise_for_status()
        return resp.json()

    url = f"{GRAPH_URL}/identity/conditionalAccess/namedLocations"
    all_locations = graph_paged(url, token)
    for loc in all_locations:
        if loc.get("displayName") == named_location_name and loc.get("@odata.type", "").endswith("ipNamedLocation"):
            return loc

    body = {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "displayName": named_location_name,
        "isTrusted": False,
        "ipRanges": [],
    }
    resp = graph_request("POST", url, token, json=body)
    resp.raise_for_status()
    return resp.json()


def add_ip_to_named_location(token: str, named_location: dict, ip_or_cidr: str) -> None:
    cidr = ip_or_cidr if "/" in ip_or_cidr else f"{ip_or_cidr}/32"
    loc_id = named_location["id"]
    url = f"{GRAPH_URL}/identity/conditionalAccess/namedLocations/{loc_id}"
    current = graph_request("GET", url, token).json()
    ranges = current.get("ipRanges", [])
    if any(r.get("cidrAddress") == cidr for r in ranges):
        return
    ranges.append({"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": cidr})
    body = {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "ipRanges": ranges,
    }
    graph_request("PATCH", url, token, json=body).raise_for_status()


def get_users_from_signins(token: str, ips: Iterable[str], since_utc: datetime) -> Dict[str, str]:
    users: Dict[str, str] = {}
    since = since_utc.isoformat()
    for ip in ips:
        filt = f"ipAddress eq '{ip}' and createdDateTime ge {since}"
        url = (
            f"{GRAPH_URL}/auditLogs/signIns?"
            f"$select=userId,userPrincipalName,ipAddress,createdDateTime&$filter={requests.utils.quote(filt)}"
        )
        for row in graph_paged(url, token):
            uid = row.get("userId")
            upn = row.get("userPrincipalName")
            if uid and uid not in users:
                users[uid] = upn
    return users


def revoke_sessions(token: str, user_id: str) -> bool:
    url = f"{GRAPH_URL}/users/{user_id}/revokeSignInSessions"
    resp = graph_request("POST", url, token)
    if resp.ok:
        return True
    return False


def reset_password(token: str, user_id: str, new_password: str) -> None:
    url = f"{GRAPH_URL}/users/{user_id}"
    body = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": new_password,
        }
    }
    graph_request("PATCH", url, token, json=body).raise_for_status()


def random_password(length: int = 20) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.SystemRandom().choice(chars) for _ in range(length))


def parse_webhook(path: str) -> Optional[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    for pair in data.get("AdditionalDetails", []):
        if len(pair) >= 2 and pair[0] == "Cloned Site":
            return pair[1]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Automate phishing response using Microsoft Graph")
    parser.add_argument("--webhook", required=True, help="Path to webhook JSON payload")
    parser.add_argument("--named-location-id", help="Existing Conditional Access named location ID")
    parser.add_argument(
        "--named-location-name",
        default="Phishing - Blocked IPs",
        help="Named location display name to create or use",
    )
    parser.add_argument("--allow", action="append", default=[], help="CIDRs to allowlist")
    parser.add_argument("--lookback", type=int, default=120, help="Minutes to search sign-in logs")
    parser.add_argument("--max-retries", type=int, default=6, help="Retries for sign-in log lag")
    parser.add_argument("--retry-delay", type=int, default=60, help="Seconds to wait between retries")
    args = parser.parse_args()

    tenant = get_env("AZURE_TENANT_ID")
    client_id = get_env("AZURE_CLIENT_ID")
    client_secret = get_env("AZURE_CLIENT_SECRET")

    cloned_site = parse_webhook(args.webhook)
    if not cloned_site:
        raise SystemExit("Webhook payload does not contain 'Cloned Site' entry")

    host = requests.utils.urlparse(cloned_site).hostname
    if not host:
        raise SystemExit("Invalid Cloned Site URL in webhook")

    ips = [ip for ip in resolve_host(host) if is_public_ip(ip) and not ip_in_any_cidr(ip, args.allow)]
    if not ips:
        print(json.dumps({"message": "No candidate public IPs"}))
        return

    token = get_access_token(tenant, client_id, client_secret)

    named_loc = ensure_named_location(token, args.named_location_id, args.named_location_name)

    since = datetime.now(timezone.utc) - timedelta(minutes=args.lookback)
    affected: Dict[str, str] = {}
    for attempt in range(1, args.max_retries + 1):
        affected = get_users_from_signins(token, ips, since)
        if affected:
            break
        time.sleep(args.retry_delay)

    for ip in ips:
        add_ip_to_named_location(token, named_loc, ip)

    results = []
    for user_id, upn in affected.items():
        if revoke_sessions(token, user_id):
            pwd = random_password()
            reset_password(token, user_id, pwd)
            results.append({"userId": user_id, "userPrincipalName": upn, "tempPassword": pwd})

    summary = {
        "ClonedSite": cloned_site,
        "Hostname": host,
        "BlockedIPs": ips,
        "Users": results,
        "Timestamp": datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

