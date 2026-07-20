#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import ssl
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision a sensor over its local API with validated TLS when used")
    parser.add_argument("base_url", help="Device base URL, normally the setup network address")
    parser.add_argument("config", type=Path, help="JSON setup document; protect/delete it because it contains secrets")
    parser.add_argument("--ca", type=Path, help="CA for HTTPS device access")
    args = parser.parse_args()
    if not args.base_url.startswith(("http://192.168.4.1", "https://")):
        raise SystemExit("plain HTTP is allowed only for the isolated 192.168.4.1 setup AP")
    context = ssl.create_default_context(cafile=str(args.ca)) if args.base_url.startswith("https://") else None
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(CookieJar()),
        urllib.request.HTTPSHandler(context=context) if context else urllib.request.HTTPHandler(),
    )
    password = getpass.getpass("Setup/local administrator password: ")
    login = urllib.request.Request(args.base_url.rstrip("/") + "/api/v1/auth/login", json.dumps({"password": password}).encode(), {"Content-Type": "application/json"}, method="POST")
    with opener.open(login, timeout=10) as response:
        session = json.load(response)
    payload = args.config.read_bytes()
    request = urllib.request.Request(args.base_url.rstrip("/") + "/api/v1/setup/apply", payload, {"Content-Type": "application/json", "X-PM-CSRF": session["csrf"]}, method="POST")
    with opener.open(request, timeout=20) as response:
        print(json.dumps(json.load(response), indent=2))
    print("Provisioning request accepted. Secret values were not printed.")


if __name__ == "__main__":
    main()

