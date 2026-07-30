#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import ssl
import time
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision a sensor over its local API with validated TLS when used"
    )
    parser.add_argument(
        "base_url", help="Device base URL, normally the setup network address"
    )
    parser.add_argument(
        "config",
        type=Path,
        help="JSON setup document; protect/delete it because it contains secrets",
    )
    parser.add_argument("--ca", type=Path, help="CA for HTTPS device access")
    args = parser.parse_args()
    if not args.base_url.startswith(("http://192.168.4.1", "https://")):
        raise SystemExit(
            "plain HTTP is allowed only for the isolated 192.168.4.1 setup AP"
        )
    payload = args.config.read_bytes()
    try:
        setup_document = json.loads(payload)
    except (TypeError, ValueError) as error:
        raise SystemExit("setup document is not valid JSON") from error
    enrollment_token = str(setup_document.get("enrollment_token", ""))
    if not 32 <= len(enrollment_token) <= 256:
        raise SystemExit("enrollment token must contain 32 through 256 characters")
    enrollment_token = ""
    context = (
        ssl.create_default_context(cafile=str(args.ca))
        if args.base_url.startswith("https://")
        else None
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(CookieJar()),
        urllib.request.HTTPSHandler(context=context)
        if context
        else urllib.request.HTTPHandler(),
    )
    parsed_base = urllib.parse.urlsplit(args.base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    open_session = urllib.request.Request(
        args.base_url.rstrip("/") + "/api/v1/auth/session",
        b"{}",
        {"Content-Type": "application/json", "Origin": origin},
        method="POST",
    )
    with opener.open(open_session, timeout=10) as response:
        session = json.load(response)
    if not session.get("csrf"):
        raise SystemExit("device did not issue a nonprivileged local session")
    password = getpass.getpass("Setup/local administrator password: ")
    login = urllib.request.Request(
        args.base_url.rstrip("/") + "/api/v1/auth/login",
        json.dumps({"password": password}).encode(),
        {
            "Content-Type": "application/json",
            "Origin": origin,
            "X-PM-CSRF": str(session["csrf"]),
        },
        method="POST",
    )
    password = ""
    with opener.open(login, timeout=10) as response:
        session = json.load(response)
    if "job_id" in session:
        deadline = time.monotonic() + 60
        job_url = (
            args.base_url.rstrip("/")
            + "/api/v1/auth/password-jobs?job_id="
            + urllib.parse.quote(str(session["job_id"]), safe="")
        )
        while time.monotonic() < deadline:
            poll = urllib.request.Request(
                job_url, {"Accept": "application/json", "Origin": origin}
            )
            with opener.open(poll, timeout=10) as response:
                session = json.load(response)
            if session.get("status") != "pending":
                break
            time.sleep(0.25)
        else:
            raise SystemExit("administrator verification timed out")
    if not session.get("elevated") or not session.get("csrf"):
        raise SystemExit("device did not issue an elevated local session")
    request = urllib.request.Request(
        args.base_url.rstrip("/") + "/api/v1/setup/apply",
        payload,
        {
            "Content-Type": "application/json",
            "X-PM-CSRF": session["csrf"],
            "Origin": origin,
        },
        method="POST",
    )
    with opener.open(request, timeout=20) as response:
        print(json.dumps(json.load(response), indent=2))
    print("Provisioning request accepted. Secret values were not printed.")


if __name__ == "__main__":
    main()
