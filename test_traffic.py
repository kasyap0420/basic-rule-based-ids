import argparse
import json
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


with (BASE_DIR / "config.json").open(
    "r",
    encoding="utf-8"
) as file:
    CONFIG = json.load(file)


def http_request(base_url, path, payload=None):
    data = None
    headers = {}

    if payload is not None:
        data = json.dumps(
            payload
        ).encode("utf-8")

        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=data,
        headers=headers,
        method="POST" if payload is not None else "GET"
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=5
        ) as response:
            return (
                response.status,
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as error:
        return (
            error.code,
            error.read().decode("utf-8")
        )


def normal_test(base_url):
    threshold = CONFIG[
        "request_rate"
    ]["requests_threshold"]

    count = max(
        1,
        min(3, threshold - 1)
    )

    for number in range(1, count + 1):
        status, body = http_request(
            base_url,
            "/api/ping"
        )

        print(
            f"normal {number}: "
            f"HTTP {status} {body}"
        )

        time.sleep(0.5)


def login_test(base_url):
    threshold = CONFIG[
        "login_attempts"
    ]["failed_attempts_threshold"]

    username = CONFIG[
        "demo_auth"
    ]["username"]

    for number in range(1, threshold + 1):
        status, body = http_request(
            base_url,
            "/login",
            {
                "username": username,
                "password": "wrong-password"
            }
        )

        print(
            f"login {number}: "
            f"HTTP {status} {body}"
        )


def rate_test(base_url):
    count = (
        CONFIG[
            "request_rate"
        ]["requests_threshold"]
        + 5
    )

    for number in range(1, count + 1):
        status, _ = http_request(
            base_url,
            "/api/ping"
        )

        print(
            f"rate {number}: "
            f"HTTP {status}"
        )


def scan_test():
    host = "127.0.0.1"

    threshold = CONFIG[
        "port_scan"
    ]["distinct_ports_threshold"]

    ports = CONFIG[
        "port_scan"
    ]["ports"][:threshold]

    for port in ports:
        with socket.create_connection(
            (host, int(port)),
            timeout=2
        ):
            print(
                f"connected to sensor port {port}"
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Authorized local IDS test traffic generator"
        )
    )

    parser.add_argument(
        "mode",
        choices=[
            "normal",
            "login",
            "rate",
            "scan"
        ]
    )

    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5000"
    )

    args = parser.parse_args()

    if args.mode == "normal":
        normal_test(args.base_url)

    elif args.mode == "login":
        login_test(args.base_url)

    elif args.mode == "rate":
        rate_test(args.base_url)

    elif args.mode == "scan":
        scan_test()


if __name__ == "__main__":
    main()