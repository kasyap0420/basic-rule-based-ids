import json
import os
import secrets
from pathlib import Path

from flask import Flask, jsonify, request
from waitress import serve

from ids_engine import DetectionEngine
from port_sensor import PortScanSensor


BASE_DIR = Path(__file__).resolve().parent


def load_config():
    config_file = BASE_DIR / "config.json"

    with config_file.open("r", encoding="utf-8") as file:
        config = json.load(file)

    log_path = Path(config["logging"]["file"])

    if not log_path.is_absolute():
        config["logging"]["file"] = str(
            BASE_DIR / log_path
        )

    return config


def env_bool(name, default=False):
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on"
    }


CONFIG = load_config()
ENGINE = DetectionEngine(CONFIG)

app = Flask(__name__)


def get_source_ip():
    return request.remote_addr or "unknown"


@app.before_request
def monitor_request_rate():
    ENGINE.record_request(
        get_source_ip(),
        request.path
    )


@app.get("/")
def index():
    return jsonify(
        service="Basic Rule-Based IDS",
        status="running",
        endpoints={
            "health": "GET /health",
            "normal_test": "GET /api/ping",
            "login_test": "POST /login"
        },
        rules={
            "port_scan": {
                **CONFIG["port_scan"],
                "enabled": env_bool(
                    "ENABLE_PORT_SENSOR",
                    CONFIG["port_scan"]["enabled"]
                )
            },
            "login_attempts": CONFIG["login_attempts"],
            "request_rate": CONFIG["request_rate"]
        }
    )


@app.get("/health")
def health():
    return jsonify(
        status="ok"
    )


@app.get("/api/ping")
def ping():
    return jsonify(
        message="pong"
    )


@app.post("/login")
def login():
    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get("username", "")
    )

    password = str(
        data.get("password", "")
    )

    expected_username = os.getenv(
        "IDS_DEMO_USERNAME",
        CONFIG["demo_auth"]["username"]
    )

    expected_password = os.getenv(
        "IDS_DEMO_PASSWORD",
        CONFIG["demo_auth"]["password"]
    )

    success = (
        secrets.compare_digest(
            username,
            expected_username
        )
        and
        secrets.compare_digest(
            password,
            expected_password
        )
    )

    ENGINE.record_login(
        get_source_ip(),
        success
    )

    if success:
        return jsonify(
            message="Login successful"
        ), 200

    return jsonify(
        message="Invalid credentials"
    ), 401


def main():
    sensor = None

    sensor_enabled = env_bool(
        "ENABLE_PORT_SENSOR",
        CONFIG["port_scan"]["enabled"]
    )

    try:
        if sensor_enabled:
            sensor = PortScanSensor(
                ENGINE,
                CONFIG["port_scan"]
            )

            sensor.start()

        render_port = os.getenv("PORT")

        if render_port:
            host = "0.0.0.0"
            port = int(render_port)
        else:
            host = CONFIG["server"]["host"]
            port = int(CONFIG["server"]["port"])

        print(
            f"[IDS] HTTP service listening "
            f"on http://{host}:{port}",
            flush=True
        )

        print(
            f"[IDS] Alert log: "
            f"{CONFIG['logging']['file']}",
            flush=True
        )

        if env_bool("TRUST_PROXY", False):
            serve(
                app,
                host=host,
                port=port,
                threads=4,
                trusted_proxy="*",
                trusted_proxy_count=2,
                trusted_proxy_headers={
                    "x-forwarded-for",
                    "x-forwarded-proto"
                },
                clear_untrusted_proxy_headers=True
            )
        else:
            serve(
                app,
                host=host,
                port=port,
                threads=4
            )

    finally:
        if sensor is not None:
            sensor.stop()


if __name__ == "__main__":
    main()