import json
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


class DetectionEngine:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()

        self.request_events = defaultdict(deque)
        self.login_failures = defaultdict(deque)
        self.port_events = defaultdict(deque)

        self.last_alert = {}

        self.log_file = Path(config["logging"]["file"])
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _prune_times(events, now, window_seconds):
        while events and now - events[0] > window_seconds:
            events.popleft()

    @staticmethod
    def _prune_port_events(events, now, window_seconds):
        while events and now - events[0][0] > window_seconds:
            events.popleft()

    def _can_alert(self, rule_id, source, now, cooldown_seconds):
        key = (rule_id, source)

        last = self.last_alert.get(key, float("-inf"))

        if now - last < cooldown_seconds:
            return False

        self.last_alert[key] = now
        return True

    def _write_alert(
        self,
        source,
        rule_id,
        event_type,
        severity,
        message,
        details
    ):
        alert = {
            "timestamp": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "source": source,
            "rule_id": rule_id,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "details": details
        }

        line = json.dumps(
            alert,
            ensure_ascii=False,
            separators=(",", ":")
        )

        with self.log_file.open("a", encoding="utf-8") as file:
            file.write(line + "\n")

        print(f"[IDS ALERT] {line}", flush=True)

        return alert

    def record_request(self, source, path):
        cfg = self.config["request_rate"]

        if path in cfg.get("excluded_paths", []):
            return None

        now = time.monotonic()

        with self.lock:
            events = self.request_events[source]
            events.append(now)

            self._prune_times(
                events,
                now,
                cfg["window_seconds"]
            )

            count = len(events)

            if count < cfg["requests_threshold"]:
                return None

            if not self._can_alert(
                "R003_HIGH_REQUEST_RATE",
                source,
                now,
                cfg["alert_cooldown_seconds"]
            ):
                return None

            return self._write_alert(
                source=source,
                rule_id="R003_HIGH_REQUEST_RATE",
                event_type="HIGH_REQUEST_RATE",
                severity="MEDIUM",
                message=(
                    f"High request rate detected: "
                    f"{count} requests within "
                    f"{cfg['window_seconds']} seconds."
                ),
                details={
                    "request_count": count,
                    "window_seconds": cfg["window_seconds"],
                    "approx_requests_per_second": round(
                        count / cfg["window_seconds"],
                        2
                    ),
                    "last_path": path
                }
            )

    def record_login(self, source, success):
        cfg = self.config["login_attempts"]
        now = time.monotonic()

        with self.lock:
            if success:
                self.login_failures.pop(source, None)
                return None

            events = self.login_failures[source]
            events.append(now)

            self._prune_times(
                events,
                now,
                cfg["window_seconds"]
            )

            count = len(events)

            if count < cfg["failed_attempts_threshold"]:
                return None

            if not self._can_alert(
                "R002_REPEATED_LOGIN_FAILURES",
                source,
                now,
                cfg["alert_cooldown_seconds"]
            ):
                return None

            return self._write_alert(
                source=source,
                rule_id="R002_REPEATED_LOGIN_FAILURES",
                event_type="REPEATED_LOGIN_FAILURES",
                severity="MEDIUM",
                message=(
                    f"Repeated failed login attempts detected: "
                    f"{count} failures within "
                    f"{cfg['window_seconds']} seconds."
                ),
                details={
                    "failed_attempts": count,
                    "window_seconds": cfg["window_seconds"],
                    "endpoint": "/login"
                }
            )

    def record_port_connection(self, source, port):
        cfg = self.config["port_scan"]
        now = time.monotonic()

        with self.lock:
            events = self.port_events[source]
            events.append((now, int(port)))

            self._prune_port_events(
                events,
                now,
                cfg["window_seconds"]
            )

            ports = sorted({
                event_port
                for _, event_port in events
            })

            if len(ports) < cfg["distinct_ports_threshold"]:
                return None

            if not self._can_alert(
                "R001_PORT_SCAN",
                source,
                now,
                cfg["alert_cooldown_seconds"]
            ):
                return None

            return self._write_alert(
                source=source,
                rule_id="R001_PORT_SCAN",
                event_type="PORT_SCAN",
                severity="HIGH",
                message=(
                    f"Port scan pattern detected: "
                    f"{len(ports)} distinct monitored ports "
                    f"within {cfg['window_seconds']} seconds."
                ),
                details={
                    "distinct_port_count": len(ports),
                    "ports": ports,
                    "window_seconds": cfg["window_seconds"]
                }
            )