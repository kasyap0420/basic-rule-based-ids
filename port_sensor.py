import socket
import threading


class PortScanSensor:
    def __init__(self, detection_engine, config):
        self.engine = detection_engine
        self.config = config

        self.stop_event = threading.Event()
        self.listeners = []
        self.threads = []

    def start(self):
        host = self.config["listen_host"]
        threshold = self.config["distinct_ports_threshold"]

        failed_ports = []

        for port in self.config["ports"]:
            listener = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            listener.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
            )

            try:
                listener.bind((host, int(port)))
                listener.listen(20)
                listener.settimeout(1.0)

                self.listeners.append(
                    (listener, int(port))
                )

            except OSError:
                failed_ports.append(int(port))
                listener.close()

        if len(self.listeners) < threshold:
            self.stop()

            raise RuntimeError(
                f"Port sensor needs at least "
                f"{threshold} available ports, "
                f"but only {len(self.listeners)} "
                f"could be opened. "
                f"Unavailable ports: {failed_ports}"
            )

        for listener, port in self.listeners:
            thread = threading.Thread(
                target=self._accept_loop,
                args=(listener, port),
                daemon=True,
                name=f"ids-port-{port}"
            )

            thread.start()
            self.threads.append(thread)

        active_ports = [
            port
            for _, port in self.listeners
        ]

        print(
            f"[IDS] Port-scan sensor listening "
            f"on {host}: {active_ports}",
            flush=True
        )

        if failed_ports:
            print(
                f"[IDS] Warning: unavailable "
                f"sensor ports: {failed_ports}",
                flush=True
            )

    def _accept_loop(self, listener, port):
        while not self.stop_event.is_set():
            try:
                connection, address = listener.accept()

            except socket.timeout:
                continue

            except OSError:
                break

            try:
                self.engine.record_port_connection(
                    address[0],
                    port
                )

            finally:
                connection.close()

    def stop(self):
        self.stop_event.set()

        for listener, _ in self.listeners:
            try:
                listener.close()

            except OSError:
                pass

        self.listeners.clear()