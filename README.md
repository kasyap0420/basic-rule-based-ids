# Basic Rule-Based IDS

A basic Python rule-based Intrusion Detection System (IDS - a system that monitors activity and identifies suspicious behavior).

The project uses predefined rules and time-based thresholds instead of Artificial Intelligence or Machine Learning. It was created as a simple, functional IDS that can be tested using controlled traffic.

## What the IDS Detects

### 1. Port-Scan Behavior
The project runs TCP sensor ports from `9001` to `9008`. If the same source connects to at least **5 different monitored ports within 10 seconds**, the activity is classified as suspicious port-scan behavior.

### 2. Repeated Failed Login Attempts
If the same source produces at least **5 failed login attempts within 60 seconds**, the IDS generates a repeated-login-failure alert.

### 3. High HTTP Request Rate
If the same source sends at least **20 monitored HTTP requests within 10 seconds**, the IDS generates a high-request-rate alert.

## How It Works

The system follows this process:

```text
Incoming activity
    -> Activity monitoring
    -> Event and pattern counting
    -> Rule and threshold comparison
    -> Normal or suspicious classification
    -> Alert generation
    -> Event logging
```

Detection thresholds are stored centrally in `config.json` so they can be changed without modifying the detection code.

## Alerts and Logging

When suspicious activity is detected, the IDS records a structured JSONL alert (JSON Lines - one JSON record per line) containing information such as:

- Timestamp
- Source IP address
- Rule ID
- Event type
- Severity
- Detection message
- Rule-specific evidence such as port numbers or request counts

Runtime alerts are written to:

```text
logs/alerts.jsonl
```

The runtime alert file is intentionally excluded from Git because it is generated while the application is running.

## Project Files

- `app.py` - Flask HTTP application and IDS server startup.
- `ids_engine.py` - Core rule-based detection and alert logging logic.
- `port_sensor.py` - TCP sensor used to detect port-scan-like behavior.
- `test_traffic.py` - Generates controlled test traffic for IDS verification.
- `config.json` - Central detection thresholds and server configuration.
- `requirements.txt` - Required Python packages.
- `.python-version` - Python runtime version used by the project.
- `Test_ScreenShots/` - Screenshots showing testing and detection results.
- `logs/` - Runtime alert-log directory.

## Technology Used

- Python
- Flask (lightweight web framework)
- Waitress (WSGI application server used to run the Flask application)
- Python standard-library networking and threading modules
- JSONL alert logging

No Machine Learning, Snort, Suricata, database, or external detection service is required.

## Local Setup

### 1. Create a virtual environment

```cmd
python -m venv .venv
```

### 2. Activate it on Windows

```cmd
.venv\Scripts\activate.bat
```

### 3. Install dependencies

```cmd
python -m pip install -r requirements.txt
```

### 4. Start the IDS

```cmd
python app.py
```

The HTTP service runs locally on:

```text
http://127.0.0.1:5000
```

## Controlled Testing

Keep `python app.py` running in one CMD window and use another CMD window for testing.

Normal traffic:

```cmd
python test_traffic.py normal
```

Controlled port-scan test:

```cmd
python test_traffic.py scan
```

Repeated failed-login test:

```cmd
python test_traffic.py login
```

High-request-rate test:

```cmd
python test_traffic.py rate
```

The tests only generate controlled traffic for demonstrating the IDS functionality.

## Scope and Limitation

This is a **basic rule-based IDS**, not a full packet-sniffing network IDS such as Snort or Suricata.

The port-scan detector monitors only the configured TCP sensor ports. It does not capture every packet, inspect all network traffic, perform deep packet inspection, or monitor every port on the computer.

The project demonstrates the complete basic IDS flow: monitored activity triggers predefined rules, suspicious behavior is identified, an alert is generated, and the event is logged.
