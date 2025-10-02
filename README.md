
Fetch telemetry from the Dr. RISE REST API and store it locally as JSON files or remotely into InfluxDB 1.x.

## Requirements
- Python 3.8+
- A virtual environment (recommended)
- Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration
Edit conf/config.json. Key sections:
- rest_api
  - base_url: e.g. https://api.drrise.idener.ai/usn/
  - auth.token_url: https://api.drrise.idener.ai/login (form-encoded)
  - auth.username, auth.password
  - verify_ssl, timeout_seconds, headers, retries
- usns: map of USN to telemetry keys
- period: choose one of
  - "lastXh" (e.g. "last24h")
  - {"start":"ISO8601","end":"ISO8601"} → same hours per day for each day in [start_date, end_date)
- storage: "file" or "influx"
- output (file mode): directory, save_json
- influxdb (influx mode): host, port, username, password, database, measurement, batching.batch_size (capped at 5000)

Notes
- Login uses application/x-www-form-urlencoded with username/password.
- Daily period windows require end time-of-day > start time-of-day.

## Run
Activate your venv and run:

```bash
source .venv/bin/activate
python fetch_telemetry.py --config conf/config.json
```

## InfluxDB write format
- measurement: from config (default: usn_data)
- tags: { usn, key, signal }
- fields: { value }
- time precision: ms
- batching: max 5000 points per write (uses min(config.batch_size, 5000))

## Troubleshooting
- WARN: No points parsed… → The API response shape didn’t match expectations; check saved JSON (file mode) or endpoint parameters.
- Login failed… → Verify auth.username/password and auth.token_url.
- Influx write failed… → Confirm database exists and credentials are correct.

