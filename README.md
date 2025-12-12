# DR-RISE Data Importer

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
Edit `conf/config.json` or `conf/config_all.json`. Key sections:

### REST API
- `rest_api.base_url`: e.g. `https://api.drrise.idener.ai/usn/`
- `rest_api.auth.token_url`: `https://api.drrise.idener.ai/login` (form-encoded)
- `rest_api.auth.username`, `rest_api.auth.password`
- `rest_api.verify_ssl`, `rest_api.timeout_seconds`, `rest_api.headers`, `rest_api.retries`

### Auto-Discovery Mode (Recommended)
Automatically discover USNs and their appliances from the API:

```json
"auto_discover": {
  "enabled": true,
  "use_appliances": true,
  "telemetry_filter": null,
  "save_discovered": true
}
```

- `enabled`: Set to `true` to auto-discover USNs and appliances from the API
- `use_appliances`: If `true`, fetches appliances from `/usn/{id}/appliances`; if `false`, uses `/usn/{id}/telemetry`
- `telemetry_filter`: Optional list of patterns to filter appliances (e.g., `["*_A*"]` for only aggregated meters)
- `save_discovered`: If `true`, saves discovered USNs/appliances to `data/discovered_usns.json`

### Manual USN Configuration
When `auto_discover.enabled` is `false`, configure USNs manually:

```json
"usns": {
  "5b175a90-7cd9-11f0-9a52-63eb4102b574": ["01_A01"],
  "68444f20-7cd9-11f0-9a52-63eb4102b574": ["02_A02"]
}
```

### Time Period
- `period`: choose one of:
  - `"lastXh"` (e.g. `"last24h"`)
  - `{"start":"ISO8601","end":"ISO8601"}` → same hours per day for each day in [start_date, end_date)

### Storage
- `storage`: `"file"` or `"influx"`
- `output` (file mode): `directory`, `save_json`
- `influxdb` (influx mode): `host`, `port`, `username`, `password`, `database`, `measurement`, `batching.batch_size` (capped at 5000)

## Run
Activate your venv and run:

```bash
source .venv/bin/activate
python fetch_telemetry.py --config conf/config_all.json
```

### Command Line Options
- `--config`: Path to configuration JSON file (required)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--log-file`: Optional log file path

### Examples

**Basic run with auto-discovery (recommended):**
```bash
python fetch_telemetry.py --config conf/config_all.json
```

**Run with verbose debug logging:**
```bash
python fetch_telemetry.py --config conf/config_all.json --log-level DEBUG
```

**Run with log file for later analysis:**
```bash
python fetch_telemetry.py --config conf/config_all.json --log-level INFO --log-file logs/import.log
```

**Run with manual USN configuration:**
```bash
python fetch_telemetry.py --config conf/config.json
```

**One-liner (activate venv and run):**
```bash
source .venv/bin/activate && python fetch_telemetry.py --config conf/config_all.json
```

**Run as a cron job (every hour):**
```bash
# Add to crontab with: crontab -e
0 * * * * cd /path/to/dr-rise-data-importer && .venv/bin/python fetch_telemetry.py --config conf/config_all.json --log-file logs/cron.log
```

**Run with custom PYTHONPATH:**
```bash
PYTHONPATH=/path/to/dr-rise-data-importer python fetch_telemetry.py --config conf/config_all.json
```

## Output Files

### Discovered USNs (`data/discovered_usns.json`)
When `auto_discover.save_discovered` is `true`, a JSON file is saved with all discovered USNs:

```json
{
  "discovered_at": "2025-12-11T12:45:05.326955+00:00",
  "usns": {
    "5b175a90-7cd9-11f0-9a52-63eb4102b574": {
      "name": "ES_01",
      "asn_id": 1,
      "appliances": ["01_A01", "01_P03", "01_S01", ...]
    },
    "68444f20-7cd9-11f0-9a52-63eb4102b574": {
      "name": "ES_02",
      "asn_id": 1,
      "appliances": ["02_A02", "02_P08", ...]
    }
  }
}
```

## InfluxDB Write Format
- **Measurement**: from config (default: `usn_data`)
- **Tags**:
  - `usn_id`: UUID of the USN (e.g., `5b175a90-7cd9-11f0-9a52-63eb4102b574`)
  - `usn_name`: Human-readable name (e.g., `ES_01`)
  - `appliance_name`: Appliance identifier (e.g., `01_A01`)
  - `appliance_type`: Type of the appliance retrieved from the API (e.g., `smart_meter`, `pv_inverter`)
  - `asn_id`: Formatted ASN identifier (e.g., `ASN_01` from raw value `1`)
  - `country`: Country code extracted from USN name (e.g., `ES` from `ES_01`)
  - `signal`: Telemetry signal name (e.g., `energy_consumed`)
- **Fields**: `{ value }`
- **Time precision**: ms
- **Batching**: max 5000 points per write (uses `min(config.batch_size, 5000)`)

### Example InfluxQL Queries

```sql
-- Get data for a specific appliance
SELECT * FROM usn_data WHERE usn_name = 'ES_01' AND appliance_name = '01_A01' LIMIT 10

-- Aggregate by USN
SELECT mean(value) FROM usn_data WHERE time > now() - 1d GROUP BY usn_name, signal

-- Filter by appliance type (from API)
SELECT sum(value) FROM usn_data WHERE appliance_type = 'smart_meter' GROUP BY usn_name

-- Filter by appliance name pattern (legacy)
SELECT sum(value) FROM usn_data WHERE appliance_name =~ /.*_A.*/ GROUP BY usn_name

-- Filter by country
SELECT mean(value) FROM usn_data WHERE country = 'ES' AND time > now() - 1d GROUP BY usn_name

-- Filter by ASN
SELECT sum(value) FROM usn_data WHERE asn_id = 'ASN_01' GROUP BY appliance_name
```

## API Endpoints Used
The importer uses the following DR-RISE API endpoints:
- `POST /login` - Authentication
- `GET /usn` - List all USNs (auto-discovery)
- `GET /usn/{id}/appliances` - List appliances for a USN (auto-discovery)
- `GET /usn/{id}/telemetry/{key}` - Fetch telemetry data

## Notes
- Login uses `application/x-www-form-urlencoded` with username/password.
- Daily period windows require end time-of-day > start time-of-day.
- Token caching is enabled; tokens are stored in `tkns/` directory.

## Troubleshooting
- **WARN: No points parsed…** → The API response shape didn't match expectations; check saved JSON (file mode) or endpoint parameters.
- **Login failed…** → Verify `auth.username`/`auth.password` and `auth.token_url`.
- **Influx write failed…** → Confirm database exists and credentials are correct.
- **Failed to fetch appliances for USN…** → The USN ID may be invalid or the USN has no appliances registered.
