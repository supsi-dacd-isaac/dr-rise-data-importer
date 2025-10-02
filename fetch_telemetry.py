#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Iterable
import datetime as dt
import json as _json

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


def iso_to_epoch_ms(iso_str: str) -> int:
    # Accept Z and offsets
    s = iso_str.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        dt_obj = dt.datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"Invalid ISO8601 datetime: {iso_str}") from e
    if dt_obj.tzinfo is None:
        # assume UTC if no zone provided
        dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
    return int(dt_obj.timestamp() * 1000)


def iso_to_dt(iso_str: str) -> dt.datetime:
    s = iso_str.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"Invalid ISO8601 datetime: {iso_str}") from e
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d


def compute_intervals(period_cfg) -> List[Tuple[int, int]]:
    # Supports: "lastXh" or {start, end} where same hours are applied for each day between dates
    intervals: List[Tuple[int, int]] = []
    now = dt.datetime.now(dt.timezone.utc)

    if isinstance(period_cfg, str):
        s = period_cfg.strip().lower()
        if s.startswith('last') and s.endswith('h'):
            num_str = s[4:-1]
            if not num_str.isdigit():
                raise ValueError(f"Invalid period format: {period_cfg}")
            hours = int(num_str)
            if hours <= 0:
                raise ValueError("Hours must be > 0 for lastXh")
            end_dt = now
            start_dt = end_dt - dt.timedelta(hours=hours)
            intervals.append((int(start_dt.timestamp()*1000), int(end_dt.timestamp()*1000)))
            return intervals
        else:
            raise ValueError(f"Unsupported period string: {period_cfg}")

    if isinstance(period_cfg, dict):
        if 'start' not in period_cfg or 'end' not in period_cfg:
            raise ValueError("period must contain 'start' and 'end'")
        start_dt = iso_to_dt(period_cfg['start'])
        end_dt = iso_to_dt(period_cfg['end'])
        if end_dt <= start_dt:
            raise ValueError("period.end must be after period.start")

        start_date = start_dt.date()
        end_date = end_dt.date()
        start_tod = start_dt.timetz()
        end_tod = end_dt.timetz()

        # If dates are equal, single interval as provided
        if start_date == end_date:
            intervals.append((int(start_dt.timestamp()*1000), int(end_dt.timestamp()*1000)))
            return intervals

        # Enforce end time-of-day after start time-of-day for daily windows
        # to keep windows within same day as per requirement
        if dt.datetime.combine(start_date, end_tod) <= dt.datetime.combine(start_date, start_tod):
            raise ValueError("For daily windows, end time must be after start time on the same day")

        # Iterate each day from start_date (inclusive) to end_date (exclusive)
        days = (end_date - start_date).days
        for i in range(days):
            day = start_date + dt.timedelta(days=i)
            # Build aware datetimes preserving timezone info from start_dt
            day_start = dt.datetime.combine(day, start_tod, tzinfo=start_dt.tzinfo)
            day_end = dt.datetime.combine(day, end_tod, tzinfo=start_dt.tzinfo)
            intervals.append((int(day_start.timestamp()*1000), int(day_end.timestamp()*1000)))
        return intervals

    raise ValueError("Unsupported period config type")


def build_session(timeout: int, retries_cfg: Dict, headers: Dict) -> requests.Session:
    session = requests.Session()
    # Base headers
    session.headers.update(headers or {})

    # Retries
    total = retries_cfg.get('total', 3)
    backoff = retries_cfg.get('backoff_factor', 0.5)
    status_forcelist = retries_cfg.get('status_forcelist', [429, 500, 502, 503, 504])

    retry = Retry(
        total=total,
        backoff_factor=backoff,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # Store default timeout on session
    session.request = _with_timeout(session.request, timeout)
    return session


def _with_timeout(request_func, timeout):
    def wrapper(method, url, **kwargs):
        if 'timeout' not in kwargs or kwargs['timeout'] is None:
            kwargs['timeout'] = timeout
        return request_func(method, url, **kwargs)
    return wrapper


def login_get_token(session: requests.Session, token_url: str, username: str, password: str, verify_ssl: bool, form_extras: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
    print("Logging in…", flush=True)
    # Form-encoded login as per provided curl
    payload = {
        'username': username,
        'password': password,
        # Defaults matching example curl
        'grant_type': '',
        'scope': '',
        'client_id': '',
        'client_secret': '',
    }
    if form_extras:
        payload.update(form_extras)
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    resp = session.post(token_url, data=payload, headers=headers, verify=verify_ssl)
    if not resp.ok:
        raise RuntimeError(f"Login failed {resp.status_code}: {resp.text[:300]}")
    try:
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"Login response is not JSON: {e}")
    token = None
    token_type = data.get('token_type') or 'Bearer'
    for key in ("access_token", "token", "jwt", "bearer", "idToken"):
        if isinstance(data.get(key), str) and data[key]:
            token = data[key]
            break
    if not token and isinstance(data.get('data'), dict):
        for key in ("access_token", "token", "jwt"):
            v = data['data'].get(key)
            if isinstance(v, str) and v:
                token = v
                break
    if not token:
        raise RuntimeError(f"Token not found in login response keys: {list(data.keys())}")
    # Normalize token_type capitalization
    token_type = token_type.capitalize() if isinstance(token_type, str) else 'Bearer'
    print("Login successful", flush=True)
    return token, token_type


# Utility: chunking for batch writes

def chunked(seq: Iterable[Any], size: int) -> Iterable[List[Any]]:
    batch: List[Any] = []
    for item in seq:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def to_timestamp_ms(v: Any) -> Optional[int]:
    if v is None:
        return None
    # Numeric seconds or ms
    if isinstance(v, (int, float)):
        # Heuristic: > 1e12 -> ms, else seconds
        if v > 1e12:
            return int(v)
        if v > 1e9:
            # seconds
            return int(v * 1000)
        # Might be seconds (small), assume seconds
        return int(v * 1000)
    # String: ISO8601 or numeric string
    if isinstance(v, str):
        s = v.strip()
        if s.isdigit():
            return to_timestamp_ms(int(s))
        # ISO8601 parse
        try:
            if s.endswith('Z'):
                s2 = s[:-1] + '+00:00'
            else:
                s2 = s
            d = dt.datetime.fromisoformat(s2)
            if d.tzinfo is None:
                d = d.replace(tzinfo=dt.timezone.utc)
            return int(d.timestamp() * 1000)
        except Exception:
            return None
    return None


KNOWN_TS_KEYS = {'ts', 'timestamp', 'time', 'date', 'datetime'}
META_KEYS = KNOWN_TS_KEYS | {'id', 'usn', 'key', 'signal', 'unit', 'quality', 'status'}


def parse_points_from_json(usn: str, telemetry_key: str, measurement: str, payload: Any) -> List[Dict[str, Any]]:
    # Returns list of Influx JSON points with measurement, tags, fields, time (ms)
    items: List[Dict[str, Any]]
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        # Case: payload has the telemetry key pointing to the array of samples
        if telemetry_key in payload and isinstance(payload[telemetry_key], list):
            items = payload[telemetry_key]
        else:
            # Try common container keys
            for k in ('data', 'items', 'telemetry', 'values', 'result', 'results'):
                if isinstance(payload.get(k), list):
                    items = payload[k]
                    break
            else:
                # Maybe a mapping of series: {signal: [{ts:.., value:..}, ...]}
                points: List[Dict[str, Any]] = []
                for sig, arr in payload.items():
                    if isinstance(arr, list):
                        for it in arr:
                            if not isinstance(it, dict):
                                continue
                            ts = None
                            for tsk in KNOWN_TS_KEYS:
                                if tsk in it:
                                    ts = to_timestamp_ms(it[tsk])
                                    break
                            if ts is None:
                                continue
                            val = None
                            for vk in ('value', 'v', 'val', sig):
                                if vk in it and isinstance(it[vk], (int, float)):
                                    val = it[vk]
                                    break
                            if val is None:
                                # 'value' might be a JSON string with fields
                                if 'value' in it and isinstance(it['value'], str):
                                    try:
                                        inner = _json.loads(it['value'].strip())
                                        if isinstance(inner, dict) and sig in inner and isinstance(inner[sig], (int, float)):
                                            val = inner[sig]
                                    except Exception:
                                        pass
                            if val is None:
                                continue
                            points.append({
                                'measurement': measurement,
                                'tags': {'usn': usn, 'key': telemetry_key, 'signal': str(sig)},
                                'time': ts,
                                'fields': {'value': float(val)}
                            })
                if points:
                    return points
                items = []
    else:
        items = []

    points: List[Dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        # timestamp lookup
        ts = None
        for tsk in KNOWN_TS_KEYS:
            if tsk in it:
                ts = to_timestamp_ms(it[tsk])
                break
        if ts is None and 't' in it:
            ts = to_timestamp_ms(it['t'])
        if ts is None:
            continue

        # Case: value holds a JSON string with multiple metrics
        if 'value' in it and isinstance(it['value'], str):
            inner_points_added = False
            try:
                inner = _json.loads(it['value'].strip())
                if isinstance(inner, dict):
                    for sig, val in inner.items():
                        if isinstance(val, (int, float)):
                            points.append({
                                'measurement': measurement,
                                'tags': {'usn': usn, 'key': telemetry_key, 'signal': str(sig)},
                                'time': ts,
                                'fields': {'value': float(val)}
                            })
                            inner_points_added = True
            except Exception:
                pass
            if inner_points_added:
                continue

        # value extraction strategies when fields are direct
        numeric_keys = [k for k, v in it.items() if k not in META_KEYS and isinstance(v, (int, float))]
        if numeric_keys:
            for sig in numeric_keys:
                val = it[sig]
                points.append({
                    'measurement': measurement,
                    'tags': {'usn': usn, 'key': telemetry_key, 'signal': str(sig)},
                    'time': ts,
                    'fields': {'value': float(val)}
                })
            continue
        # Single numeric value field
        val = None
        for vk in ('value', 'v', 'val', 'y'):
            if vk in it and isinstance(it[vk], (int, float)):
                val = it[vk]
                break
        if val is not None:
            sig = it.get('signal') or it.get('name') or 'value'
            points.append({
                'measurement': measurement,
                'tags': {'usn': usn, 'key': telemetry_key, 'signal': str(sig)},
                'time': ts,
                'fields': {'value': float(val)}
            })
            continue
    return points


def build_influx_client(cfg: Dict[str, Any]):
    from influxdb import InfluxDBClient
    host = cfg.get('host', 'localhost')
    port = int(cfg.get('port', 8086))
    username = cfg.get('username')
    password = cfg.get('password')
    database = cfg.get('database')
    ssl = bool(cfg.get('ssl', False))
    verify_ssl = bool(cfg.get('verify_ssl', True))
    path = cfg.get('path', '')
    gzip = bool(cfg.get('gzip', False))
    timeout = int(cfg.get('timeout_seconds', 10))

    client = InfluxDBClient(
        host=host,
        port=port,
        username=username,
        password=password,
        database=database,
        ssl=ssl,
        verify_ssl=verify_ssl,
        path=path,
        gzip=gzip,
        timeout=timeout,
    )
    return client


def write_points_influx(client, points: List[Dict[str, Any]], time_precision: str = 'ms', max_batch: int = 5000) -> int:
    if not points:
        return 0
    written = 0
    for batch in chunked(points, max_batch):
        ok = client.write_points(batch, time_precision=time_precision)
        if not ok:
            raise RuntimeError("Failed to write points to InfluxDB")
        written += len(batch)
    return written


def fetch_and_save(session: requests.Session, base_url: str, auth_header_value: str, pairs: List[Tuple[str, str]], start_ms: int, end_ms: int, out_dir: Path, save_json: bool, verify_ssl: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    headers = {"Authorization": auth_header_value, "Accept": "application/json"}
    for usn, telemetry in pairs:
        url = f"{base_url.rstrip('/')}/{usn}/telemetry/{telemetry}"
        params = {"start_ts": start_ms, "end_ts": end_ms}
        out_name = f"{usn}_{telemetry}_{start_ms}_{end_ms}.json"
        out_path = out_dir / out_name
        print(f"Fetching {usn}/{telemetry} [{start_ms}->{end_ms}]…", flush=True)
        resp = session.get(url, headers=headers, params=params, verify=verify_ssl)
        if not resp.ok:
            print(f"WARN: Request failed for {usn}/{telemetry}: {resp.status_code} {resp.text[:200]}", file=sys.stderr)
            continue
        if save_json:
            try:
                out_path.write_text(resp.text)
                print(f"Saved {out_path}", flush=True)
            except Exception as e:
                print(f"ERROR: Failed to save {out_path}: {e}", file=sys.stderr)


def load_pairs(usns_cfg: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for usn, telemetries in (usns_cfg or {}).items():
        for t in telemetries:
            pairs.append((usn, t))
    return pairs


def fetch_and_store(session: requests.Session, base_url: str, auth_header_value: str, pairs: List[Tuple[str, str]], intervals: List[Tuple[int, int]], storage_mode: str, out_dir: Path, save_json: bool, verify_ssl: bool, influx_cfg: Optional[Dict[str, Any]]) -> None:
    headers = {"Authorization": auth_header_value, "Accept": "application/json"}
    influx_client = None
    measurement = None
    max_batch = 5000
    if storage_mode == 'influx':
        if not influx_cfg:
            raise RuntimeError("Influx storage selected but 'influxdb' config missing")
        influx_client = build_influx_client(influx_cfg)
        measurement = influx_cfg.get('measurement', 'usn_data')
        cfg_batch = None
        batching = influx_cfg.get('batching') if isinstance(influx_cfg.get('batching'), dict) else None
        if batching:
            try:
                cfg_batch = int(batching.get('batch_size'))
            except Exception:
                cfg_batch = None
        if cfg_batch and cfg_batch > 0:
            max_batch = min(cfg_batch, 5000)

    out_dir.mkdir(parents=True, exist_ok=True)

    for (start_ms, end_ms) in intervals:
        params = {"start_ts": start_ms, "end_ts": end_ms}
        for usn, telemetry in pairs:
            url = f"{base_url.rstrip('/')}/{usn}/telemetry/{telemetry}"
            print(f"Fetching {usn}/{telemetry} [{start_ms}->{end_ms}]…", flush=True)
            resp = session.get(url, headers=headers, params=params, verify=verify_ssl)
            if not resp.ok:
                print(f"WARN: Request failed for {usn}/{telemetry}: {resp.status_code} {resp.text[:200]}", file=sys.stderr)
                continue

            if storage_mode == 'file':
                if save_json:
                    out_name = f"{usn}_{telemetry}_{start_ms}_{end_ms}.json"
                    out_path = out_dir / out_name
                    try:
                        out_path.write_text(resp.text)
                        print(f"Saved {out_path}", flush=True)
                    except Exception as e:
                        print(f"ERROR: Failed to save {out_path}: {e}", file=sys.stderr)
            elif storage_mode == 'influx':
                try:
                    payload = resp.json()
                except Exception as e:
                    print(f"ERROR: Response is not JSON for {usn}/{telemetry}: {e}", file=sys.stderr)
                    continue
                points = parse_points_from_json(usn, telemetry, measurement, payload)
                if not points:
                    print(f"WARN: No points parsed for {usn}/{telemetry}", file=sys.stderr)
                    continue
                try:
                    written = write_points_influx(influx_client, points, time_precision='ms', max_batch=max_batch)
                    print(f"Wrote {written} points for {usn}/{telemetry}", flush=True)
                except Exception as e:
                    print(f"ERROR: Failed to write to InfluxDB for {usn}/{telemetry}: {e}", file=sys.stderr)
            else:
                print(f"ERROR: Unknown storage mode '{storage_mode}'", file=sys.stderr)
                return


def main():
    ap = argparse.ArgumentParser(description="Login and fetch telemetry data using config JSON.")
    ap.add_argument("--config", required=True, help="Path to configuration JSON file.")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"Config not found: {cfg_path}", file=sys.stderr)
        sys.exit(2)

    cfg = json.loads(cfg_path.read_text())

    rest = cfg.get("rest_api", {})
    auth = rest.get("auth", {})
    base_url = rest.get("base_url")
    token_url = auth.get("token_url")
    username = auth.get("username")
    password = auth.get("password")
    timeout = rest.get("timeout_seconds", 30)
    headers = rest.get("headers", {})
    retries_cfg = rest.get("retries", {})
    verify_ssl = rest.get("verify_ssl", True)
    form_extras = auth.get("form", {})

    if not base_url or not token_url or not username or not password:
        print("Missing required REST config: base_url, auth.token_url, auth.username, auth.password", file=sys.stderr)
        sys.exit(2)

    # period: accept either 'period' (string or dict) or fallback 'periodLast'
    period_cfg = cfg.get("period")
    if period_cfg is None and cfg.get('periodLast') is not None:
        period_cfg = cfg.get('periodLast')
    if period_cfg is None:
        print("Missing 'period' in config", file=sys.stderr)
        sys.exit(2)

    try:
        intervals = compute_intervals(period_cfg)
    except Exception as e:
        print(f"Invalid period: {e}", file=sys.stderr)
        sys.exit(2)

    if not intervals:
        print("No intervals to fetch after parsing period", file=sys.stderr)
        sys.exit(2)

    pairs = load_pairs(cfg.get("usns", {}))
    if not pairs:
        print("No USN/telemetry pairs configured under 'usns'", file=sys.stderr)
        sys.exit(2)

    # storage selection
    storage_mode = (cfg.get('storage') or 'file').lower()
    output_cfg = cfg.get("output", {})
    save_json = bool(output_cfg.get("save_json", True))
    out_dir = Path(output_cfg.get("directory", "data"))

    influx_cfg = cfg.get('influxdb') if storage_mode == 'influx' else None

    session = build_session(timeout=timeout, retries_cfg=retries_cfg, headers=headers)

    token, token_type = login_get_token(session, token_url, username, password, verify_ssl, form_extras=form_extras)
    auth_header_value = f"{token_type} {token}"

    fetch_and_store(
        session=session,
        base_url=base_url,
        auth_header_value=auth_header_value,
        pairs=pairs,
        intervals=intervals,
        storage_mode=storage_mode,
        out_dir=out_dir,
        save_json=save_json,
        verify_ssl=verify_ssl,
        influx_cfg=influx_cfg,
    )


if __name__ == "__main__":
    main()
