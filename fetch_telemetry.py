#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Iterable
import datetime as dt
import json as _json
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import hashlib
import base64
from urllib.parse import urlparse
import logging

# Module logger
logger = logging.getLogger(__name__)


def setup_logging(level: Optional[str] = None, log_file: Optional[str] = None) -> None:
    lvl_name = (level or "INFO").upper()
    lvl = getattr(logging, lvl_name, logging.INFO)

    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler()
    sh.setLevel(lvl)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    if log_file:
        try:
            fh = logging.FileHandler(log_file)
            fh.setLevel(lvl)
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except Exception as e:
            logger.warning("Failed to set log file %s: %s", log_file, e)

    for noisy in ("urllib3", "requests", "influxdb"):
        logging.getLogger(noisy).setLevel(logging.WARNING if lvl > logging.DEBUG else logging.DEBUG)


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


# Helper: format millis epoch to ISO8601 Z string

def ms_to_iso_z(ms: Any) -> str:
    try:
        ms_int = int(ms)
        d = dt.datetime.fromtimestamp(ms_int / 1000.0, tz=dt.timezone.utc)
        return d.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(ms)


def _fmt_duration(ms_remaining: int) -> str:
    try:
        if ms_remaining is None:
            return "unknown"
        secs = max(0, int(ms_remaining // 1000))
        if secs < 60:
            return f"{secs}s"
        mins = secs // 60
        if mins < 60:
            return f"{mins}m {secs % 60}s"
        hours = mins // 60
        if hours < 24:
            return f"{hours}h {mins % 60}m"
        days = hours // 24
        return f"{days}d {hours % 24}h"
    except Exception:
        return "unknown"


# -------------------- Token cache helpers --------------------

TOKEN_SKEW_MS = 60_000  # 60s safety window

def _token_cache_dir() -> Path:
    # store tokens next to this script under tkns/
    d = Path(__file__).resolve().parent / 'tkns'
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_file_name(token_url: str, username: str) -> Path:
    parsed = urlparse(token_url)
    host = (parsed.hostname or 'host').replace(':', '_')
    ident = f"{username}@{host}"
    h = hashlib.sha1(token_url.encode('utf-8')).hexdigest()[:10]
    fname = f"{ident}_{h}.json"
    return _token_cache_dir() / fname


def _decode_jwt_exp_ms(token: str) -> Optional[int]:
    # best-effort decode of JWT exp claim (seconds since epoch)
    parts = token.split('.')
    if len(parts) != 3:
        return None
    try:
        payload = parts[1]
        # base64url decode with padding
        pad = '=' * (-len(payload) % 4)
        data = base64.urlsafe_b64decode(payload + pad)
        obj = json.loads(data.decode('utf-8'))
        exp = obj.get('exp')
        if isinstance(exp, (int, float)):
            return int(float(exp) * 1000)
    except Exception:
        return None
    return None


def _load_cached_token(cache_path: Path) -> Optional[Tuple[str, str]]:
    try:
        if not cache_path.exists():
            return None
        data = json.loads(cache_path.read_text())
        token = data.get('token')
        token_type = data.get('token_type') or 'Bearer'
        expires_at = data.get('expires_at_ms')
        now_ms = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
        if token and isinstance(token, str):
            if isinstance(expires_at, (int, float)):
                if now_ms + TOKEN_SKEW_MS < int(expires_at):
                    return token, token_type
                else:
                    return None
            # No expiry info: fall back to JWT exp if possible
            jwt_exp = _decode_jwt_exp_ms(token)
            if isinstance(jwt_exp, int) and now_ms + TOKEN_SKEW_MS < jwt_exp:
                return token, token_type
    except Exception:
        return None
    return None


def _save_token(cache_path: Path, token: str, token_type: str, expires_at_ms: Optional[int]) -> None:
    data = {
        'token': token,
        'token_type': token_type,
        'issued_at_ms': int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000),
    }
    if isinstance(expires_at_ms, int):
        data['expires_at_ms'] = expires_at_ms
    try:
        cache_path.write_text(json.dumps(data))
        try:
            # best-effort restrict perms on POSIX
            cache_path.chmod(0o600)
        except Exception:
            pass
    except Exception as e:
        logger.warning("Failed to write token cache %s: %s", cache_path, e)


def _load_cached_token_with_status(cache_path: Path) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
    status: Dict[str, Any] = {
        'found': False,
        'usable': False,
        'reason': None,
        'expires_at_ms': None,
        'now_ms': int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000),
        'skew_ms': TOKEN_SKEW_MS,
    }
    try:
        if not cache_path.exists():
            status['reason'] = 'not_found'
            return None, None, status
        data = json.loads(cache_path.read_text())
        status['found'] = True
        token = data.get('token')
        token_type = data.get('token_type') or 'Bearer'
        expires_at = data.get('expires_at_ms')
        status['expires_at_ms'] = expires_at
        now_ms = status['now_ms']
        # Evaluate usability
        if not token or not isinstance(token, str):
            status['reason'] = 'empty_token'
            return None, None, status
        # Expiry known
        if isinstance(expires_at, (int, float)):
            if now_ms + TOKEN_SKEW_MS < int(expires_at):
                status['usable'] = True
                status['reason'] = 'valid_not_expired'
                return token, token_type, status
            else:
                status['reason'] = 'expired_or_within_skew'
                return None, None, status
        # No expiry info: try JWT exp
        jwt_exp = _decode_jwt_exp_ms(token)
        status['expires_at_ms'] = jwt_exp
        if isinstance(jwt_exp, int) and now_ms + TOKEN_SKEW_MS < jwt_exp:
            status['usable'] = True
            status['reason'] = 'valid_not_expired_jwt'
            return token, token_type, status
        status['reason'] = 'no_expiry_or_jwt_expired'
        return None, None, status
    except Exception as e:
        status['reason'] = f'cache_error:{e.__class__.__name__}'
        return None, None, status


# -------------------------------------------------------------

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
    # Try cache first with detailed status logging
    cache_path = _cache_file_name(token_url, username)
    token, token_type, st = _load_cached_token_with_status(cache_path)
    if st.get('found') and st.get('usable') and token and token_type:
        exp_ms = st.get('expires_at_ms')
        rem = None if exp_ms is None else (st['expires_at_ms'] - st['now_ms'])
        logger.info(
            "Token cache hit; reusing token (expires at %s, in %s)",
            ms_to_iso_z(exp_ms) if exp_ms else 'unknown',
            _fmt_duration(rem),
        )
        return token, token_type
    else:
        if not st.get('found'):
            logger.info("No cached token found; requesting a new token")
        else:
            exp_ms = st.get('expires_at_ms')
            reason = st.get('reason') or 'unusable'
            when = ms_to_iso_z(exp_ms) if exp_ms else 'unknown'
            logger.info("Cached token unusable (%s); requesting a new token (cached exp: %s)", reason, when)

    # Form-encoded login
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
    token_type = token_type.capitalize() if isinstance(token_type, str) else 'Bearer'

    # Determine expiry
    now_ms = int(dt.datetime.now(dt.timezone.utc).timestamp() * 1000)
    expires_at_ms: Optional[int] = None
    expires_in = None
    for k in ('expires_in', 'expiresIn', 'expires'):
        v = data.get(k)
        if v is None and isinstance(data.get('data'), dict):
            v = data['data'].get(k)
        if isinstance(v, (int, float, str)):
            try:
                expires_in = int(float(v))
                break
            except Exception:
                pass
    if isinstance(expires_in, int) and expires_in > 0:
        expires_at_ms = now_ms + expires_in * 1000
    else:
        jwt_exp = _decode_jwt_exp_ms(token)
        if isinstance(jwt_exp, int) and jwt_exp > now_ms:
            expires_at_ms = jwt_exp

    # Log new token expiry info
    if expires_at_ms:
        logger.info(
            "Obtained new token (expires at %s, in %s); caching",
            ms_to_iso_z(expires_at_ms),
            _fmt_duration(expires_at_ms - now_ms),
        )
    else:
        logger.info("Obtained new token (expiry unknown); caching")

    # Cache token
    _save_token(cache_path, token, token_type, expires_at_ms)

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


def _format_asn_id(asn_id_raw: Any) -> str:
    """Format raw asn_id (e.g., 1) to tag format (e.g., 'ASN_01')."""
    if asn_id_raw is None:
        return 'ASN_00'
    try:
        asn_num = int(asn_id_raw)
        return f'ASN_{asn_num:02d}'
    except (ValueError, TypeError):
        return f'ASN_{asn_id_raw}'


def _extract_country(usn_name: str) -> str:
    """Extract country code from USN name (e.g., 'ES_01' -> 'ES')."""
    if not usn_name:
        return 'XX'
    # Split by underscore and take the first part
    parts = usn_name.split('_')
    if parts and len(parts[0]) >= 2:
        return parts[0].upper()
    return usn_name[:2].upper() if len(usn_name) >= 2 else 'XX'


def parse_points_from_json(usn_id: str, usn_name: str, appliance_name: str, measurement: str, payload: Any, asn_id_raw: Any = None) -> List[Dict[str, Any]]:
    # Returns list of Influx JSON points with measurement, tags, fields, time (ms)
    # Tags include: usn_id, usn_name, appliance_name, asn_id, country, signal
    base_tags = {
        'usn_id': usn_id,
        'usn_name': usn_name,
        'appliance_name': appliance_name,
        'asn_id': _format_asn_id(asn_id_raw),
        'country': _extract_country(usn_name),
    }
    
    items: List[Dict[str, Any]]
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        # Case: payload has the telemetry key pointing to the array of samples
        if appliance_name in payload and isinstance(payload[appliance_name], list):
            items = payload[appliance_name]
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
                                'tags': {**base_tags, 'signal': str(sig)},
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
                                'tags': {**base_tags, 'signal': str(sig)},
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
                    'tags': {**base_tags, 'signal': str(sig)},
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
                'tags': {**base_tags, 'signal': str(sig)},
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
        logger.info("Fetching %s/%s [%s->%s]", usn, telemetry, ms_to_iso_z(start_ms), ms_to_iso_z(end_ms))
        resp = session.get(url, headers=headers, params=params, verify=verify_ssl)
        if not resp.ok:
            logger.warning("Request failed for %s/%s: %s %s", usn, telemetry, resp.status_code, resp.text[:200])
            continue
        if save_json:
            try:
                out_path.write_text(resp.text)
                logger.info("Saved %s", out_path)
            except Exception as e:
                logger.error("Failed to save %s: %s", out_path, e)


def load_pairs(usns_cfg: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for usn, telemetries in (usns_cfg or {}).items():
        for t in telemetries:
            pairs.append((usn, t))
    return pairs


# -------------------- Auto-discovery functions --------------------

def fetch_all_usns(session: requests.Session, base_url: str, auth_header_value: str, verify_ssl: bool) -> List[Dict[str, Any]]:
    """Fetch all USNs from the API (/usn endpoint)."""
    # base_url is like "https://api.drrise.idener.ai/usn/" - we need root
    api_root = base_url.rstrip('/').rsplit('/usn', 1)[0]
    url = f"{api_root}/usn"
    headers = {"Authorization": auth_header_value, "Accept": "application/json"}
    logger.info("Fetching all USNs from %s", url)
    resp = session.get(url, headers=headers, verify=verify_ssl)
    if not resp.ok:
        raise RuntimeError(f"Failed to fetch USNs: {resp.status_code} {resp.text[:300]}")
    try:
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"USN response is not JSON: {e}")
    
    # API may return a list directly or wrapped in a container
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ('data', 'items', 'usns', 'results'):
            if isinstance(data.get(key), list):
                return data[key]
        # If dict with USN IDs as keys
        if all(isinstance(v, dict) for v in data.values()):
            return [{'id': k, **v} for k, v in data.items()]
    return []


def fetch_usn_details(session: requests.Session, base_url: str, auth_header_value: str, usn_id: str, verify_ssl: bool) -> Dict[str, Any]:
    """Fetch details for a specific USN by UUID."""
    url = f"{base_url.rstrip('/')}/{usn_id}"
    headers = {"Authorization": auth_header_value, "Accept": "application/json"}
    logger.debug("Fetching USN details: %s", url)
    resp = session.get(url, headers=headers, verify=verify_ssl)
    if not resp.ok:
        logger.warning("Failed to fetch USN details for %s: %s", usn_id, resp.status_code)
        return {}
    try:
        return resp.json()
    except Exception:
        return {}


def fetch_usn_appliances(session: requests.Session, base_url: str, auth_header_value: str, usn_id: str, verify_ssl: bool) -> List[Dict[str, Any]]:
    """Fetch all appliances for a specific USN (/usn/{id}/appliances)."""
    url = f"{base_url.rstrip('/')}/{usn_id}/appliances"
    headers = {"Authorization": auth_header_value, "Accept": "application/json"}
    logger.debug("Fetching appliances for USN %s: %s", usn_id, url)
    resp = session.get(url, headers=headers, verify=verify_ssl)
    if not resp.ok:
        logger.warning("Failed to fetch appliances for USN %s: %s %s", usn_id, resp.status_code, resp.text[:200])
        return []
    try:
        data = resp.json()
    except Exception as e:
        logger.warning("Appliances response is not JSON for %s: %s", usn_id, e)
        return []
    
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ('data', 'items', 'appliances', 'results'):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def fetch_usn_telemetry_keys(session: requests.Session, base_url: str, auth_header_value: str, usn_id: str, verify_ssl: bool) -> List[str]:
    """Fetch available telemetry keys for a USN (/usn/{id}/telemetry)."""
    url = f"{base_url.rstrip('/')}/{usn_id}/telemetry"
    headers = {"Authorization": auth_header_value, "Accept": "application/json"}
    logger.debug("Fetching telemetry keys for USN %s: %s", usn_id, url)
    resp = session.get(url, headers=headers, verify=verify_ssl)
    if not resp.ok:
        logger.warning("Failed to fetch telemetry keys for USN %s: %s", usn_id, resp.status_code)
        return []
    try:
        data = resp.json()
    except Exception:
        return []
    
    # Response is typically a dict with telemetry keys as keys
    if isinstance(data, dict):
        return list(data.keys())
    if isinstance(data, list):
        # May be list of dicts with 'key' field
        keys = []
        for item in data:
            if isinstance(item, dict) and 'key' in item:
                keys.append(item['key'])
            elif isinstance(item, str):
                keys.append(item)
        return keys
    return []


def auto_discover_pairs(session: requests.Session, base_url: str, auth_header_value: str, verify_ssl: bool, use_appliances: bool = True, telemetry_filter: Optional[List[str]] = None) -> Tuple[List[Tuple[str, str]], Dict[str, Dict[str, Any]]]:
    """
    Auto-discover USNs and their telemetry keys/appliances from the API.
    
    Args:
        session: HTTP session
        base_url: Base URL for USN endpoints
        auth_header_value: Authorization header value
        verify_ssl: Whether to verify SSL
        use_appliances: If True, use appliance IDs as telemetry keys; if False, use telemetry endpoint
        telemetry_filter: Optional list of telemetry key patterns to filter (if None, fetch all)
    
    Returns:
        Tuple of (pairs list, usns_dict) where usns_dict maps USN ID -> {name, asn_id, appliances}
    """
    usns = fetch_all_usns(session, base_url, auth_header_value, verify_ssl)
    logger.info("Discovered %d USNs", len(usns))
    
    pairs: List[Tuple[str, str]] = []
    usns_dict: Dict[str, Dict[str, Any]] = {}
    
    for usn_data in usns:
        usn_id = usn_data.get('id') or usn_data.get('uuid') or usn_data.get('usn_id')
        if not usn_id:
            logger.warning("USN entry missing ID: %s", usn_data)
            continue
        
        usn_name = usn_data.get('name', usn_id)
        asn_id_raw = usn_data.get('asn_id')  # e.g., 1, 2, etc.
        
        if use_appliances:
            # Get appliances for this USN
            appliances = fetch_usn_appliances(session, base_url, auth_header_value, usn_id, verify_ssl)
            telemetry_keys = []
            for appl in appliances:
                appl_id = appl.get('appliance_id') or appl.get('id') or appl.get('name')
                if appl_id:
                    telemetry_keys.append(appl_id)
            logger.info("USN %s (%s): found %d appliances: %s", usn_id, usn_name, len(telemetry_keys), telemetry_keys)
        else:
            # Get telemetry keys directly
            telemetry_keys = fetch_usn_telemetry_keys(session, base_url, auth_header_value, usn_id, verify_ssl)
            logger.info("USN %s (%s): found %d telemetry keys", usn_id, usn_name, len(telemetry_keys))
        
        # Apply filter if provided
        if telemetry_filter:
            import fnmatch
            filtered_keys = []
            for key in telemetry_keys:
                for pattern in telemetry_filter:
                    if fnmatch.fnmatch(key, pattern):
                        filtered_keys.append(key)
                        break
            telemetry_keys = filtered_keys
        
        # Always save the USN info (even if no appliances)
        usns_dict[usn_id] = {
            'name': usn_name,
            'asn_id': asn_id_raw,
            'appliances': telemetry_keys
        }
        
        # Only add to pairs if there are telemetry keys to fetch
        for key in telemetry_keys:
            pairs.append((usn_id, key))
    
    return pairs, usns_dict


def save_discovered_config(usns_dict: Dict[str, Dict[str, Any]], out_path: Path) -> None:
    """Save discovered USNs and telemetry keys to a JSON file for reference."""
    data = {
        'discovered_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'usns': usns_dict
    }
    try:
        out_path.write_text(json.dumps(data, indent=2))
        logger.info("Saved discovered configuration to %s", out_path)
    except Exception as e:
        logger.warning("Failed to save discovered config: %s", e)


def fetch_and_store(session: requests.Session, base_url: str, auth_header_value: str, pairs: List[Tuple[str, str]], intervals: List[Tuple[int, int]], storage_mode: str, out_dir: Path, save_json: bool, verify_ssl: bool, influx_cfg: Optional[Dict[str, Any]], usn_metadata: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
    """
    Fetch telemetry data and store it.
    
    Args:
        usn_metadata: Optional mapping of USN ID -> {name, asn_id} for tagging in InfluxDB
    """
    headers = {"Authorization": auth_header_value, "Accept": "application/json"}
    influx_client = None
    measurement = None
    max_batch = 5000
    usn_metadata = usn_metadata or {}
    
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
        for usn_id, appliance_name in pairs:
            # Get USN metadata from mapping, fallback to defaults
            meta = usn_metadata.get(usn_id, {})
            usn_name = meta.get('name', usn_id)
            asn_id_raw = meta.get('asn_id')
            
            url = f"{base_url.rstrip('/')}/{usn_id}/telemetry/{appliance_name}"
            logger.info("Fetching %s (%s) / %s [%s->%s]", usn_id, usn_name, appliance_name, ms_to_iso_z(start_ms), ms_to_iso_z(end_ms))
            resp = session.get(url, headers=headers, params=params, verify=verify_ssl)
            if not resp.ok:
                logger.warning("Request failed for %s/%s: %s %s", usn_id, appliance_name, resp.status_code, resp.text[:200])
                continue

            if storage_mode == 'file':
                if save_json:
                    out_name = f"{usn_id}_{appliance_name}_{start_ms}_{end_ms}.json"
                    out_path = out_dir / out_name
                    try:
                        out_path.write_text(resp.text)
                        logger.info("Saved %s", out_path)
                    except Exception as e:
                        logger.error("Failed to save %s: %s", out_path, e)
            elif storage_mode == 'influx':
                try:
                    payload = resp.json()
                except Exception as e:
                    logger.error("Response is not JSON for %s/%s: %s", usn_id, appliance_name, e)
                    continue
                points = parse_points_from_json(usn_id, usn_name, appliance_name, measurement, payload, asn_id_raw)
                if not points:
                    logger.warning("No points parsed for %s/%s", usn_id, appliance_name)
                    continue
                try:
                    written = write_points_influx(influx_client, points, time_precision='ms', max_batch=max_batch)
                    logger.info("Wrote %s points for %s (%s) / %s", written, usn_id, usn_name, appliance_name)
                except Exception as e:
                    logger.error("Failed to write to InfluxDB for %s/%s: %s", usn_id, appliance_name, e)
            else:
                logger.error("Unknown storage mode '%s'", storage_mode)
                return


def main():
    ap = argparse.ArgumentParser(description="Login and fetch telemetry data using config JSON.")
    ap.add_argument("--config", required=True, help="Path to configuration JSON file.")
    ap.add_argument("--log-level", default=None, help="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Overrides config.logging.level.")
    ap.add_argument("--log-file", default=None, help="Optional log file path. Overrides config.logging.file.")
    args = ap.parse_args()

    # Setup logging ASAP (CLI has precedence); may be overridden by config if CLI not provided
    setup_logging(level=args.log_level, log_file=args.log_file)

    # Start markers
    run_start_utc = dt.datetime.now(dt.timezone.utc)
    run_start_perf = time.perf_counter()
    logger.info("=== Run started === (config=%s)", args.config)

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        logger.error("Config not found: %s", cfg_path)
        sys.exit(2)

    cfg = json.loads(cfg_path.read_text())

    # Reconfigure logging from config if provided and not overridden by CLI
    log_cfg = cfg.get("logging", {}) if isinstance(cfg.get("logging"), dict) else {}
    level = args.log_level or log_cfg.get("level")
    log_file = args.log_file or log_cfg.get("file")
    setup_logging(level=level, log_file=log_file)
    logger.info("Using log level=%s%s", (level or "INFO").upper(), f", file={log_file}" if log_file else "")

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
        logger.error("Missing required REST config: base_url, auth.token_url, auth.username, auth.password")
        sys.exit(2)

    # period: accept either 'period' (string or dict) or fallback 'periodLast'
    period_cfg = cfg.get("period")
    if period_cfg is None and cfg.get('periodLast') is not None:
        period_cfg = cfg.get('periodLast')
    if period_cfg is None:
        logger.error("Missing 'period' in config")
        sys.exit(2)

    try:
        intervals = compute_intervals(period_cfg)
    except Exception as e:
        logger.error("Invalid period: %s", e)
        sys.exit(2)

    if not intervals:
        logger.error("No intervals to fetch after parsing period")
        sys.exit(2)

    # storage selection
    storage_mode = (cfg.get('storage') or 'file').lower()
    output_cfg = cfg.get("output", {})
    save_json = bool(output_cfg.get("save_json", True))
    out_dir = Path(output_cfg.get("directory", "data"))

    influx_cfg = cfg.get('influxdb') if storage_mode == 'influx' else None

    # Build session early - needed for both auto-discovery and regular fetching
    session = build_session(timeout=timeout, retries_cfg=retries_cfg, headers=headers)

    # Auto-discovery or manual pairs configuration
    auto_discover_cfg = cfg.get("auto_discover", {})
    if isinstance(auto_discover_cfg, bool):
        auto_discover_cfg = {"enabled": auto_discover_cfg}
    
    if auto_discover_cfg.get("enabled", False):
        logger.info("Auto-discovery mode enabled - fetching USNs and appliances from API")
        # Authenticate first for discovery
        try:
            token, token_type = login_get_token(session, token_url, username, password, verify_ssl, form_extras=form_extras)
        except Exception as e:
            logger.error("Authentication failed: %s", e)
            sys.exit(1)
        auth_header_value = f"{token_type} {token}"
        
        use_appliances = auto_discover_cfg.get("use_appliances", True)
        telemetry_filter = auto_discover_cfg.get("telemetry_filter", None)
        
        pairs, usns_dict = auto_discover_pairs(
            session=session,
            base_url=base_url,
            auth_header_value=auth_header_value,
            verify_ssl=verify_ssl,
            use_appliances=use_appliances,
            telemetry_filter=telemetry_filter
        )
        
        if not pairs:
            logger.error("No USN/telemetry pairs discovered from API")
            sys.exit(2)
        
        # Optionally save discovered config
        if auto_discover_cfg.get("save_discovered", False):
            out_cfg_path = out_dir / "discovered_usns.json"
            save_discovered_config(usns_dict, out_cfg_path)
        
        # Extract USN ID -> metadata mapping for tagging
        usn_metadata: Dict[str, Dict[str, Any]] = {
            usn_id: {'name': info['name'], 'asn_id': info.get('asn_id')}
            for usn_id, info in usns_dict.items()
        }
    else:
        # Manual mode - use pairs from config (check both 'usns' and 'usns_manual')
        usns_cfg = cfg.get("usns") or cfg.get("usns_manual") or {}
        pairs = load_pairs(usns_cfg)
        if not pairs:
            logger.error("No USN/telemetry pairs configured under 'usns' or 'usns_manual'")
            sys.exit(2)
        
        # In manual mode, we don't have USN metadata - will use defaults
        usn_metadata = {}
        
        # Authenticate
        try:
            token, token_type = login_get_token(session, token_url, username, password, verify_ssl, form_extras=form_extras)
        except Exception as e:
            logger.error("Authentication failed: %s", e)
            sys.exit(1)
        auth_header_value = f"{token_type} {token}"

    # Log planned work summary
    starts = [s for (s, _e) in intervals]
    ends = [e for (_s, e) in intervals]
    logger.info(
        "Fetch start: pairs=%d, intervals=%d (%s -> %s), storage=%s, save_json=%s",
        len(pairs),
        len(intervals),
        ms_to_iso_z(min(starts)),
        ms_to_iso_z(max(ends)),
        storage_mode,
        save_json,
    )

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
        usn_metadata=usn_metadata,
    )

    # End marker
    elapsed_s = time.perf_counter() - run_start_perf
    # simple HH:MM:SS
    hh = int(elapsed_s // 3600)
    mm = int((elapsed_s % 3600) // 60)
    ss = int(elapsed_s % 60)
    dur = f"{hh:02d}:{mm:02d}:{ss:02d}"
    logger.info("=== Run finished successfully === (duration=%s)", dur)


if __name__ == "__main__":
    main()
