"""Safe CSV parsing, validation, and preprocessing for authentication logs."""

from __future__ import annotations

import csv
import io
import ipaddress
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

try:
    import pandas as pd  # type: ignore
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

REQUIRED_COLUMNS = ("timestamp", "username", "source_ip", "status")
OPTIONAL_COLUMNS = ("user_agent", "application")

TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@+\-]{1,128}$")


def sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename or "upload.csv")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._")
    if not cleaned:
        cleaned = "upload.csv"
    if not cleaned.lower().endswith(".csv"):
        cleaned += ".csv"
    return cleaned[:120]


def sanitize_csv_cell(value: Any) -> str:
    """Neutralize spreadsheet formula injection characters (=, +, -, @, tab, CR)."""
    text = str(value if value is not None else "")
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def parse_timestamp(raw_ts: str) -> Tuple[Optional[str], Optional[float]]:
    ts = (raw_ts or "").strip()
    if not ts:
        return None, None

    # Handle numeric epoch seconds or milliseconds
    if re.fullmatch(r"\d{10}(\.\d+)?", ts):
        epoch = float(ts)
        iso = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return iso, epoch

    # Try Python's ISO parser first
    try:
        iso_candidate = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), dt.timestamp()
    except ValueError:
        pass

    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ"), dt.timestamp()
        except ValueError:
            continue

    return None, None


def validate_ip(raw_ip: str) -> Optional[str]:
    ip_str = (raw_ip or "").strip()
    if not ip_str:
        return None
    try:
        parsed = ipaddress.ip_address(ip_str)
        return str(parsed)
    except ValueError:
        return None


def validate_username(raw_user: str) -> Optional[str]:
    user = (raw_user or "").strip()
    if not user or not USERNAME_PATTERN.match(user):
        return None
    return user


def normalize_status(
    raw_status: str,
    success_tokens: Sequence[str],
    failure_tokens: Sequence[str],
) -> Optional[str]:
    token = (raw_status or "").strip().upper()
    if not token:
        return None
    success_set = {s.strip().upper() for s in success_tokens if s.strip()}
    failure_set = {f.strip().upper() for f in failure_tokens if f.strip()}
    if token in success_set:
        return "SUCCESS"
    if token in failure_set:
        return "FAILED"
    return None


def _read_rows(csv_text: str) -> Tuple[List[str], List[Dict[str, str]]]:
    if HAS_PANDAS:
        try:
            df = pd.read_csv(io.StringIO(csv_text), dtype=str, keep_default_na=False)
            headers = [str(c).strip().lower() for c in df.columns]
            df.columns = headers
            rows = df.to_dict(orient="records")
            return headers, [{str(k): str(v) for k, v in r.items()} for r in rows]
        except Exception:
            pass

    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        return [], []
    headers = [str(h).strip().lower() for h in reader.fieldnames if h is not None]
    rows: List[Dict[str, str]] = []
    for raw_row in reader:
        normalized_row = {
            str(k).strip().lower(): (str(v) if v is not None else "")
            for k, v in raw_row.items()
            if k is not None
        }
        rows.append(normalized_row)
    return headers, rows


def parse_and_validate_csv(
    raw_bytes: bytes,
    success_tokens: Sequence[str] = ("SUCCESS", "OK", "ALLOWED", "AUTHENTICATED", "PASS", "200"),
    failure_tokens: Sequence[str] = ("FAILED", "FAILURE", "DENIED", "INVALID", "REJECTED", "ERROR", "401", "403"),
    max_size_mb: int = 25,
) -> Dict[str, Any]:
    """Validate CSV structure, fields, duplicates, and return cleaned records + validation report."""
    size_bytes = len(raw_bytes)
    if size_bytes == 0:
        return {
            "ok": False,
            "error": "Uploaded CSV file is empty.",
            "records": [],
            "validation_errors": [{"row": 0, "field": "file", "message": "Empty file"}],
        }

    if size_bytes > max_size_mb * 1024 * 1024:
        return {
            "ok": False,
            "error": f"File exceeds maximum allowed size of {max_size_mb} MB.",
            "records": [],
            "validation_errors": [{"row": 0, "field": "file", "message": f"Exceeds {max_size_mb} MB"}],
        }

    try:
        csv_text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            csv_text = raw_bytes.decode("latin-1")
        except UnicodeDecodeError:
            return {
                "ok": False,
                "error": "File encoding is not valid UTF-8 or Latin-1 text.",
                "records": [],
                "validation_errors": [{"row": 0, "field": "encoding", "message": "Invalid text encoding"}],
            }

    headers, raw_rows = _read_rows(csv_text)
    if not headers:
        return {
            "ok": False,
            "error": "CSV file has no header row.",
            "records": [],
            "validation_errors": [{"row": 1, "field": "header", "message": "Missing CSV header"}],
        }

    missing_cols = [col for col in REQUIRED_COLUMNS if col not in headers]
    if missing_cols:
        return {
            "ok": False,
            "error": f"Missing required CSV column(s): {', '.join(missing_cols)}",
            "records": [],
            "validation_errors": [
                {"row": 1, "field": col, "message": f"Missing required column '{col}'"}
                for col in missing_cols
            ],
        }

    if not raw_rows:
        return {
            "ok": False,
            "error": "CSV file contains headers but zero authentication records.",
            "records": [],
            "validation_errors": [{"row": 1, "field": "rows", "message": "No data rows found"}],
        }

    valid_records: List[Dict[str, Any]] = []
    validation_errors: List[Dict[str, Any]] = []
    seen_fingerprints: Set[Tuple[str, str, str, str]] = set()
    duplicate_count = 0

    for idx, row in enumerate(raw_rows, start=2):
        raw_ts = row.get("timestamp", "")
        raw_user = row.get("username", "")
        raw_ip = row.get("source_ip", "")
        raw_status = row.get("status", "")
        user_agent = (row.get("user_agent", "") or "").strip()[:200]
        application = (row.get("application", "") or "").strip()[:100]

        iso_ts, epoch_ts = parse_timestamp(raw_ts)
        if iso_ts is None or epoch_ts is None:
            validation_errors.append({
                "row": idx,
                "field": "timestamp",
                "value": raw_ts[:64],
                "message": "Invalid or missing timestamp format",
            })
            continue

        username = validate_username(raw_user)
        if username is None:
            validation_errors.append({
                "row": idx,
                "field": "username",
                "value": raw_user[:64],
                "message": "Invalid or missing username",
            })
            continue

        source_ip = validate_ip(raw_ip)
        if source_ip is None:
            validation_errors.append({
                "row": idx,
                "field": "source_ip",
                "value": raw_ip[:64],
                "message": "Invalid IPv4/IPv6 address",
            })
            continue

        norm_status = normalize_status(raw_status, success_tokens, failure_tokens)
        if norm_status is None:
            validation_errors.append({
                "row": idx,
                "field": "status",
                "value": raw_status[:32],
                "message": "Unrecognized authentication status",
            })
            continue

        fingerprint = (iso_ts, username, source_ip, norm_status)
        is_duplicate = 1 if fingerprint in seen_fingerprints else 0
        if is_duplicate:
            duplicate_count += 1
        else:
            seen_fingerprints.add(fingerprint)

        valid_records.append({
            "timestamp": iso_ts,
            "epoch_ts": epoch_ts,
            "username": username,
            "source_ip": source_ip,
            "status": norm_status,
            "raw_status": raw_status.strip()[:32],
            "user_agent": user_agent,
            "application": application,
            "is_duplicate": is_duplicate,
        })

    if not valid_records:
        return {
            "ok": False,
            "error": "No valid authentication records remained after validation.",
            "records": [],
            "total_rows": len(raw_rows),
            "valid_rows": 0,
            "duplicate_rows": 0,
            "invalid_rows": len(validation_errors),
            "validation_errors": validation_errors[:100],
        }

    return {
        "ok": True,
        "error": None,
        "records": valid_records,
        "total_rows": len(raw_rows),
        "valid_rows": len(valid_records),
        "duplicate_rows": duplicate_count,
        "invalid_rows": len(validation_errors),
        "validation_errors": validation_errors[:100],
        "parser_engine": "pandas" if HAS_PANDAS else "python-csv",
    }
