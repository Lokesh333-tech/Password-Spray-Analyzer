"""Framework-agnostic REST API handlers backed by SQLite and Python DAA algorithms."""

from __future__ import annotations

import json
import os
import platform
import random
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.algorithms.binary_search import binary_search_time_range
from backend.algorithms.graph_bfs import bfs_traverse, build_bipartite_graph
from backend.algorithms.greedy_prioritizer import score_and_prioritize_threats
from backend.algorithms.hash_table import group_events_by_ip
from backend.algorithms.merge_sort import merge_sort_events
from backend.algorithms.sliding_window import detect_password_spray_windows
from backend.database.db import DB_PATH, get_connection, init_db
from backend.detection.engine import run_detection_pipeline
from backend.sample_data.generate_sample import write_sample_csv
from backend.utils.csv_processor import parse_and_validate_csv, parse_timestamp, sanitize_filename
from backend.utils.pdf_generator import generate_csv_report, generate_pdf_report

SAMPLE_CSV_PATH = Path(__file__).resolve().parent / "sample_data" / "sample_auth_logs.csv"


def _get_settings_row(conn: sqlite3.Connection) -> Dict[str, Any]:
    row = conn.execute("SELECT * FROM application_settings WHERE id = 1").fetchone()
    if not row:
        init_db()
        row = conn.execute("SELECT * FROM application_settings WHERE id = 1").fetchone()
    d = dict(row)
    return {
        "window_minutes": int(d["window_minutes"]),
        "min_distinct_accounts": int(d["min_distinct_accounts"]),
        "success_statuses": json.loads(d["success_statuses_json"]),
        "failure_statuses": json.loads(d["failure_statuses_json"]),
        "max_upload_mb": int(d["max_upload_mb"]),
        "default_theme": d["default_theme"],
        "updated_at": d["updated_at"],
    }


def _resolve_dataset_id(conn: sqlite3.Connection, requested_id: Optional[int] = None) -> Optional[int]:
    if requested_id is not None:
        row = conn.execute("SELECT id FROM datasets WHERE id = ?", (int(requested_id),)).fetchone()
        if row:
            return int(row["id"])
    row = conn.execute("SELECT id FROM datasets ORDER BY id DESC LIMIT 1").fetchone()
    return int(row["id"]) if row else None


def handle_health() -> Tuple[int, Dict[str, Any]]:
    return 200, {
        "status": "ok",
        "service": "Password Spray Analyzer API",
        "python_version": platform.python_version(),
        "database": str(DB_PATH),
    }


def handle_list_datasets(db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            """
            SELECT d.*, ar.suspicious_ip_count, ar.critical_alert_count, ar.executed_at AS last_analyzed_at
            FROM datasets d
            LEFT JOIN analysis_results ar ON ar.id = (
                SELECT id FROM analysis_results WHERE dataset_id = d.id ORDER BY id DESC LIMIT 1
            )
            ORDER BY d.id DESC
            """
        ).fetchall()
        datasets = []
        for r in rows:
            item = dict(r)
            item["summary"] = json.loads(item.pop("summary_json", "{}") or "{}")
            datasets.append(item)
        return 200, {"datasets": datasets}
    finally:
        conn.close()


def handle_delete_dataset(dataset_id: int, db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        existing = conn.execute("SELECT id, name FROM datasets WHERE id = ?", (dataset_id,)).fetchone()
        if not existing:
            return 404, {"error": "Dataset not found."}
        conn.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))
        conn.commit()
        return 200, {"deleted": True, "dataset_id": dataset_id}
    finally:
        conn.close()


def _ingest_csv_bytes(
    conn: sqlite3.Connection,
    raw_bytes: bytes,
    filename: str,
    dataset_name: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    settings = _get_settings_row(conn)
    clean_filename = sanitize_filename(filename)
    parsed = parse_and_validate_csv(
        raw_bytes,
        success_tokens=settings["success_statuses"],
        failure_tokens=settings["failure_statuses"],
        max_size_mb=settings["max_upload_mb"],
    )
    if not parsed["ok"]:
        return 400, {
            "error": parsed["error"],
            "validation_errors": parsed.get("validation_errors", []),
        }

    records = parsed["records"]
    now_iso = datetime.now(timezone.utc).isoformat()
    name = (dataset_name or clean_filename.rsplit(".", 1)[0]).strip()[:120] or "Authentication Dataset"

    cur = conn.execute(
        """
        INSERT INTO datasets (
            name, filename, file_size_bytes, row_count, valid_row_count,
            duplicate_count, invalid_row_count, uploaded_at, status, summary_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'uploaded', '{}')
        """,
        (
            name,
            clean_filename,
            len(raw_bytes),
            parsed["total_rows"],
            parsed["valid_rows"],
            parsed["duplicate_rows"],
            parsed["invalid_rows"],
            now_iso,
        ),
    )
    dataset_id = cur.lastrowid

    conn.executemany(
        """
        INSERT INTO authentication_logs (
            dataset_id, timestamp, epoch_ts, username, source_ip, status,
            raw_status, user_agent, application, is_duplicate
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                dataset_id,
                r["timestamp"],
                r["epoch_ts"],
                r["username"],
                r["source_ip"],
                r["status"],
                r["raw_status"],
                r["user_agent"],
                r["application"],
                r["is_duplicate"],
            )
            for r in records
        ],
    )
    conn.commit()

    analysis_summary = run_detection_pipeline(
        conn,
        int(dataset_id),
        window_minutes=settings["window_minutes"],
        min_distinct_accounts=settings["min_distinct_accounts"],
    )

    return 201, {
        "dataset_id": dataset_id,
        "name": name,
        "filename": clean_filename,
        "total_rows": parsed["total_rows"],
        "valid_rows": parsed["valid_rows"],
        "duplicate_rows": parsed["duplicate_rows"],
        "invalid_rows": parsed["invalid_rows"],
        "validation_errors": parsed["validation_errors"],
        "parser_engine": parsed.get("parser_engine", "python-csv"),
        "analysis": analysis_summary,
    }


def handle_upload(
    raw_bytes: bytes,
    filename: str,
    dataset_name: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        return _ingest_csv_bytes(conn, raw_bytes, filename, dataset_name)
    except sqlite3.Error as exc:
        conn.rollback()
        return 500, {"error": f"Database error during upload: {str(exc)}"}
    finally:
        conn.close()


def handle_load_sample(db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    if not SAMPLE_CSV_PATH.exists():
        write_sample_csv(SAMPLE_CSV_PATH)
    raw_bytes = SAMPLE_CSV_PATH.read_bytes()
    conn = get_connection(db_path)
    try:
        stamp = datetime.now(timezone.utc).strftime("%H:%M")
        return _ingest_csv_bytes(
            conn,
            raw_bytes,
            "sample_auth_logs.csv",
            f"Enterprise Auth Sample ({stamp} UTC)",
        )
    finally:
        conn.close()


def handle_analyze(body: Dict[str, Any], db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        settings = _get_settings_row(conn)
        dataset_id = _resolve_dataset_id(conn, body.get("dataset_id"))
        if dataset_id is None:
            return 404, {"error": "No dataset available to analyze. Upload a CSV log file first."}

        window_minutes = int(body.get("window_minutes", settings["window_minutes"]))
        min_distinct = int(body.get("min_distinct_accounts", settings["min_distinct_accounts"]))
        if window_minutes < 1 or window_minutes > 1440:
            return 400, {"error": "window_minutes must be between 1 and 1440."}
        if min_distinct < 2 or min_distinct > 500:
            return 400, {"error": "min_distinct_accounts must be between 2 and 500."}

        result = run_detection_pipeline(
            conn,
            dataset_id,
            window_minutes=window_minutes,
            min_distinct_accounts=min_distinct,
        )
        return 200, result
    except (ValueError, TypeError) as exc:
        return 400, {"error": f"Invalid analysis parameters: {str(exc)}"}
    finally:
        conn.close()


def handle_get_logs(params: Dict[str, str], db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        req_id = int(params["dataset_id"]) if params.get("dataset_id") else None
        dataset_id = _resolve_dataset_id(conn, req_id)
        if dataset_id is None:
            return 200, {
                "dataset": None,
                "logs": [],
                "total": 0,
                "page": 1,
                "page_size": 50,
                "before_sort_preview": [],
                "after_sort_preview": [],
                "ip_groups": [],
                "merge_sort_metrics": None,
                "hash_table_metrics": None,
                "binary_search_metrics": None,
            }

        dataset_row = dict(conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone())
        raw_rows = conn.execute(
            """
            SELECT id, timestamp, epoch_ts, username, source_ip, status, raw_status,
                   user_agent, application, is_duplicate
            FROM authentication_logs
            WHERE dataset_id = ?
            ORDER BY id ASC
            """,
            (dataset_id,),
        ).fetchall()
        raw_events = [dict(r) for r in raw_rows]

        # Explicit Merge Sort on all events in dataset
        sorted_events, merge_metrics = merge_sort_events(raw_events, key_field="epoch_ts")

        # Explicit Hash Table grouping by IP
        ip_groups, _, hash_metrics = group_events_by_ip(sorted_events)

        # Explicit Binary Search time-range filtering
        start_ts = params.get("start", "").strip()
        end_ts = params.get("end", "").strip()
        start_epoch = parse_timestamp(start_ts)[1] if start_ts else None
        end_epoch = parse_timestamp(end_ts)[1] if end_ts else None

        range_events, bsearch_metrics = binary_search_time_range(
            sorted_events,
            start_epoch=start_epoch,
            end_epoch=end_epoch,
        )

        # Optional text/status/ip filters on the Binary Search slice
        search = params.get("search", "").strip().lower()
        status_filter = params.get("status", "").strip().upper()
        ip_filter = params.get("ip", "").strip()

        filtered = []
        for ev in range_events:
            if status_filter and status_filter != "ALL" and ev["status"] != status_filter:
                continue
            if ip_filter and ev["source_ip"] != ip_filter:
                continue
            if search:
                haystack = f"{ev['username']} {ev['source_ip']} {ev['application']} {ev['status']}".lower()
                if search not in haystack:
                    continue
            filtered.append(ev)

        page = max(1, int(params.get("page", "1") or 1))
        page_size = min(200, max(10, int(params.get("page_size", "50") or 50)))
        start_idx = (page - 1) * page_size
        paged_logs = filtered[start_idx : start_idx + page_size]

        return 200, {
            "dataset": dataset_row,
            "logs": paged_logs,
            "total": len(filtered),
            "page": page,
            "page_size": page_size,
            "min_timestamp": sorted_events[0]["timestamp"] if sorted_events else None,
            "max_timestamp": sorted_events[-1]["timestamp"] if sorted_events else None,
            "before_sort_preview": raw_events[:8],
            "after_sort_preview": sorted_events[:8],
            "ip_groups": ip_groups,
            "merge_sort_metrics": merge_metrics,
            "hash_table_metrics": hash_metrics,
            "binary_search_metrics": bsearch_metrics,
        }
    finally:
        conn.close()


def handle_dashboard(params: Dict[str, str], db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        req_id = int(params["dataset_id"]) if params.get("dataset_id") else None
        dataset_id = _resolve_dataset_id(conn, req_id)
        if dataset_id is None:
            return 200, {
                "has_data": False,
                "dataset": None,
                "kpis": {
                    "total_events": 0,
                    "failed_attempts": 0,
                    "successful_attempts": 0,
                    "suspicious_ips": 0,
                    "critical_alerts": 0,
                },
                "charts": {
                    "timeline": [],
                    "status_distribution": [],
                    "severity_distribution": [],
                    "top_suspicious_ips": [],
                    "top_targeted_accounts": [],
                    "hourly_activity": [],
                },
                "recent_alerts": [],
                "datasets": [],
                "algorithm_metrics": [],
            }

        dataset_row = dict(conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone())
        analysis_row = conn.execute(
            "SELECT * FROM analysis_results WHERE dataset_id = ? ORDER BY id DESC LIMIT 1",
            (dataset_id,),
        ).fetchone()
        analysis = dict(analysis_row) if analysis_row else {}

        logs = [
            dict(r)
            for r in conn.execute(
                "SELECT timestamp, epoch_ts, username, source_ip, status FROM authentication_logs WHERE dataset_id = ? ORDER BY epoch_ts ASC",
                (dataset_id,),
            ).fetchall()
        ]
        threats = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM detected_threats WHERE dataset_id = ? ORDER BY greedy_rank ASC, risk_score DESC",
                (dataset_id,),
            ).fetchall()
        ]
        targeted_rows = [
            dict(r)
            for r in conn.execute(
                """
                SELECT username,
                       SUM(failed_attempts) AS failed_attempts,
                       SUM(successful_attempts) AS successful_attempts,
                       COUNT(DISTINCT source_ip) AS attacking_ips,
                       MAX(had_success_after_failure) AS compromised
                FROM targeted_accounts
                WHERE dataset_id = ?
                GROUP BY username
                ORDER BY failed_attempts DESC, attacking_ips DESC
                LIMIT 10
                """,
                (dataset_id,),
            ).fetchall()
        ]

        # Build timeline buckets (by 30-min or hour depending on span)
        timeline_buckets: Dict[str, Dict[str, Any]] = {}
        hourly_buckets: Dict[int, Dict[str, int]] = {
            h: {"hour": h, "label": f"{h:02d}:00", "success": 0, "failed": 0} for h in range(24)
        }
        total_events = len(logs)
        failed_count = 0
        success_count = 0

        span_sec = (logs[-1]["epoch_ts"] - logs[0]["epoch_ts"]) if len(logs) > 1 else 0
        bucket_format = "%m-%d %H:00" if span_sec > 8 * 3600 else "%H:%M"

        for ev in logs:
            dt = datetime.fromtimestamp(float(ev["epoch_ts"]), tz=timezone.utc)
            if ev["status"] == "SUCCESS":
                success_count += 1
                hourly_buckets[dt.hour]["success"] += 1
            else:
                failed_count += 1
                hourly_buckets[dt.hour]["failed"] += 1

            if span_sec > 8 * 3600:
                b_key = dt.strftime(bucket_format)
            else:
                minute_slot = (dt.minute // 10) * 10
                b_key = f"{dt.hour:02d}:{minute_slot:02d}"

            if b_key not in timeline_buckets:
                timeline_buckets[b_key] = {"time": b_key, "success": 0, "failed": 0, "total": 0}
            timeline_buckets[b_key]["total"] += 1
            if ev["status"] == "SUCCESS":
                timeline_buckets[b_key]["success"] += 1
            else:
                timeline_buckets[b_key]["failed"] += 1

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for t in threats:
            sev = t.get("severity", "Low")
            if sev in sev_counts:
                sev_counts[sev] += 1

        algo_rows = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM algorithm_metrics WHERE dataset_id = ? ORDER BY id ASC",
                (dataset_id,),
            ).fetchall()
        ]

        _, ds_list_res = handle_list_datasets(db_path)

        return 200, {
            "has_data": True,
            "dataset": dataset_row,
            "analysis": analysis,
            "kpis": {
                "total_events": total_events,
                "failed_attempts": failed_count,
                "successful_attempts": success_count,
                "suspicious_ips": len(threats),
                "critical_alerts": sev_counts["Critical"],
            },
            "charts": {
                "timeline": list(timeline_buckets.values()),
                "status_distribution": [
                    {"name": "Successful", "value": success_count},
                    {"name": "Failed", "value": failed_count},
                ],
                "severity_distribution": [
                    {"severity": k, "count": v} for k, v in sev_counts.items()
                ],
                "top_suspicious_ips": [
                    {
                        "ip": t["source_ip"],
                        "risk_score": t["risk_score"],
                        "distinct_accounts": t["distinct_accounts"],
                        "failed_attempts": t["failed_attempts"],
                        "severity": t["severity"],
                    }
                    for t in threats[:8]
                ],
                "top_targeted_accounts": targeted_rows,
                "hourly_activity": [hourly_buckets[h] for h in range(24)],
            },
            "recent_alerts": threats[:6],
            "datasets": ds_list_res["datasets"][:6],
            "algorithm_metrics": algo_rows,
        }
    finally:
        conn.close()


def handle_get_threats(params: Dict[str, str], db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        req_id = int(params["dataset_id"]) if params.get("dataset_id") else None
        dataset_id = _resolve_dataset_id(conn, req_id)
        if dataset_id is None:
            return 200, {"threats": [], "targeted_accounts": [], "dataset_id": None}

        severity = params.get("severity", "").strip()
        ip_q = params.get("ip", "").strip().lower()
        account_q = params.get("account", "").strip().lower()
        search_q = params.get("search", "").strip().lower()
        start_q = params.get("start", "").strip()
        end_q = params.get("end", "").strip()

        rows = conn.execute(
            """
            SELECT * FROM detected_threats
            WHERE dataset_id = ?
            ORDER BY greedy_rank ASC, risk_score DESC
            """,
            (dataset_id,),
        ).fetchall()

        threats: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["score_breakdown"] = json.loads(item.pop("score_breakdown_json", "[]") or "[]")
            acc_rows = conn.execute(
                "SELECT * FROM targeted_accounts WHERE threat_id = ? ORDER BY had_success_after_failure DESC, failed_attempts DESC",
                (item["id"],),
            ).fetchall()
            item["targeted_accounts"] = [dict(a) for a in acc_rows]

            if severity and severity.lower() != "all" and item["severity"].lower() != severity.lower():
                continue
            if ip_q and ip_q not in item["source_ip"].lower():
                continue
            if account_q and not any(account_q in a["username"].lower() for a in item["targeted_accounts"]):
                continue
            if search_q:
                in_ip = search_q in item["source_ip"].lower()
                in_exp = search_q in item["explanation"].lower()
                in_acc = any(search_q in a["username"].lower() for a in item["targeted_accounts"])
                if not (in_ip or in_exp or in_acc):
                    continue
            if start_q and item["last_seen"] < start_q:
                continue
            if end_q and item["first_seen"] > end_q:
                continue
            threats.append(item)

        all_targeted = [
            dict(r)
            for r in conn.execute(
                """
                SELECT username,
                       COUNT(DISTINCT source_ip) AS attacking_ips,
                       SUM(total_attempts) AS total_attempts,
                       SUM(failed_attempts) AS failed_attempts,
                       SUM(successful_attempts) AS successful_attempts,
                       MAX(had_success_after_failure) AS had_success_after_failure,
                       MAX(failures_before_success) AS max_failures_before_success,
                       MAX(last_attempt) AS last_attempt
                FROM targeted_accounts
                WHERE dataset_id = ?
                GROUP BY username
                ORDER BY had_success_after_failure DESC, failed_attempts DESC
                """,
                (dataset_id,),
            ).fetchall()
        ]

        saf_events = [
            dict(r)
            for r in conn.execute(
                """
                SELECT * FROM targeted_accounts
                WHERE dataset_id = ? AND had_success_after_failure = 1
                ORDER BY failures_before_success DESC
                """,
                (dataset_id,),
            ).fetchall()
        ]

        return 200, {
            "dataset_id": dataset_id,
            "threats": threats,
            "targeted_accounts": all_targeted,
            "success_after_failure": saf_events,
        }
    finally:
        conn.close()


def handle_get_threat_detail(threat_id: int, db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM detected_threats WHERE id = ?", (threat_id,)).fetchone()
        if not row:
            return 404, {"error": "Threat alert not found."}
        threat = dict(row)
        threat["score_breakdown"] = json.loads(threat.pop("score_breakdown_json", "[]") or "[]")
        accounts = [
            dict(a)
            for a in conn.execute(
                "SELECT * FROM targeted_accounts WHERE threat_id = ? ORDER BY had_success_after_failure DESC, failed_attempts DESC",
                (threat_id,),
            ).fetchall()
        ]
        events = [
            dict(e)
            for e in conn.execute(
                """
                SELECT timestamp, username, source_ip, status, application, user_agent
                FROM authentication_logs
                WHERE dataset_id = ? AND source_ip = ?
                ORDER BY epoch_ts ASC
                LIMIT 200
                """,
                (threat["dataset_id"], threat["source_ip"]),
            ).fetchall()
        ]
        threat["targeted_accounts"] = accounts
        threat["events"] = events
        return 200, {"threat": threat}
    finally:
        conn.close()


def handle_network(params: Dict[str, str], db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        req_id = int(params["dataset_id"]) if params.get("dataset_id") else None
        dataset_id = _resolve_dataset_id(conn, req_id)
        if dataset_id is None:
            return 200, {"nodes": [], "edges": [], "bfs": None}

        logs = [
            dict(r)
            for r in conn.execute(
                "SELECT username, source_ip, status FROM authentication_logs WHERE dataset_id = ? ORDER BY epoch_ts ASC",
                (dataset_id,),
            ).fetchall()
        ]
        threat_rows = conn.execute(
            "SELECT source_ip, risk_score, severity FROM detected_threats WHERE dataset_id = ?",
            (dataset_id,),
        ).fetchall()
        threat_map = {r["source_ip"]: dict(r) for r in threat_rows}

        graph = build_bipartite_graph(logs, threat_ips=threat_map)
        start_node = params.get("start_node", "").strip()
        if not start_node or start_node not in graph.nodes:
            if threat_rows:
                start_node = f"ip:{threat_rows[0]['source_ip']}"
            elif graph.nodes:
                start_node = next(iter(graph.nodes.keys()))

        bfs_result, bfs_metrics = bfs_traverse(graph, start_node) if start_node else (None, None)

        return 200, {
            "dataset_id": dataset_id,
            "nodes": list(graph.nodes.values()),
            "edges": graph.edges,
            "bfs": bfs_result,
            "bfs_metrics": bfs_metrics,
        }
    finally:
        conn.close()


def handle_algorithms(params: Dict[str, str], db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        req_id = int(params["dataset_id"]) if params.get("dataset_id") else None
        dataset_id = _resolve_dataset_id(conn, req_id)
        metrics: List[Dict[str, Any]] = []
        if dataset_id is not None:
            rows = conn.execute(
                "SELECT * FROM algorithm_metrics WHERE dataset_id = ? ORDER BY id ASC",
                (dataset_id,),
            ).fetchall()
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item.pop("result_summary", "{}") or "{}")
                metrics.append(item)

        return 200, {
            "dataset_id": dataset_id,
            "environment": {
                "python_version": platform.python_version(),
                "platform": platform.system(),
                "architecture": platform.machine(),
                "timer": "time.perf_counter_ns() (monotonic high-resolution nanosecond counter)",
            },
            "metrics": metrics,
        }
    finally:
        conn.close()


def _generate_synthetic_events(count: int, seed: int = 101) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    base_epoch = 1795500000.0
    ips = [f"198.51.100.{i}" for i in range(1, 26)] + [f"203.0.113.{i}" for i in range(1, 26)]
    users = [f"user_{i:03d}" for i in range(1, 41)]
    events: List[Dict[str, Any]] = []
    for idx in range(count):
        ep = base_epoch + rng.uniform(0, 7200)
        events.append({
            "id": idx + 1,
            "timestamp": datetime.fromtimestamp(ep, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "epoch_ts": ep,
            "username": rng.choice(users),
            "source_ip": rng.choice(ips),
            "status": "FAILED" if rng.random() < 0.78 else "SUCCESS",
        })
    return events


def handle_algorithm_benchmark(body: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Run live Python DAA benchmarks across 100, 1000, 5000, and 10000 synthetic records."""
    sizes = body.get("sizes") or [100, 1000, 5000, 10000]
    safe_sizes = [min(10000, max(10, int(s))) for s in sizes[:6]]

    results = []
    for n in safe_sizes:
        events = _generate_synthetic_events(n, seed=n + 7)
        sorted_events, m_sort = merge_sort_events(events)
        _, ip_map, m_hash = group_events_by_ip(sorted_events)

        mid_ep = sorted_events[len(sorted_events) // 2]["epoch_ts"]
        _, m_bsearch = binary_search_time_range(sorted_events, mid_ep - 300, mid_ep + 300)
        candidates, m_sw = detect_password_spray_windows(ip_map, window_minutes=10, min_distinct_accounts=8)
        prioritized, _ = score_and_prioritize_threats(candidates)
        threat_map = {t["source_ip"]: t for t in prioritized}
        graph = build_bipartite_graph(sorted_events, threat_ips=threat_map, max_nodes=250)
        start_node = next(iter(graph.nodes.keys()), "")
        _, m_bfs = bfs_traverse(graph, start_node)

        results.append({
            "size": n,
            "merge_sort_ms": m_sort["execution_time_ms"],
            "hash_table_ms": m_hash["execution_time_ms"],
            "binary_search_ms": m_bsearch["execution_time_ms"],
            "sliding_window_ms": m_sw["execution_time_ms"],
            "bfs_ms": m_bfs["execution_time_ms"],
            "merge_comparisons": m_sort["comparisons"],
            "hash_collisions": m_hash["collisions"],
            "bsearch_comparisons": m_bsearch["comparisons"],
            "windows_evaluated": m_sw["windows_evaluated"],
            "bfs_visited": m_bfs["vertices_visited"],
        })

    return 200, {
        "environment": {
            "python_version": platform.python_version(),
            "platform": platform.system(),
            "architecture": platform.machine(),
            "timer": "time.perf_counter_ns()",
        },
        "benchmarks": results,
    }


def handle_reports(params: Dict[str, str], db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        severity_filter = params.get("severity", "").strip()
        start_date = params.get("start", "").strip()
        end_date = params.get("end", "").strip()

        rows = conn.execute(
            """
            SELECT ar.*, d.name AS dataset_name, d.filename, d.duplicate_count
            FROM analysis_results ar
            JOIN datasets d ON d.id = ar.dataset_id
            ORDER BY ar.id DESC
            """
        ).fetchall()

        reports = []
        for r in rows:
            item = dict(r)
            item["summary"] = json.loads(item.pop("summary_json", "{}") or "{}")
            if start_date and item["executed_at"] < start_date:
                continue
            if end_date and item["executed_at"] > end_date:
                continue
            if severity_filter and severity_filter.lower() != "all":
                key = f"{severity_filter.lower()}_alert_count"
                if item.get(key, 0) <= 0:
                    continue
            reports.append(item)

        return 200, {"reports": reports}
    finally:
        conn.close()


def handle_export_report(
    body: Dict[str, Any],
    db_path: Optional[str] = None,
) -> Tuple[int, bytes, str, str]:
    """Generate downloadable PDF or CSV report for a dataset."""
    conn = get_connection(db_path)
    try:
        dataset_id = _resolve_dataset_id(conn, body.get("dataset_id"))
        if dataset_id is None:
            return 404, json.dumps({"error": "No dataset found to export."}).encode("utf-8"), "application/json", "error.json"

        fmt = str(body.get("format", "pdf")).lower().strip()
        severity_filter = str(body.get("severity", "")).strip()

        dataset = dict(conn.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,)).fetchone())
        analysis_row = conn.execute(
            "SELECT * FROM analysis_results WHERE dataset_id = ? ORDER BY id DESC LIMIT 1",
            (dataset_id,),
        ).fetchone()
        summary = dict(analysis_row) if analysis_row else {
            "total_events": dataset["valid_row_count"],
            "failed_events": 0,
            "success_events": 0,
            "suspicious_ip_count": 0,
            "critical_alert_count": 0,
            "high_alert_count": 0,
            "medium_alert_count": 0,
            "window_minutes": 10,
            "min_distinct_accounts": 8,
        }

        threats = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM detected_threats WHERE dataset_id = ? ORDER BY greedy_rank ASC, risk_score DESC",
                (dataset_id,),
            ).fetchall()
        ]
        if severity_filter and severity_filter.lower() != "all":
            threats = [t for t in threats if t["severity"].lower() == severity_filter.lower()]

        targeted = [
            dict(r)
            for r in conn.execute(
                """
                SELECT * FROM targeted_accounts
                WHERE dataset_id = ?
                ORDER BY had_success_after_failure DESC, failed_attempts DESC
                """,
                (dataset_id,),
            ).fetchall()
        ]
        algos = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM algorithm_metrics WHERE dataset_id = ? ORDER BY id ASC",
                (dataset_id,),
            ).fetchall()
        ]

        report_payload = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "dataset": dataset,
            "summary": summary,
            "threats": threats,
            "targeted_accounts": targeted,
            "algorithm_metrics": algos,
        }

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if fmt == "csv":
            content = generate_csv_report(report_payload)
            return 200, content, "text/csv; charset=utf-8", f"psa_security_report_{stamp}.csv"

        content = generate_pdf_report(report_payload)
        return 200, content, "application/pdf", f"psa_security_report_{stamp}.pdf"
    finally:
        conn.close()


def handle_get_settings(db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        return 200, {"settings": _get_settings_row(conn)}
    finally:
        conn.close()


def handle_update_settings(body: Dict[str, Any], db_path: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    conn = get_connection(db_path)
    try:
        current = _get_settings_row(conn)
        window_minutes = int(body.get("window_minutes", current["window_minutes"]))
        min_distinct = int(body.get("min_distinct_accounts", current["min_distinct_accounts"]))
        max_upload_mb = int(body.get("max_upload_mb", current["max_upload_mb"]))
        default_theme = str(body.get("default_theme", current["default_theme"])).lower()

        if window_minutes < 1 or window_minutes > 1440:
            return 400, {"error": "window_minutes must be between 1 and 1440."}
        if min_distinct < 2 or min_distinct > 500:
            return 400, {"error": "min_distinct_accounts must be between 2 and 500."}
        if max_upload_mb < 1 or max_upload_mb > 100:
            return 400, {"error": "max_upload_mb must be between 1 and 100."}
        if default_theme not in ("light", "dark", "system"):
            return 400, {"error": "default_theme must be light, dark, or system."}

        success_statuses = body.get("success_statuses", current["success_statuses"])
        failure_statuses = body.get("failure_statuses", current["failure_statuses"])
        if isinstance(success_statuses, str):
            success_statuses = [s.strip().upper() for s in success_statuses.split(",") if s.strip()]
        if isinstance(failure_statuses, str):
            failure_statuses = [s.strip().upper() for s in failure_statuses.split(",") if s.strip()]

        if not success_statuses or not failure_statuses:
            return 400, {"error": "Both success_statuses and failure_statuses must contain at least one token."}

        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            UPDATE application_settings
            SET window_minutes = ?,
                min_distinct_accounts = ?,
                success_statuses_json = ?,
                failure_statuses_json = ?,
                max_upload_mb = ?,
                default_theme = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (
                window_minutes,
                min_distinct,
                json.dumps(success_statuses),
                json.dumps(failure_statuses),
                max_upload_mb,
                default_theme,
                now_iso,
            ),
        )
        conn.commit()
        return 200, {"settings": _get_settings_row(conn)}
    except (ValueError, TypeError) as exc:
        return 400, {"error": f"Invalid settings payload: {str(exc)}"}
    finally:
        conn.close()
