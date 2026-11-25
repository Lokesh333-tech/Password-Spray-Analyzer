"""Core Password-Spray Detection Engine connecting all DAA modules to SQLite."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List

from backend.algorithms.binary_search import binary_search_time_range
from backend.algorithms.graph_bfs import bfs_traverse, build_bipartite_graph
from backend.algorithms.greedy_prioritizer import score_and_prioritize_threats
from backend.algorithms.hash_table import group_events_by_ip
from backend.algorithms.merge_sort import merge_sort_events
from backend.algorithms.sliding_window import detect_password_spray_windows


def run_detection_pipeline(
    conn: sqlite3.Connection,
    dataset_id: int,
    window_minutes: int = 10,
    min_distinct_accounts: int = 8,
) -> Dict[str, Any]:
    """Execute Merge Sort -> Hash Table -> Sliding Window -> Greedy Prioritization -> BFS & persist."""
    rows = conn.execute(
        """
        SELECT id, dataset_id, timestamp, epoch_ts, username, source_ip, status, raw_status,
               user_agent, application, is_duplicate
        FROM authentication_logs
        WHERE dataset_id = ?
        """,
        (dataset_id,),
    ).fetchall()

    events: List[Dict[str, Any]] = [dict(r) for r in rows]
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Explicit Merge Sort chronologically
    sorted_events, merge_metrics = merge_sort_events(events, key_field="epoch_ts")

    # 2. Explicit Hash Table grouping by source IP
    ip_summaries, ip_events_map, hash_metrics = group_events_by_ip(sorted_events)

    # 3. Binary Search probe validation (midpoint 10-min range sample)
    if sorted_events:
        mid_epoch = float(sorted_events[len(sorted_events) // 2]["epoch_ts"])
        _, bsearch_metrics = binary_search_time_range(
            sorted_events,
            start_epoch=mid_epoch - (window_minutes * 30),
            end_epoch=mid_epoch + (window_minutes * 30),
        )
    else:
        _, bsearch_metrics = binary_search_time_range(sorted_events)

    # 4. Sliding Window password spray detection
    candidates, sw_metrics = detect_password_spray_windows(
        ip_events_map,
        window_minutes=window_minutes,
        min_distinct_accounts=min_distinct_accounts,
    )

    # 5. Greedy threat prioritization & explainable scoring
    threats, greedy_metrics = score_and_prioritize_threats(candidates)

    # 6. Bipartite Graph + BFS traversal on highest-risk IP (if any)
    threat_map = {t["source_ip"]: t for t in threats}
    graph = build_bipartite_graph(sorted_events, threat_ips=threat_map)
    if threats:
        start_node = f"ip:{threats[0]['source_ip']}"
    elif ip_summaries:
        start_node = f"ip:{ip_summaries[0]['source_ip']}"
    else:
        start_node = ""
    _, bfs_metrics = bfs_traverse(graph, start_node)

    # Clear prior analysis for this dataset before inserting fresh results
    conn.execute("DELETE FROM targeted_accounts WHERE dataset_id = ?", (dataset_id,))
    conn.execute("DELETE FROM detected_threats WHERE dataset_id = ?", (dataset_id,))
    conn.execute("DELETE FROM algorithm_metrics WHERE dataset_id = ?", (dataset_id,))

    for threat in threats:
        cur = conn.execute(
            """
            INSERT INTO detected_threats (
                dataset_id, source_ip, total_attempts, failed_attempts, successful_attempts,
                distinct_accounts, first_seen, last_seen, window_minutes, window_peak_accounts,
                window_peak_attempts, peak_window_start, peak_window_end,
                success_after_failure_count, risk_score, severity, explanation,
                score_breakdown_json, greedy_rank, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dataset_id,
                threat["source_ip"],
                threat["total_attempts"],
                threat["failed_attempts"],
                threat["successful_attempts"],
                threat["distinct_accounts"],
                threat["first_seen"],
                threat["last_seen"],
                threat["window_minutes"],
                threat["window_peak_accounts"],
                threat["window_peak_attempts"],
                threat["peak_window_start"],
                threat["peak_window_end"],
                threat["success_after_failure_count"],
                threat["risk_score"],
                threat["severity"],
                threat["explanation"],
                json.dumps(threat["score_breakdown"]),
                threat["greedy_rank"],
                now_iso,
            ),
        )
        threat_id = cur.lastrowid

        for acc in threat["targeted_accounts"]:
            conn.execute(
                """
                INSERT INTO targeted_accounts (
                    threat_id, dataset_id, username, source_ip, total_attempts,
                    failed_attempts, successful_attempts, failures_before_success,
                    had_success_after_failure, first_attempt, last_attempt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    threat_id,
                    dataset_id,
                    acc["username"],
                    threat["source_ip"],
                    acc["total_attempts"],
                    acc["failed_attempts"],
                    acc["successful_attempts"],
                    acc["failures_before_success"],
                    1 if acc["had_success_after_failure"] else 0,
                    acc["first_attempt"],
                    acc["last_attempt"],
                ),
            )

    total_events = len(sorted_events)
    failed_events = sum(1 for e in sorted_events if e["status"] == "FAILED")
    success_events = sum(1 for e in sorted_events if e["status"] == "SUCCESS")
    critical_cnt = sum(1 for t in threats if t["severity"] == "Critical")
    high_cnt = sum(1 for t in threats if t["severity"] == "High")
    medium_cnt = sum(1 for t in threats if t["severity"] == "Medium")
    low_cnt = sum(1 for t in threats if t["severity"] == "Low")
    avg_score = round(sum(t["risk_score"] for t in threats) / len(threats), 1) if threats else 0.0

    summary_payload = {
        "unique_ips": len(ip_summaries),
        "unique_usernames": len({e["username"] for e in sorted_events}),
        "top_ip_summaries": ip_summaries[:15],
        "graph_nodes": len(graph.nodes),
        "graph_edges": len(graph.edges),
    }

    conn.execute(
        """
        INSERT INTO analysis_results (
            dataset_id, executed_at, window_minutes, min_distinct_accounts,
            total_events, failed_events, success_events, suspicious_ip_count,
            critical_alert_count, high_alert_count, medium_alert_count, low_alert_count,
            avg_risk_score, summary_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            dataset_id,
            now_iso,
            window_minutes,
            min_distinct_accounts,
            total_events,
            failed_events,
            success_events,
            len(threats),
            critical_cnt,
            high_cnt,
            medium_cnt,
            low_cnt,
            avg_score,
            json.dumps(summary_payload),
        ),
    )

    all_metrics = [merge_metrics, hash_metrics, bsearch_metrics, sw_metrics, bfs_metrics, greedy_metrics]
    for m in all_metrics:
        conn.execute(
            """
            INSERT INTO algorithm_metrics (
                dataset_id, algorithm_name, input_size, execution_time_ms,
                time_complexity, space_complexity, result_summary, measured_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dataset_id,
                m["algorithm"],
                int(m.get("input_size", m.get("vertices_total", 0))),
                float(m.get("execution_time_ms", 0.0)),
                m["time_complexity"],
                m["space_complexity"],
                json.dumps(m),
                now_iso,
            ),
        )

    conn.execute(
        "UPDATE datasets SET status = 'analyzed', summary_json = ? WHERE id = ?",
        (json.dumps(summary_payload), dataset_id),
    )
    conn.commit()

    return {
        "dataset_id": dataset_id,
        "executed_at": now_iso,
        "total_events": total_events,
        "failed_events": failed_events,
        "success_events": success_events,
        "suspicious_ip_count": len(threats),
        "critical_alert_count": critical_cnt,
        "high_alert_count": high_cnt,
        "medium_alert_count": medium_cnt,
        "low_alert_count": low_cnt,
        "avg_risk_score": avg_score,
        "algorithm_metrics": all_metrics,
    }
