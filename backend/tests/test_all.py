"""Automated test suite for Password Spray Analyzer DAA algorithms, CSV validation, and APIs."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.algorithms.binary_search import binary_search_time_range
from backend.algorithms.graph_bfs import bfs_traverse, build_bipartite_graph
from backend.algorithms.greedy_prioritizer import score_and_prioritize_threats
from backend.algorithms.hash_table import CustomHashTable, group_events_by_ip
from backend.algorithms.merge_sort import merge_sort_events
from backend.algorithms.sliding_window import detect_password_spray_windows
from backend.api_handlers import (
    handle_analyze,
    handle_dashboard,
    handle_export_report,
    handle_get_logs,
    handle_get_settings,
    handle_get_threat_detail,
    handle_get_threats,
    handle_network,
    handle_reports,
    handle_update_settings,
    handle_upload,
)
from backend.database.db import init_db
from backend.utils.csv_processor import parse_and_validate_csv


class TestDAAAlgorithms(unittest.TestCase):
    def test_merge_sort_correctness_and_stability(self) -> None:
        events = [
            {"id": 1, "epoch_ts": 300.0, "username": "c"},
            {"id": 2, "epoch_ts": 100.0, "username": "a1"},
            {"id": 3, "epoch_ts": 200.0, "username": "b"},
            {"id": 4, "epoch_ts": 100.0, "username": "a2"},
        ]
        sorted_ev, metrics = merge_sort_events(events)
        self.assertEqual([e["id"] for e in sorted_ev], [2, 4, 3, 1])
        self.assertEqual(metrics["time_complexity"], "O(n log n)")
        self.assertEqual(metrics["space_complexity"], "O(n)")

    def test_hash_table_grouping_and_resizing(self) -> None:
        ht = CustomHashTable(initial_capacity=16)
        for i in range(40):
            ht.put(f"198.51.100.{i}", i)
        self.assertEqual(ht.size, 40)
        self.assertGreater(ht.resizes, 0)
        self.assertEqual(ht.get("198.51.100.15"), 15)

        events = [
            {"source_ip": "198.51.100.1", "username": "u1", "status": "FAILED", "epoch_ts": 10.0, "timestamp": "t1"},
            {"source_ip": "198.51.100.1", "username": "u2", "status": "SUCCESS", "epoch_ts": 20.0, "timestamp": "t2"},
            {"source_ip": "198.51.100.2", "username": "u1", "status": "FAILED", "epoch_ts": 30.0, "timestamp": "t3"},
        ]
        summaries, ip_map, metrics = group_events_by_ip(events)
        self.assertEqual(metrics["unique_ips"], 2)
        self.assertEqual(len(ip_map["198.51.100.1"]), 2)
        top = next(s for s in summaries if s["source_ip"] == "198.51.100.1")
        self.assertEqual(top["distinct_usernames"], 2)
        self.assertEqual(top["failed_attempts"], 1)
        self.assertEqual(top["successful_attempts"], 1)

    def test_binary_search_range_retrieval(self) -> None:
        sorted_events = [{"epoch_ts": float(t * 10), "id": t} for t in range(1, 21)]
        matched, metrics = binary_search_time_range(sorted_events, start_epoch=50.0, end_epoch=120.0)
        self.assertEqual([m["id"] for m in matched], [5, 6, 7, 8, 9, 10, 11, 12])
        self.assertGreater(metrics["comparisons"], 0)

        empty_match, _ = binary_search_time_range(sorted_events, start_epoch=500.0, end_epoch=600.0)
        self.assertEqual(empty_match, [])

    def test_sliding_window_spray_and_success_after_failure(self) -> None:
        base = 1795500000.0
        # Suspicious IP targeting 10 distinct accounts in 5 minutes + 1 compromise
        spray_events = [
            {
                "epoch_ts": base + i * 25,
                "timestamp": f"2026-11-24T10:0{i // 2}:00Z",
                "username": f"user_{i}",
                "source_ip": "198.51.100.50",
                "status": "FAILED",
            }
            for i in range(10)
        ]
        # Repeat failure then success on user_3
        spray_events.append({
            "epoch_ts": base + 300,
            "timestamp": "2026-11-24T10:05:00Z",
            "username": "user_3",
            "source_ip": "198.51.100.50",
            "status": "SUCCESS",
        })
        # Normal IP targeting only 2 accounts
        normal_events = [
            {"epoch_ts": base + 10, "timestamp": "2026-11-24T10:00:10Z", "username": "user_a", "source_ip": "10.0.0.5", "status": "SUCCESS"},
            {"epoch_ts": base + 20, "timestamp": "2026-11-24T10:00:20Z", "username": "user_b", "source_ip": "10.0.0.5", "status": "FAILED"},
        ]
        candidates, _ = detect_password_spray_windows(
            {"198.51.100.50": spray_events, "10.0.0.5": normal_events},
            window_minutes=10,
            min_distinct_accounts=8,
        )
        self.assertEqual(len(candidates), 1)
        c = candidates[0]
        self.assertEqual(c["source_ip"], "198.51.100.50")
        self.assertEqual(c["window_peak_accounts"], 10)
        self.assertEqual(c["success_after_failure_count"], 1)

        prioritized, _ = score_and_prioritize_threats(candidates)
        self.assertEqual(prioritized[0]["greedy_rank"], 1)
        self.assertGreaterEqual(prioritized[0]["risk_score"], 60)

    def test_bfs_traversal(self) -> None:
        events = [
            {"source_ip": "198.51.100.1", "username": "alice", "status": "FAILED"},
            {"source_ip": "198.51.100.1", "username": "bob", "status": "FAILED"},
            {"source_ip": "203.0.113.2", "username": "bob", "status": "SUCCESS"},
        ]
        graph = build_bipartite_graph(events)
        bfs_res, metrics = bfs_traverse(graph, "ip:198.51.100.1")
        self.assertEqual(metrics["vertices_visited"], 4)
        self.assertIn("alice", bfs_res["discovered_accounts"])
        self.assertIn("bob", bfs_res["discovered_accounts"])
        self.assertIn("203.0.113.2", bfs_res["discovered_ips"])

    def test_large_dataset_10k_records(self) -> None:
        events = [{"epoch_ts": float(10000 - i), "username": f"u{i % 20}", "source_ip": f"198.51.100.{i % 50}", "status": "FAILED"} for i in range(10000)]
        sorted_ev, metrics = merge_sort_events(events)
        self.assertEqual(len(sorted_ev), 10000)
        self.assertEqual(sorted_ev[0]["epoch_ts"], 1.0)
        self.assertGreater(metrics["execution_time_ms"], 0)


class TestCSVValidationAndAPI(unittest.TestCase):
    def test_csv_validation_edge_cases(self) -> None:
        empty = parse_and_validate_csv(b"")
        self.assertFalse(empty["ok"])

        bad_header = parse_and_validate_csv(b"time,user,ip\n2026-01-01T00:00:00Z,alice,10.0.0.1\n")
        self.assertFalse(bad_header["ok"])

        mixed_csv = (
            "timestamp,username,source_ip,status\n"
            "2026-11-24T10:00:00Z,alice,198.51.100.10,FAILED\n"
            "2026-11-24T10:00:00Z,alice,198.51.100.10,FAILED\n"
            "NOT_A_DATE,bob,198.51.100.10,FAILED\n"
            "2026-11-24T10:01:00Z,carol,999.999.999.999,FAILED\n"
        ).encode("utf-8")
        res = parse_and_validate_csv(mixed_csv)
        self.assertTrue(res["ok"])
        self.assertEqual(res["valid_rows"], 2)
        self.assertEqual(res["duplicate_rows"], 1)
        self.assertEqual(res["invalid_rows"], 2)

    def test_end_to_end_api_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = str(Path(tmpdir) / "test.db")
            init_db(db_file)

            # Build CSV with 9 sprayed accounts + success-after-failure + normal traffic
            lines = ["timestamp,username,source_ip,status,application"]
            for i in range(9):
                lines.append(f"2026-11-24T12:0{i}:00Z,user_{i},198.51.100.88,FAILED,SSO")
            lines.append("2026-11-24T12:09:30Z,user_4,198.51.100.88,SUCCESS,SSO")
            lines.append("2026-11-24T12:00:00Z,normal.user,10.0.1.2,SUCCESS,VPN")

            code, up_res = handle_upload("\n".join(lines).encode("utf-8"), "spray_test.csv", "Test Batch", db_path=db_file)
            self.assertEqual(code, 201)
            ds_id = up_res["dataset_id"]

            code, dash = handle_dashboard({"dataset_id": str(ds_id)}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertTrue(dash["has_data"])
            self.assertEqual(dash["kpis"]["suspicious_ips"], 1)

            code, logs = handle_get_logs({"dataset_id": str(ds_id)}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertEqual(logs["total"], 11)

            code, threats = handle_get_threats({"dataset_id": str(ds_id)}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertEqual(len(threats["threats"]), 1)
            threat_id = threats["threats"][0]["id"]

            code, detail = handle_get_threat_detail(threat_id, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertEqual(detail["threat"]["source_ip"], "198.51.100.88")

            code, net = handle_network({"dataset_id": str(ds_id)}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertGreater(len(net["nodes"]), 0)

            code, re_run = handle_analyze({"dataset_id": ds_id, "window_minutes": 15, "min_distinct_accounts": 8}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertEqual(re_run["suspicious_ip_count"], 1)

            code, pdf_bytes, mime, _ = handle_export_report({"dataset_id": ds_id, "format": "pdf"}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertEqual(mime, "application/pdf")
            self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))

            code, csv_bytes, mime, _ = handle_export_report({"dataset_id": ds_id, "format": "csv"}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertIn(b"198.51.100.88", csv_bytes)

            code, rep_list = handle_reports({}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertGreaterEqual(len(rep_list["reports"]), 1)

            code, st = handle_get_settings(db_path=db_file)
            self.assertEqual(code, 200)
            self.assertEqual(st["settings"]["window_minutes"], 10)

            code, upd = handle_update_settings({"window_minutes": 15, "min_distinct_accounts": 6}, db_path=db_file)
            self.assertEqual(code, 200)
            self.assertEqual(upd["settings"]["window_minutes"], 15)


if __name__ == "__main__":
    unittest.main()
