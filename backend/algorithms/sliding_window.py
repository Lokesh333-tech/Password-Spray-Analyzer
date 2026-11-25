"""Explicit Sliding Window Algorithm for password-spray attack detection.

Time Complexity:
  - Per IP with k sorted events: O(k) two-pointer traversal
  - Across all n events (including per-IP Merge Sort): O(n log k)
Space Complexity:
  - O(u + w) where u is distinct targeted usernames and w is active window size
"""

from __future__ import annotations

import math
import time
from typing import Any, Dict, List, Tuple

from .merge_sort import merge_sort_events


def detect_password_spray_windows(
    ip_events_map: Dict[str, List[Dict[str, Any]]],
    window_minutes: int = 10,
    min_distinct_accounts: int = 8,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Run Sliding Window analysis across each source IP's chronological events.

    Returns (candidate_threats, metrics).
    """
    start_ns = time.perf_counter_ns()
    window_seconds = max(1, int(window_minutes)) * 60
    min_accounts = max(1, int(min_distinct_accounts))

    candidates: List[Dict[str, Any]] = []
    total_events_scanned = 0
    total_windows_evaluated = 0

    for source_ip, raw_events in ip_events_map.items():
        if not raw_events:
            continue

        # Step 1: Sort this IP's events chronologically using explicit Merge Sort
        sorted_events, _ = merge_sort_events(raw_events, key_field="epoch_ts")
        n = len(sorted_events)
        total_events_scanned += n

        # Step 2: Two-pointer Sliding Window over chronological events
        left = 0
        window_failed_counts: Dict[str, int] = {}
        window_total_counts = 0

        peak_distinct_failed = 0
        peak_window_attempts = 0
        peak_window_start = sorted_events[0].get("timestamp", "")
        peak_window_end = sorted_events[0].get("timestamp", "")
        peak_window_duration_sec = 0.0
        triggering_windows = 0

        for right in range(n):
            ev_r = sorted_events[right]
            r_epoch = float(ev_r.get("epoch_ts", 0.0))
            r_user = str(ev_r.get("username", ""))
            r_status = str(ev_r.get("status", "")).upper()

            window_total_counts += 1
            if r_status == "FAILED" and r_user:
                window_failed_counts[r_user] = window_failed_counts.get(r_user, 0) + 1

            # Shrink left pointer until window duration <= window_seconds
            while left <= right and (r_epoch - float(sorted_events[left].get("epoch_ts", 0.0))) > window_seconds:
                ev_l = sorted_events[left]
                l_user = str(ev_l.get("username", ""))
                l_status = str(ev_l.get("status", "")).upper()
                window_total_counts -= 1
                if l_status == "FAILED" and l_user in window_failed_counts:
                    window_failed_counts[l_user] -= 1
                    if window_failed_counts[l_user] <= 0:
                        del window_failed_counts[l_user]
                left += 1

            total_windows_evaluated += 1
            distinct_failed_in_window = len(window_failed_counts)

            if distinct_failed_in_window >= min_accounts:
                triggering_windows += 1

            if (
                distinct_failed_in_window > peak_distinct_failed
                or (
                    distinct_failed_in_window == peak_distinct_failed
                    and window_total_counts > peak_window_attempts
                )
            ):
                peak_distinct_failed = distinct_failed_in_window
                peak_window_attempts = window_total_counts
                peak_window_start = str(sorted_events[left].get("timestamp", ""))
                peak_window_end = str(ev_r.get("timestamp", ""))
                peak_window_duration_sec = max(
                    1.0,
                    r_epoch - float(sorted_events[left].get("epoch_ts", r_epoch)),
                )

        # Step 3: Per-account breakdown & success-after-failure detection
        account_stats: Dict[str, Dict[str, Any]] = {}
        total_failed = 0
        total_success = 0

        for ev in sorted_events:
            user = str(ev.get("username", ""))
            status = str(ev.get("status", "")).upper()
            ts = str(ev.get("timestamp", ""))
            if user not in account_stats:
                account_stats[user] = {
                    "username": user,
                    "total_attempts": 0,
                    "failed_attempts": 0,
                    "successful_attempts": 0,
                    "failures_before_success": 0,
                    "had_success_after_failure": False,
                    "first_attempt": ts,
                    "last_attempt": ts,
                }
            st = account_stats[user]
            st["total_attempts"] += 1
            st["last_attempt"] = ts
            if status == "SUCCESS":
                total_success += 1
                st["successful_attempts"] += 1
                if st["failed_attempts"] > 0:
                    st["had_success_after_failure"] = True
                    st["failures_before_success"] = st["failed_attempts"]
            else:
                total_failed += 1
                st["failed_attempts"] += 1

        distinct_accounts_all = len(account_stats)
        success_after_failure_accounts = [
            acc for acc in account_stats.values() if acc["had_success_after_failure"]
        ]

        # Calculate attempt uniformity across accounts (entropy / coefficient of variation)
        counts = [acc["failed_attempts"] for acc in account_stats.values() if acc["failed_attempts"] > 0]
        if len(counts) > 1:
            mean_c = sum(counts) / len(counts)
            variance = sum((c - mean_c) ** 2 for c in counts) / len(counts)
            std_c = math.sqrt(variance)
            # Uniformity near 1.0 means low attempts-per-account variance (classic password spray)
            uniformity = max(0.0, min(1.0, 1.0 - (std_c / (mean_c + 1.0))))
        else:
            uniformity = 0.0

        is_spray_candidate = peak_distinct_failed >= min_accounts
        # Also surface high-risk repeated failure + compromise patterns even slightly below threshold
        is_suspicious = is_spray_candidate or (
            len(success_after_failure_accounts) > 0 and total_failed >= 5 and distinct_accounts_all >= 3
        )

        if is_suspicious:
            candidates.append({
                "source_ip": source_ip,
                "total_attempts": n,
                "failed_attempts": total_failed,
                "successful_attempts": total_success,
                "distinct_accounts": distinct_accounts_all,
                "window_minutes": int(window_minutes),
                "min_distinct_accounts": min_accounts,
                "window_peak_accounts": peak_distinct_failed,
                "window_peak_attempts": peak_window_attempts,
                "peak_window_start": peak_window_start,
                "peak_window_end": peak_window_end,
                "peak_window_duration_sec": round(peak_window_duration_sec, 2),
                "triggering_windows": triggering_windows,
                "first_seen": str(sorted_events[0].get("timestamp", "")),
                "last_seen": str(sorted_events[-1].get("timestamp", "")),
                "success_after_failure_count": len(success_after_failure_accounts),
                "uniformity_index": round(uniformity, 3),
                "is_threshold_spray": is_spray_candidate,
                "targeted_accounts": list(account_stats.values()),
            })

    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
    metrics = {
        "algorithm": "Sliding Window",
        "input_size": total_events_scanned,
        "ips_analyzed": len(ip_events_map),
        "windows_evaluated": total_windows_evaluated,
        "suspicious_ips_detected": len(candidates),
        "window_minutes": int(window_minutes),
        "min_distinct_accounts": min_accounts,
        "execution_time_ms": round(elapsed_ms, 4),
        "time_complexity": "O(n) per sorted stream",
        "space_complexity": "O(u + w)",
    }
    return candidates, metrics
