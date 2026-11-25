"""Explicit Binary Search implementation for sorted authentication log time-range queries.

Time Complexity:
  - Bounds discovery: O(log n)
  - Range extraction: O(log n + k), where k is matching records
Space Complexity:
  - O(1) auxiliary for bounds search, O(k) for returned slice
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple


def lower_bound(
    sorted_events: List[Dict[str, Any]],
    target_epoch: float,
    key_field: str = "epoch_ts",
) -> Tuple[int, int]:
    """Find the first index where event[key_field] >= target_epoch.

    Returns (index, comparisons).
    """
    low = 0
    high = len(sorted_events)
    comparisons = 0

    while low < high:
        mid = low + (high - low) // 2
        comparisons += 1
        val = float(sorted_events[mid].get(key_field, 0.0))
        if val < target_epoch:
            low = mid + 1
        else:
            high = mid

    return low, comparisons


def upper_bound(
    sorted_events: List[Dict[str, Any]],
    target_epoch: float,
    key_field: str = "epoch_ts",
) -> Tuple[int, int]:
    """Find the first index where event[key_field] > target_epoch.

    Returns (index, comparisons).
    """
    low = 0
    high = len(sorted_events)
    comparisons = 0

    while low < high:
        mid = low + (high - low) // 2
        comparisons += 1
        val = float(sorted_events[mid].get(key_field, 0.0))
        if val <= target_epoch:
            low = mid + 1
        else:
            high = mid

    return low, comparisons


def binary_search_time_range(
    sorted_events: List[Dict[str, Any]],
    start_epoch: Optional[float] = None,
    end_epoch: Optional[float] = None,
    key_field: str = "epoch_ts",
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Retrieve authentication records within [start_epoch, end_epoch] using Binary Search.

    Precondition: sorted_events must be sorted ascending by key_field (via Merge Sort).
    """
    start_ns = time.perf_counter_ns()
    n = len(sorted_events)

    if n == 0:
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        return [], {
            "algorithm": "Binary Search",
            "input_size": 0,
            "matched_count": 0,
            "left_index": 0,
            "right_index": 0,
            "comparisons": 0,
            "execution_time_ms": round(elapsed_ms, 4),
            "time_complexity": "O(log n + k)",
            "space_complexity": "O(1) search / O(k) result",
        }

    total_comparisons = 0
    if start_epoch is not None:
        left_idx, c1 = lower_bound(sorted_events, float(start_epoch), key_field)
        total_comparisons += c1
    else:
        left_idx = 0

    if end_epoch is not None:
        right_idx, c2 = upper_bound(sorted_events, float(end_epoch), key_field)
        total_comparisons += c2
    else:
        right_idx = n

    if left_idx >= right_idx:
        matched: List[Dict[str, Any]] = []
    else:
        matched = sorted_events[left_idx:right_idx]

    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

    metrics = {
        "algorithm": "Binary Search",
        "input_size": n,
        "matched_count": len(matched),
        "left_index": left_idx,
        "right_index": max(left_idx, right_idx),
        "comparisons": total_comparisons,
        "execution_time_ms": round(elapsed_ms, 4),
        "time_complexity": "O(log n + k)",
        "space_complexity": "O(1) search / O(k) result",
    }
    return matched, metrics
