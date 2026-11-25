"""Explicit Merge Sort implementation for chronological sorting of authentication events.

Time Complexity:
  - Best Case:    O(n log n)
  - Average Case: O(n log n)
  - Worst Case:   O(n log n)
Space Complexity:
  - Auxiliary:    O(n)
Stability: Stable (preserves original relative order on equal keys).
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Tuple


def _merge(
    left: List[Dict[str, Any]],
    right: List[Dict[str, Any]],
    key_fn: Callable[[Dict[str, Any]], float],
    stats: Dict[str, int],
) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    i = 0
    j = 0
    len_left = len(left)
    len_right = len(right)

    while i < len_left and j < len_right:
        stats["comparisons"] += 1
        # Use <= to guarantee stable sort
        if key_fn(left[i]) <= key_fn(right[j]):
            merged.append(left[i])
            i += 1
        else:
            merged.append(right[j])
            j += 1
        stats["merges"] += 1

    while i < len_left:
        merged.append(left[i])
        i += 1
        stats["merges"] += 1

    while j < len_right:
        merged.append(right[j])
        j += 1
        stats["merges"] += 1

    return merged


def _merge_sort_recursive(
    items: List[Dict[str, Any]],
    key_fn: Callable[[Dict[str, Any]], float],
    stats: Dict[str, int],
    depth: int,
) -> List[Dict[str, Any]]:
    if depth > stats["max_depth"]:
        stats["max_depth"] = depth

    n = len(items)
    if n <= 1:
        return list(items)

    mid = n // 2
    left_half = _merge_sort_recursive(items[:mid], key_fn, stats, depth + 1)
    right_half = _merge_sort_recursive(items[mid:], key_fn, stats, depth + 1)
    return _merge(left_half, right_half, key_fn, stats)


def merge_sort_events(
    events: List[Dict[str, Any]],
    key_field: str = "epoch_ts",
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Sort authentication events chronologically using explicit Merge Sort.

    Returns (sorted_events, telemetry_metrics).
    Never calls Python's built-in .sort() or sorted().
    """
    stats = {"comparisons": 0, "merges": 0, "max_depth": 0}
    start_ns = time.perf_counter_ns()

    if not events:
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
        return [], {
            "algorithm": "Merge Sort",
            "input_size": 0,
            "execution_time_ms": round(elapsed_ms, 4),
            "comparisons": 0,
            "merge_operations": 0,
            "max_recursion_depth": 0,
            "time_complexity": "O(n log n)",
            "space_complexity": "O(n)",
            "stable": True,
        }

    def key_fn(item: Dict[str, Any]) -> float:
        val = item.get(key_field, 0.0)
        return float(val) if val is not None else 0.0

    sorted_items = _merge_sort_recursive(events, key_fn, stats, 1)
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

    metrics = {
        "algorithm": "Merge Sort",
        "input_size": len(events),
        "execution_time_ms": round(elapsed_ms, 4),
        "comparisons": stats["comparisons"],
        "merge_operations": stats["merges"],
        "max_recursion_depth": stats["max_depth"],
        "time_complexity": "O(n log n)",
        "space_complexity": "O(n)",
        "stable": True,
    }
    return sorted_items, metrics
