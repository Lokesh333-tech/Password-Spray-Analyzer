"""Explicit Hash Table implementation with separate chaining for IP grouping.

Time Complexity:
  - Average Lookup / Insert: O(1)
  - Worst-Case Lookup / Insert: O(n) (if all keys collide into a single bucket)
Space Complexity:
  - O(n + m) where n is stored entries and m is bucket capacity.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple


class CustomHashTable:
    """Hash table using polynomial rolling hash + FNV mixing and separate chaining."""

    def __init__(self, initial_capacity: int = 64, load_factor_threshold: float = 0.75) -> None:
        self.capacity = max(16, initial_capacity)
        self.load_factor_threshold = load_factor_threshold
        self.buckets: List[List[Tuple[str, Any]]] = [[] for _ in range(self.capacity)]
        self.size = 0
        self.collisions = 0
        self.resizes = 0

    def _hash(self, key: str) -> int:
        # FNV-1a inspired 32-bit hash for uniform IP string distribution
        h = 2166136261
        for ch in key:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        return h % self.capacity

    def _resize(self) -> None:
        old_buckets = self.buckets
        self.capacity *= 2
        self.buckets = [[] for _ in range(self.capacity)]
        self.size = 0
        self.resizes += 1
        for bucket in old_buckets:
            for k, v in bucket:
                self.put(k, v, count_resize=False)

    def put(self, key: str, value: Any, count_resize: bool = True) -> None:
        if count_resize and (self.size + 1) / self.capacity > self.load_factor_threshold:
            self._resize()

        idx = self._hash(key)
        bucket = self.buckets[idx]
        for i, (existing_key, _) in enumerate(bucket):
            if existing_key == key:
                bucket[i] = (key, value)
                return

        if len(bucket) > 0:
            self.collisions += 1
        bucket.append((key, value))
        self.size += 1

    def get(self, key: str, default: Any = None) -> Any:
        idx = self._hash(key)
        bucket = self.buckets[idx]
        for existing_key, val in bucket:
            if existing_key == key:
                return val
        return default

    def items(self) -> List[Tuple[str, Any]]:
        result: List[Tuple[str, Any]] = []
        for bucket in self.buckets:
            for pair in bucket:
                result.append(pair)
        return result

    def max_chain_length(self) -> int:
        max_len = 0
        for bucket in self.buckets:
            if len(bucket) > max_len:
                max_len = len(bucket)
        return max_len

    def used_buckets(self) -> int:
        return sum(1 for bucket in self.buckets if len(bucket) > 0)


def group_events_by_ip(
    events: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    """Group authentication events by source_ip using CustomHashTable.

    Returns (ip_summaries, ip_events_map, metrics).
    """
    start_ns = time.perf_counter_ns()
    initial_cap = max(32, min(4096, len(events) // 2 + 16))
    table = CustomHashTable(initial_capacity=initial_cap)

    for ev in events:
        ip = str(ev.get("source_ip", "unknown"))
        entry = table.get(ip)
        if entry is None:
            entry = {
                "source_ip": ip,
                "total_attempts": 0,
                "successful_attempts": 0,
                "failed_attempts": 0,
                "usernames_table": CustomHashTable(initial_capacity=16),
                "events": [],
                "first_seen": ev.get("timestamp", ""),
                "last_seen": ev.get("timestamp", ""),
                "first_epoch": float(ev.get("epoch_ts", 0.0)),
                "last_epoch": float(ev.get("epoch_ts", 0.0)),
            }
            table.put(ip, entry)

        entry["total_attempts"] += 1
        status = str(ev.get("status", "")).upper()
        if status == "SUCCESS":
            entry["successful_attempts"] += 1
        else:
            entry["failed_attempts"] += 1

        username = str(ev.get("username", ""))
        if username:
            entry["usernames_table"].put(username, True)

        epoch = float(ev.get("epoch_ts", 0.0))
        if epoch < entry["first_epoch"]:
            entry["first_epoch"] = epoch
            entry["first_seen"] = ev.get("timestamp", "")
        if epoch > entry["last_epoch"]:
            entry["last_epoch"] = epoch
            entry["last_seen"] = ev.get("timestamp", "")

        entry["events"].append(ev)

    summaries: List[Dict[str, Any]] = []
    ip_events_map: Dict[str, List[Dict[str, Any]]] = {}

    for ip, entry in table.items():
        distinct_users = [u for u, _ in entry["usernames_table"].items()]
        ip_events_map[ip] = entry["events"]
        summaries.append({
            "source_ip": ip,
            "total_attempts": entry["total_attempts"],
            "distinct_usernames": len(distinct_users),
            "usernames_sample": distinct_users[:10],
            "successful_attempts": entry["successful_attempts"],
            "failed_attempts": entry["failed_attempts"],
            "failure_rate": round(
                (entry["failed_attempts"] / entry["total_attempts"]) * 100, 1
            ) if entry["total_attempts"] > 0 else 0.0,
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
        })

    # Sort summaries deterministically by total_attempts descending via simple insertion/merge
    summaries.sort(key=lambda x: (-x["total_attempts"], x["source_ip"]))
    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

    metrics = {
        "algorithm": "Hash Table (Separate Chaining)",
        "input_size": len(events),
        "unique_ips": table.size,
        "bucket_capacity": table.capacity,
        "used_buckets": table.used_buckets(),
        "load_factor": round(table.size / table.capacity, 4) if table.capacity else 0.0,
        "collisions": table.collisions,
        "resizes": table.resizes,
        "max_chain_length": table.max_chain_length(),
        "execution_time_ms": round(elapsed_ms, 4),
        "time_complexity": "O(1) avg / O(n) worst",
        "space_complexity": "O(n)",
    }
    return summaries, ip_events_map, metrics
