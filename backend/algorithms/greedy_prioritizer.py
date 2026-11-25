"""Greedy Threat Prioritization & Explainable Heuristic Scoring Engine.

Assigns an explainable heuristic risk score between 0 and 100 based on:
  1. Distinct accounts targeted (0-35 pts)
  2. Failure volume & failure ratio (0-20 pts)
  3. Attack time concentration in sliding window (0-20 pts)
  4. Repeated failures followed by successful login (0-15 pts)
  5. Horizontal distribution uniformity across accounts (0-10 pts)

Note: These are deterministic, explainable heuristic weights for security triage,
not statistical probabilities.

Time Complexity: O(t log t) for greedy prioritization over t candidate threats.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple


def classify_severity(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def compute_heuristic_score(candidate: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]], str]:
    """Compute an explainable 0-100 heuristic risk score and plain-language rationale."""
    distinct_accounts = int(candidate.get("distinct_accounts", 0))
    peak_accounts = int(candidate.get("window_peak_accounts", 0))
    min_thresh = max(1, int(candidate.get("min_distinct_accounts", 8)))
    total_attempts = max(1, int(candidate.get("total_attempts", 1)))
    failed_attempts = int(candidate.get("failed_attempts", 0))
    window_minutes = max(1, int(candidate.get("window_minutes", 10)))
    peak_attempts = int(candidate.get("window_peak_attempts", 0))
    peak_duration_sec = max(1.0, float(candidate.get("peak_window_duration_sec", 60.0)))
    saf_count = int(candidate.get("success_after_failure_count", 0))
    uniformity = float(candidate.get("uniformity_index", 0.0))

    # 1. Distinct accounts targeted (0-35 pts)
    breadth_ratio = max(peak_accounts, distinct_accounts) / max(min_thresh, 1)
    distinct_pts = min(35, round(min(2.2, breadth_ratio) * 15.9))

    # 2. Failure frequency & failure ratio (0-20 pts)
    fail_ratio = failed_attempts / total_attempts
    volume_factor = min(1.0, failed_attempts / 35.0)
    failure_pts = min(20, round((fail_ratio * 10.0) + (volume_factor * 10.0)))

    # 3. Time concentration / attack velocity inside window (0-20 pts)
    attempts_per_min = peak_attempts / max(0.5, peak_duration_sec / 60.0)
    window_density = min(1.0, peak_accounts / max(1.0, float(min_thresh) * 1.5))
    velocity_factor = min(1.0, attempts_per_min / 6.0)
    concentration_pts = min(20, round((window_density * 12.0) + (velocity_factor * 8.0)))

    # 4. Repeated failures followed by successful login (0-15 pts)
    saf_pts = min(15, saf_count * 8) if saf_count > 0 else 0

    # 5. Attempt uniformity across accounts (0-10 pts)
    distribution_pts = min(10, round(uniformity * 10.0))

    total_score = max(0, min(100, distinct_pts + failure_pts + concentration_pts + saf_pts + distribution_pts))

    breakdown = [
        {
            "factor": "Distinct Targeted Accounts",
            "points": distinct_pts,
            "max_points": 35,
            "detail": f"{peak_accounts} distinct failed accounts inside {window_minutes}m window ({distinct_accounts} overall).",
        },
        {
            "factor": "Failure Frequency & Ratio",
            "points": failure_pts,
            "max_points": 20,
            "detail": f"{failed_attempts} failed of {total_attempts} total attempts ({round(fail_ratio * 100, 1)}% failure rate).",
        },
        {
            "factor": "Temporal Concentration",
            "points": concentration_pts,
            "max_points": 20,
            "detail": f"{peak_attempts} attempts concentrated in {round(peak_duration_sec / 60.0, 1)}m (~{round(attempts_per_min, 1)} attempts/min).",
        },
        {
            "factor": "Success After Repeated Failures",
            "points": saf_pts,
            "max_points": 15,
            "detail": (
                f"{saf_count} account(s) authenticated successfully after prior failed attempts."
                if saf_count > 0
                else "No post-failure successful logins observed from this IP."
            ),
        },
        {
            "factor": "Horizontal Spray Uniformity",
            "points": distribution_pts,
            "max_points": 10,
            "detail": f"Uniformity index {uniformity:.2f} across targeted usernames.",
        },
    ]

    severity = classify_severity(total_score)

    reasons = [
        f"Source IP {candidate['source_ip']} targeted {peak_accounts} distinct accounts with failed logins inside a {window_minutes}-minute sliding window (threshold: {min_thresh}).",
        f"Recorded {failed_attempts} failures out of {total_attempts} total attempts ({round(fail_ratio * 100, 1)}% failure rate).",
    ]
    if saf_count > 0:
        reasons.append(
            f"High-priority indicator: {saf_count} account(s) succeeded after earlier failed attempts, suggesting potential credential compromise."
        )
    if uniformity >= 0.6:
        reasons.append(
            "Low attempt variance across usernames matches horizontal password spraying rather than single-account brute force."
        )
    reasons.append(
        f"Assigned heuristic risk score {total_score}/100 ({severity}) based on breadth, velocity, failure ratio, compromise indicators, and uniformity."
    )

    return total_score, breakdown, " ".join(reasons)


def score_and_prioritize_threats(
    candidates: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Score each threat candidate and apply Greedy Prioritization by risk severity."""
    start_ns = time.perf_counter_ns()

    scored: List[Dict[str, Any]] = []
    for cand in candidates:
        score, breakdown, explanation = compute_heuristic_score(cand)
        enriched = dict(cand)
        enriched["risk_score"] = score
        enriched["severity"] = classify_severity(score)
        enriched["score_breakdown"] = breakdown
        enriched["explanation"] = explanation
        scored.append(enriched)

    # Greedy selection: iteratively extract the maximum-impact threat first
    remaining = list(scored)
    prioritized: List[Dict[str, Any]] = []
    rank = 1

    while remaining:
        best_idx = 0
        for i in range(1, len(remaining)):
            cur = remaining[i]
            best = remaining[best_idx]
            cur_key = (cur["risk_score"], cur["success_after_failure_count"], cur["window_peak_accounts"], cur["failed_attempts"])
            best_key = (best["risk_score"], best["success_after_failure_count"], best["window_peak_accounts"], best["failed_attempts"])
            if cur_key > best_key:
                best_idx = i
        chosen = remaining.pop(best_idx)
        chosen["greedy_rank"] = rank
        rank += 1
        prioritized.append(chosen)

    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
    metrics = {
        "algorithm": "Greedy Threat Prioritization",
        "input_size": len(candidates),
        "prioritized_count": len(prioritized),
        "execution_time_ms": round(elapsed_ms, 4),
        "time_complexity": "O(t^2) selection / O(t log t) heap",
        "space_complexity": "O(t)",
    }
    return prioritized, metrics
