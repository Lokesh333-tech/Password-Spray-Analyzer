"""Generate synthetic authentication logs CSV using fictional usernames and RFC 5737/1918 reserved IPs."""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

FICTIONAL_USERS = [
    "alice.mercer", "bob.vance", "carol.chen", "david.kim", "elena.rostova",
    "frank.castillo", "grace.okafor", "henry.lin", "iris.patel", "jack.morgan",
    "karen.cho", "liam.oconnor", "maya.santos", "noah.klein", "olivia.berg",
    "peter.nguyen", "quinn.harper", "rachel.adams", "sam.takahashi", "tara.singh",
    "uma.krishnan", "victor.rossi", "wendy.zhao", "xavier.dubois",
]

NORMAL_IPS = [
    "10.0.12.14", "10.0.12.22", "10.0.14.8", "10.0.15.31",
    "10.0.18.45", "10.0.19.102", "192.0.2.15", "192.0.2.28",
]

APPS = ["SSO-Portal", "VPN-Gateway", "Corporate-Mail", "Git-Enterprise", "Cloud-Console"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/17.5",
    "OpenVPN-Client/3.4.2",
    "python-requests/2.31.0",
    "curl/8.4.0",
]


def build_synthetic_rows(seed: int = 42) -> list[dict[str, str]]:
    rng = random.Random(seed)
    base_time = datetime(2026, 11, 24, 6, 0, 0, tzinfo=timezone.utc)
    rows: list[dict[str, str]] = []

    # 1. Normal background corporate authentication traffic across 16 hours
    for i in range(180):
        dt = base_time + timedelta(minutes=rng.randint(0, 960), seconds=rng.randint(0, 59))
        user = rng.choice(FICTIONAL_USERS)
        ip = rng.choice(NORMAL_IPS)
        status = "SUCCESS" if rng.random() < 0.91 else "FAILED"
        rows.append({
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "username": user,
            "source_ip": ip,
            "status": status,
            "user_agent": rng.choice(USER_AGENTS[:3]),
            "application": rng.choice(APPS[:4]),
        })

    # 2. Critical Password Spray Campaign #1 (198.51.100.77) - 18 distinct users in 7 minutes + 2 compromises
    spray1_start = base_time + timedelta(hours=3, minutes=12)
    spray1_targets = FICTIONAL_USERS[:18]
    for idx, user in enumerate(spray1_targets):
        dt = spray1_start + timedelta(seconds=idx * 21 + rng.randint(0, 5))
        rows.append({
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "username": user,
            "source_ip": "198.51.100.77",
            "status": "FAILED",
            "user_agent": "python-requests/2.31.0",
            "application": "SSO-Portal",
        })
    # Second spray wave from same IP + 2 accounts compromised after repeated failures
    for idx, user in enumerate(spray1_targets[:12]):
        dt = spray1_start + timedelta(minutes=4, seconds=idx * 16)
        status = "SUCCESS" if user in ("david.kim", "maya.santos") else "FAILED"
        rows.append({
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "username": user,
            "source_ip": "198.51.100.77",
            "status": status,
            "user_agent": "python-requests/2.31.0",
            "application": "SSO-Portal",
        })

    # 3. High Severity Password Spray Campaign #2 (203.0.113.45) - 12 distinct users in 8 minutes + 1 compromise
    spray2_start = base_time + timedelta(hours=7, minutes=40)
    spray2_targets = FICTIONAL_USERS[6:18]
    for idx, user in enumerate(spray2_targets):
        dt1 = spray2_start + timedelta(seconds=idx * 30)
        rows.append({
            "timestamp": dt1.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "username": user,
            "source_ip": "203.0.113.45",
            "status": "FAILED",
            "user_agent": "curl/8.4.0",
            "application": "VPN-Gateway",
        })
        dt2 = dt1 + timedelta(seconds=95)
        status = "SUCCESS" if user == "iris.patel" else "FAILED"
        rows.append({
            "timestamp": dt2.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "username": user,
            "source_ip": "203.0.113.45",
            "status": status,
            "user_agent": "curl/8.4.0",
            "application": "VPN-Gateway",
        })

    # 4. Medium Severity Password Spray Campaign #3 (198.51.100.194) - 9 distinct users in 9 minutes, 0 compromises
    spray3_start = base_time + timedelta(hours=11, minutes=5)
    for idx, user in enumerate(FICTIONAL_USERS[14:23]):
        dt = spray3_start + timedelta(seconds=idx * 55)
        rows.append({
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "username": user,
            "source_ip": "198.51.100.194",
            "status": "FAILED",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0",
            "application": "Corporate-Mail",
        })

    # 5. Single-account brute force noise (203.0.113.99) - 18 failures on 1 user (should NOT trigger 8-account spray)
    bf_start = base_time + timedelta(hours=5, minutes=20)
    for idx in range(18):
        dt = bf_start + timedelta(seconds=idx * 12)
        rows.append({
            "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "username": "frank.castillo",
            "source_ip": "203.0.113.99",
            "status": "FAILED",
            "user_agent": "curl/8.4.0",
            "application": "Cloud-Console",
        })

    # Shuffle rows intentionally so Merge Sort demonstrates chronological ordering
    rng.shuffle(rows)
    return rows


def write_sample_csv(target_path: Path) -> Path:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    rows = build_synthetic_rows()
    fieldnames = ["timestamp", "username", "source_ip", "status", "user_agent", "application"]
    with target_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return target_path


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "sample_auth_logs.csv"
    write_sample_csv(out)
    print(f"Generated {out}")
