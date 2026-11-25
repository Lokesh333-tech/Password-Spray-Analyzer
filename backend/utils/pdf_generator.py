"""Downloadable CSV and PDF 1.4 security report generator."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from .csv_processor import sanitize_csv_cell


def generate_csv_report(report_data: Dict[str, Any]) -> bytes:
    """Generate a sanitized CSV detection report containing summary and threats."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    dataset = report_data.get("dataset", {})
    summary = report_data.get("summary", {})
    threats: List[Dict[str, Any]] = report_data.get("threats", [])
    targeted: List[Dict[str, Any]] = report_data.get("targeted_accounts", [])
    algos: List[Dict[str, Any]] = report_data.get("algorithm_metrics", [])

    writer.writerow(["PASSWORD SPRAY ANALYZER — SECURITY DETECTION REPORT"])
    writer.writerow(["Generated At (UTC)", report_data.get("generated_at", datetime.now(timezone.utc).isoformat())])
    writer.writerow(["Dataset", sanitize_csv_cell(dataset.get("name", "Unknown"))])
    writer.writerow(["Total Events", summary.get("total_events", 0)])
    writer.writerow(["Failed Events", summary.get("failed_events", 0)])
    writer.writerow(["Successful Events", summary.get("success_events", 0)])
    writer.writerow(["Suspicious IPs", summary.get("suspicious_ip_count", 0)])
    writer.writerow(["Critical Alerts", summary.get("critical_alert_count", 0)])
    writer.writerow([])

    writer.writerow([
        "Greedy Rank",
        "Source IP",
        "Severity",
        "Risk Score",
        "Total Attempts",
        "Failed Attempts",
        "Successful Attempts",
        "Distinct Accounts",
        "Peak Window Accounts",
        "Success After Failure Count",
        "Window (min)",
        "First Observed",
        "Last Observed",
        "Detection Explanation",
    ])
    for t in threats:
        writer.writerow([
            t.get("greedy_rank", ""),
            sanitize_csv_cell(t.get("source_ip", "")),
            sanitize_csv_cell(t.get("severity", "")),
            t.get("risk_score", 0),
            t.get("total_attempts", 0),
            t.get("failed_attempts", 0),
            t.get("successful_attempts", 0),
            t.get("distinct_accounts", 0),
            t.get("window_peak_accounts", 0),
            t.get("success_after_failure_count", 0),
            t.get("window_minutes", 10),
            sanitize_csv_cell(t.get("first_seen", "")),
            sanitize_csv_cell(t.get("last_seen", "")),
            sanitize_csv_cell(t.get("explanation", "")),
        ])

    writer.writerow([])
    writer.writerow(["TOP TARGETED USER ACCOUNTS"])
    writer.writerow(["Username", "Source IP", "Failed Attempts", "Successful Attempts", "Success After Failure", "Last Attempt"])
    for acc in targeted[:50]:
        writer.writerow([
            sanitize_csv_cell(acc.get("username", "")),
            sanitize_csv_cell(acc.get("source_ip", "")),
            acc.get("failed_attempts", 0),
            acc.get("successful_attempts", 0),
            "YES" if acc.get("had_success_after_failure") else "NO",
            sanitize_csv_cell(acc.get("last_attempt", "")),
        ])

    writer.writerow([])
    writer.writerow(["ALGORITHM PERFORMANCE METRICS"])
    writer.writerow(["Algorithm", "Input Size", "Execution Time (ms)", "Time Complexity", "Space Complexity"])
    for m in algos:
        writer.writerow([
            sanitize_csv_cell(m.get("algorithm_name", "")),
            m.get("input_size", 0),
            m.get("execution_time_ms", 0),
            sanitize_csv_cell(m.get("time_complexity", "")),
            sanitize_csv_cell(m.get("space_complexity", "")),
        ])

    return buf.getvalue().encode("utf-8")


def _pdf_escape(text: str) -> str:
    ascii_safe = text.encode("latin-1", "replace").decode("latin-1")
    return ascii_safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_text(text: str, max_chars: int = 92) -> List[str]:
    words = text.split()
    if not words:
        return [""]
    lines: List[str] = []
    cur = words[0]
    for w in words[1:]:
        if len(cur) + 1 + len(w) <= max_chars:
            cur += " " + w
        else:
            lines.append(cur)
            cur = w
    lines.append(cur)
    return lines


def generate_pdf_report(report_data: Dict[str, Any]) -> bytes:
    """Generate a valid multi-page PDF 1.4 security report in pure Python."""
    dataset = report_data.get("dataset", {})
    summary = report_data.get("summary", {})
    threats: List[Dict[str, Any]] = report_data.get("threats", [])
    targeted: List[Dict[str, Any]] = report_data.get("targeted_accounts", [])
    algos: List[Dict[str, Any]] = report_data.get("algorithm_metrics", [])
    generated_at = report_data.get("generated_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

    # Build structured printable lines: (font_tag, size, text, color_rgb)
    # font_tag: F1 = Helvetica, F2 = Helvetica-Bold, F3 = Courier
    lines: List[tuple[str, int, str, tuple[float, float, float]]] = []

    def add_line(font: str, size: int, text: str, color: tuple[float, float, float] = (0.1, 0.1, 0.12)) -> None:
        lines.append((font, size, text, color))

    def add_gap(count: int = 1) -> None:
        for _ in range(count):
            lines.append(("F1", 10, "", (0.1, 0.1, 0.12)))

    # Header
    add_line("F2", 18, "PASSWORD SPRAY ANALYZER", (0.86, 0.15, 0.15))
    add_line("F1", 10, "Intelligent Authentication Threat Detection — Security Report", (0.35, 0.35, 0.4))
    add_line("F1", 9, f"Generated: {generated_at}   |   Dataset: {dataset.get('name', 'Active Dataset')}", (0.4, 0.4, 0.45))
    add_line("F1", 9, "-" * 95, (0.82, 0.82, 0.85))
    add_gap()

    # Section 1: Dataset & KPI Summary
    add_line("F2", 13, "1. Dataset & Authentication Summary", (0.09, 0.09, 0.11))
    add_line("F1", 10, f"Filename: {dataset.get('filename', 'N/A')}   |   Valid Records: {summary.get('total_events', 0)}   |   Duplicates Flagged: {dataset.get('duplicate_count', 0)}")
    add_line("F1", 10, f"Successful Logins: {summary.get('success_events', 0)}   |   Failed Logins: {summary.get('failed_events', 0)}")
    add_line("F1", 10, f"Suspicious Source IPs: {summary.get('suspicious_ip_count', 0)}   |   Critical: {summary.get('critical_alert_count', 0)}   |   High: {summary.get('high_alert_count', 0)}   |   Medium: {summary.get('medium_alert_count', 0)}")
    add_line("F1", 10, f"Detection Parameters: {summary.get('window_minutes', 10)}-minute sliding window, minimum {summary.get('min_distinct_accounts', 8)} distinct targeted accounts.")
    add_gap()

    # Section 2: Suspicious IP Threats
    add_line("F2", 13, "2. Detected Suspicious IP Addresses (Greedy Priority Order)", (0.09, 0.09, 0.11))
    if not threats:
        add_line("F1", 10, "No suspicious password-spraying IP addresses detected under current thresholds.")
    else:
        for t in threats[:25]:
            sev = t.get("severity", "Low")
            sev_color = (0.86, 0.15, 0.15) if sev in ("Critical", "High") else (0.75, 0.45, 0.05)
            add_line(
                "F2",
                10,
                f"#{t.get('greedy_rank', 1)}  IP: {t.get('source_ip', '')}  |  Score: {t.get('risk_score', 0)}/100 ({sev})  |  Distinct Accounts: {t.get('distinct_accounts', 0)}",
                sev_color,
            )
            add_line(
                "F3",
                9,
                f"    Attempts: {t.get('total_attempts', 0)} (Fail: {t.get('failed_attempts', 0)}, Ok: {t.get('successful_attempts', 0)})  |  Peak Window: {t.get('window_peak_accounts', 0)} accts  |  SAF: {t.get('success_after_failure_count', 0)}",
            )
            add_line(
                "F1",
                9,
                f"    Observed: {t.get('first_seen', '')} to {t.get('last_seen', '')}",
                (0.35, 0.35, 0.4),
            )
            for wrapped in _wrap_text(str(t.get("explanation", "")), 90):
                add_line("F1", 9, f"    {wrapped}", (0.2, 0.2, 0.24))
            add_gap()

    # Section 3: Targeted Accounts
    add_line("F2", 13, "3. Most Targeted User Accounts & Compromise Indicators", (0.09, 0.09, 0.11))
    if not targeted:
        add_line("F1", 10, "No targeted accounts recorded.")
    else:
        for acc in targeted[:20]:
            flag = " [SUCCESS AFTER FAILURE]" if acc.get("had_success_after_failure") else ""
            color = (0.86, 0.15, 0.15) if acc.get("had_success_after_failure") else (0.15, 0.15, 0.18)
            add_line(
                "F3",
                9,
                f"- {acc.get('username', ''):<22} | IP: {acc.get('source_ip', ''):<16} | Fail: {acc.get('failed_attempts', 0):<3} | Ok: {acc.get('successful_attempts', 0):<2}{flag}",
                color,
            )
    add_gap()

    # Section 4: Algorithm Performance Metrics
    add_line("F2", 13, "4. DAA Algorithm Performance Telemetry", (0.09, 0.09, 0.11))
    for m in algos:
        add_line(
            "F3",
            9,
            f"- {m.get('algorithm_name', ''):<28} | n={m.get('input_size', 0):<6} | {m.get('execution_time_ms', 0):.4f} ms | Time: {m.get('time_complexity', '')} | Space: {m.get('space_complexity', '')}",
        )

    # Paginate into 46 lines per page (Letter: 612 x 792)
    lines_per_page = 46
    pages: List[List[tuple[str, int, str, tuple[float, float, float]]]] = [
        lines[i : i + lines_per_page] for i in range(0, len(lines), lines_per_page)
    ] or [[]]

    # Construct PDF objects
    objects: List[bytes] = []

    def add_obj(data: bytes) -> int:
        objects.append(data)
        return len(objects)

    # 1: Catalog, 2: Pages placeholder, 3-5: Fonts
    add_obj(b"<< /Type /Catalog /Pages 2 0 R >>")
    add_obj(b"")  # placeholder for Pages
    add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    page_ids: List[int] = []
    total_pages = len(pages)

    for page_idx, page_lines in enumerate(pages, start=1):
        stream_cmds: List[str] = ["BT"]
        y = 750
        for font, size, text, (r, g, b) in page_lines:
            if text:
                stream_cmds.append(f"{r:.2f} {g:.2f} {b:.2f} rg")
                stream_cmds.append(f"/{font} {size} Tf")
                stream_cmds.append(f"1 0 0 1 46 {y} Tm ({_pdf_escape(text)}) Tj")
            y -= 15

        # Footer page number
        stream_cmds.append("0.45 0.45 0.50 rg")
        stream_cmds.append("/F1 8 Tf")
        footer = f"Password Spray Analyzer  |  Defensive Authentication Forensics  |  Page {page_idx} of {total_pages}"
        stream_cmds.append(f"1 0 0 1 46 28 Tm ({_pdf_escape(footer)}) Tj")
        stream_cmds.append("ET")

        content_bytes = "\n".join(stream_cmds).encode("latin-1")
        content_id = add_obj(
            f"<< /Length {len(content_bytes)} >>\nstream\n".encode("ascii")
            + content_bytes
            + b"\nendstream"
        )
        page_id = add_obj(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents {content_id} 0 R >>".encode("ascii")
        )
        page_ids.append(page_id)

    kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [ {kids_str} ] /Count {len(page_ids)} >>".encode("ascii")

    # Assemble PDF byte stream with accurate xref offsets
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for idx, obj_bytes in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{idx} 0 obj\n".encode("ascii"))
        out.extend(obj_bytes)
        out.extend(b"\nendobj\n")

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)
