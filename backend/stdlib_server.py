"""Pure Python 3.11 HTTP server bridging to the exact same backend API handlers and SQLite DB.

Used automatically when running in environments without Flask installed, ensuring real Python
DAA execution and real SQLite persistence without any mock frontend calculations.
"""

from __future__ import annotations

import json
import os
import re
import sys
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlparse

# Ensure workspace root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.api_handlers import (
    handle_algorithm_benchmark,
    handle_algorithms,
    handle_analyze,
    handle_dashboard,
    handle_delete_dataset,
    handle_export_report,
    handle_get_logs,
    handle_get_settings,
    handle_get_threat_detail,
    handle_get_threats,
    handle_health,
    handle_list_datasets,
    handle_load_sample,
    handle_network,
    handle_reports,
    handle_update_settings,
    handle_upload,
)
from backend.database.db import init_db


def _parse_multipart(content_type: str, body: bytes) -> Tuple[bytes, str, str | None]:
    header_bytes = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8")
    msg = BytesParser(policy=email_policy).parsebytes(header_bytes + body)
    file_bytes = b""
    filename = "upload.csv"
    dataset_name = None

    if msg.is_multipart():
        for part in msg.iter_parts():
            disp = part.get("Content-Disposition", "")
            if 'name="file"' in disp:
                filename = part.get_filename() or "upload.csv"
                payload = part.get_payload(decode=True)
                file_bytes = payload if payload is not None else b""
            elif 'name="name"' in disp:
                payload = part.get_payload(decode=True)
                if payload:
                    dataset_name = payload.decode("utf-8", errors="replace").strip()

    return file_bytes, filename, dataset_name


class ApiRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy per-request stderr spam
        return

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_binary(self, status_code: int, data: bytes, mime: str, filename: str) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b""
        if length > 26 * 1024 * 1024:
            return b""
        return self.rfile.read(length)

    def _read_json(self) -> Dict[str, Any]:
        raw = self._read_body()
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _query_params(self, query: str) -> Dict[str, str]:
        parsed = parse_qs(query, keep_blank_values=False)
        return {k: v[0] for k, v in parsed.items() if v}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = self._query_params(parsed.query)

        if path == "/api/health":
            code, data = handle_health()
            return self._send_json(code, data)
        if path == "/api/datasets":
            code, data = handle_list_datasets()
            return self._send_json(code, data)
        if path == "/api/logs":
            code, data = handle_get_logs(params)
            return self._send_json(code, data)
        if path == "/api/dashboard":
            code, data = handle_dashboard(params)
            return self._send_json(code, data)
        if path == "/api/threats":
            code, data = handle_get_threats(params)
            return self._send_json(code, data)
        m = re.fullmatch(r"/api/threats/(\d+)", path)
        if m:
            code, data = handle_get_threat_detail(int(m.group(1)))
            return self._send_json(code, data)
        if path == "/api/network":
            code, data = handle_network(params)
            return self._send_json(code, data)
        if path == "/api/algorithms":
            code, data = handle_algorithms(params)
            return self._send_json(code, data)
        if path == "/api/reports":
            code, data = handle_reports(params)
            return self._send_json(code, data)
        if path == "/api/settings":
            code, data = handle_get_settings()
            return self._send_json(code, data)

        self._send_json(404, {"error": f"Unknown GET endpoint: {path}"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = self._query_params(parsed.query)

        if path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            raw = self._read_body()
            if "multipart/form-data" in content_type:
                file_bytes, filename, dataset_name = _parse_multipart(content_type, raw)
            else:
                file_bytes = raw
                filename = self.headers.get("X-Filename", "upload.csv")
                dataset_name = params.get("name")
            code, data = handle_upload(file_bytes, filename, dataset_name)
            return self._send_json(code, data)

        if path == "/api/datasets/sample":
            code, data = handle_load_sample()
            return self._send_json(code, data)
        if path == "/api/analyze":
            code, data = handle_analyze(self._read_json())
            return self._send_json(code, data)
        if path == "/api/algorithms/benchmark":
            code, data = handle_algorithm_benchmark(self._read_json())
            return self._send_json(code, data)
        if path == "/api/reports/export":
            code, content, mime, filename = handle_export_report(self._read_json())
            return self._send_binary(code, content, mime, filename)

        self._send_json(404, {"error": f"Unknown POST endpoint: {path}"})

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/api/settings":
            code, data = handle_update_settings(self._read_json())
            return self._send_json(code, data)
        self._send_json(404, {"error": f"Unknown PUT endpoint: {path}"})

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        m = re.fullmatch(r"/api/datasets/(\d+)", path)
        if m:
            code, data = handle_delete_dataset(int(m.group(1)))
            return self._send_json(code, data)
        self._send_json(404, {"error": f"Unknown DELETE endpoint: {path}"})


def main() -> None:
    init_db()
    port = int(os.environ.get("PYTHON_API_PORT", "5001"))
    server = ThreadingHTTPServer(("127.0.0.1", port), ApiRequestHandler)
    print(f"Password Spray Analyzer Python API running on http://127.0.0.1:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
