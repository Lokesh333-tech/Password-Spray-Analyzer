"""Flask REST API entrypoint for Password Spray Analyzer."""

from __future__ import annotations

import os
from flask import Flask, Response, jsonify, request
from flask_cors import CORS

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


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

    allowed_origins = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

    init_db()

    @app.get("/api/health")
    def health():
        code, data = handle_health()
        return jsonify(data), code

    @app.get("/api/datasets")
    def list_datasets():
        code, data = handle_list_datasets()
        return jsonify(data), code

    @app.delete("/api/datasets/<int:dataset_id>")
    def delete_dataset(dataset_id: int):
        code, data = handle_delete_dataset(dataset_id)
        return jsonify(data), code

    @app.post("/api/datasets/sample")
    def load_sample():
        code, data = handle_load_sample()
        return jsonify(data), code

    @app.post("/api/upload")
    def upload():
        if "file" in request.files:
            file_obj = request.files["file"]
            raw_bytes = file_obj.read()
            filename = file_obj.filename or "upload.csv"
            dataset_name = request.form.get("name")
        else:
            raw_bytes = request.get_data()
            filename = request.headers.get("X-Filename", "upload.csv")
            dataset_name = request.args.get("name")
        code, data = handle_upload(raw_bytes, filename, dataset_name)
        return jsonify(data), code

    @app.get("/api/logs")
    def get_logs():
        code, data = handle_get_logs(dict(request.args))
        return jsonify(data), code

    @app.get("/api/dashboard")
    def get_dashboard():
        code, data = handle_dashboard(dict(request.args))
        return jsonify(data), code

    @app.post("/api/analyze")
    def analyze():
        body = request.get_json(silent=True) or {}
        code, data = handle_analyze(body)
        return jsonify(data), code

    @app.get("/api/threats")
    def get_threats():
        code, data = handle_get_threats(dict(request.args))
        return jsonify(data), code

    @app.get("/api/threats/<int:threat_id>")
    def get_threat_detail(threat_id: int):
        code, data = handle_get_threat_detail(threat_id)
        return jsonify(data), code

    @app.get("/api/network")
    def get_network():
        code, data = handle_network(dict(request.args))
        return jsonify(data), code

    @app.get("/api/algorithms")
    def get_algorithms():
        code, data = handle_algorithms(dict(request.args))
        return jsonify(data), code

    @app.post("/api/algorithms/benchmark")
    def run_benchmark():
        body = request.get_json(silent=True) or {}
        code, data = handle_algorithm_benchmark(body)
        return jsonify(data), code

    @app.get("/api/reports")
    def get_reports():
        code, data = handle_reports(dict(request.args))
        return jsonify(data), code

    @app.post("/api/reports/export")
    def export_report():
        body = request.get_json(silent=True) or {}
        code, content, mime, filename = handle_export_report(body)
        return Response(
            content,
            status=code,
            mimetype=mime,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/settings")
    def get_settings():
        code, data = handle_get_settings()
        return jsonify(data), code

    @app.put("/api/settings")
    def update_settings():
        body = request.get_json(silent=True) or {}
        code, data = handle_update_settings(body)
        return jsonify(data), code

    @app.errorhandler(413)
    def file_too_large(_err):
        return jsonify({"error": "Uploaded file exceeds maximum allowed size limit (25 MB)."}), 413

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", "5001"))
    app.run(host="127.0.0.1", port=port, debug=False)
