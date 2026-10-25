"""Flask application factory and local-only JSON API."""

from __future__ import annotations

import csv
import hmac
import io
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

from .scanner import ScanBusy, ScanError, ScanManager, SystemProbe
from .store import Store

APP_NAME = "ReconDeck"
APP_VERSION = "1.0.0"
API_HEADER = "X-ReconDeck-Token"


def create_app(
    *,
    data_dir: str | Path | None = None,
    test_config: dict[str, Any] | None = None,
) -> Flask:
    root = Path(__file__).resolve().parent.parent
    data_path = Path(data_dir) if data_dir else Path(
        os.environ.get("RECONDECK_DATA_DIR", root / "data")
    )
    data_path.mkdir(parents=True, exist_ok=True)

    app = Flask(
        __name__,
        static_folder=str(root / "static"),
        template_folder=str(root / "templates"),
    )
    app.config.update(
        MAX_CONTENT_LENGTH=64 * 1024,
        JSON_SORT_KEYS=False,
    )
    if test_config:
        app.config.update(test_config)

    api_token = secrets.token_urlsafe(32)
    app.config["API_TOKEN"] = api_token
    store = Store(data_path / "recondeck.db")
    probe = SystemProbe()
    manager = ScanManager(store, probe)
    app.extensions["recondeck_store"] = store
    app.extensions["recondeck_manager"] = manager
    app.extensions["recondeck_probe"] = probe
    app.extensions["recondeck_data_dir"] = str(data_path)

    @app.before_request
    def local_only() -> Response | None:
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            return jsonify({"error": "ReconDeck is available on this machine only."}), 403
        host = (request.host or "").split(":", 1)[0].strip("[]").lower()
        if host not in {"127.0.0.1", "localhost", "::1"}:
            return jsonify({"error": "Unrecognized local host header."}), 403
        if request.path.startswith("/api/"):
            supplied = request.headers.get(API_HEADER, "")
            if not supplied or not hmac.compare_digest(supplied, api_token):
                return jsonify({"error": "Missing or invalid ReconDeck session token."}), 403
        return None

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; font-src 'self'; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
            "form-action 'none'; object-src 'none'"
        )
        if request.path == "/" or request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index() -> str:
        response = Response(render_template("index.html", token=api_token))
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        return response

    @app.get("/healthz")
    def healthz() -> Response:
        return jsonify({"status": "ok", "app": APP_NAME, "version": APP_VERSION})

    @app.get("/api/bootstrap")
    def bootstrap() -> Response:
        system = probe.get(refresh=True)
        stats = store.stats()
        recent = store.list_scans(limit=6)
        inventory = store.inventory(limit=500)
        active = manager.dynamic_state()
        return jsonify(
            {
                "app": {"name": APP_NAME, "version": system.get("version", "1.0.0")},
                "system": system,
                "stats": stats,
                "recentScans": recent,
                "inventory": inventory,
                "live": active,
            }
        )

    @app.get("/api/system")
    def system() -> Response:
        refresh = request.args.get("refresh") == "1"
        return jsonify({"system": probe.get(refresh=refresh), "live": manager.dynamic_state()})

    @app.get("/api/stats")
    def stats() -> Response:
        return jsonify({"stats": store.stats(), "live": manager.dynamic_state()})

    @app.get("/api/inventory")
    def inventory() -> Response:
        limit = _int_arg("limit", 200, minimum=1, maximum=1000)
        return jsonify({"inventory": store.inventory(limit=limit)})

    @app.get("/api/assets/<string:address>")
    def asset_detail(address: str) -> Response:
        if len(address) > 80:
            return jsonify({"error": "Asset not found."}), 404
        asset = store.asset(address)
        if not asset:
            return jsonify({"error": "Asset not found."}), 404
        return jsonify({"asset": asset})

    @app.get("/api/inventory/export")
    def export_inventory() -> Response:
        fmt = request.args.get("format", "csv").lower()
        hosts = store.inventory(limit=1000)
        stamp = datetime.now().strftime("%Y%m%d")
        if fmt == "json":
            payload = json.dumps(
                {
                    "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "hosts": hosts,
                },
                indent=2,
            )
            return Response(
                payload,
                mimetype="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="recondeck-inventory-{stamp}.json"'
                },
            )
        if fmt == "csv":
            return Response(
                _inventory_csv(hosts),
                mimetype="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="recondeck-inventory-{stamp}.csv"'
                },
            )
        return jsonify({"error": "Choose JSON or CSV format."}), 400

    @app.get("/api/scans")
    def scans() -> Response:
        limit = _int_arg("limit", 50, minimum=1, maximum=200)
        kind = request.args.get("kind")
        status = request.args.get("status")
        query = request.args.get("q", "").strip()
        rows = store.list_scans(limit=limit, kind=kind, status=status, query=query)
        return jsonify({"scans": rows, "live": manager.dynamic_state()})

    @app.post("/api/scans")
    def start_scan() -> Response:
        if not request.is_json:
            return jsonify({"error": "Send a JSON scan request."}), 415
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "Scan request must be a JSON object."}), 400
        try:
            job = manager.start(body)
        except ScanBusy as exc:
            return (
                jsonify({"error": exc.message, "code": exc.code, "activeId": exc.active_id}),
                409,
            )
        except ScanError as exc:
            return jsonify({"error": exc.message, "code": exc.code}), _status_for(exc.code)
        payload = manager.serialize_job(job, after_log=0)
        payload["logs"] = []
        payload["logCount"] = 0
        return jsonify({"scan": payload}), 202

    @app.get("/api/scans/<scan_id>")
    def scan_detail(scan_id: str) -> Response:
        after = _int_arg("after", 0, minimum=0, maximum=100000)
        job = manager.jobs.get(scan_id)
        if job is not None:
            return jsonify(
                {"scan": manager.serialize_job(job, after_log=after), "live": manager.dynamic_state()}
            )
        record = store.get_scan(scan_id)
        if not record:
            return jsonify({"error": "Scan not found."}), 404
        logs_text = record.pop("log", "")
        log_lines = logs_text.splitlines()
        if after > len(log_lines):
            after = 0
        record["logs"] = log_lines[after:]
        record["logCount"] = len(log_lines)
        record.setdefault("progress", 100.0 if record.get("status") == "completed" else 0.0)
        record.setdefault("profileLabel", record.get("profile"))
        record["summary"] = record.get("summary") or {}
        return jsonify({"scan": record, "live": manager.dynamic_state()})

    @app.post("/api/scans/<scan_id>/cancel")
    def cancel_scan(scan_id: str) -> Response:
        try:
            job = manager.cancel(scan_id)
        except ScanError as exc:
            return jsonify({"error": exc.message, "code": exc.code}), (
                404 if exc.code == "not_found" else 409
            )
        return jsonify({"scan": manager.serialize_job(job), "message": "Stopping scan…"}), 202

    @app.delete("/api/scans/<scan_id>")
    def delete_scan(scan_id: str) -> Response:
        active = manager.active()
        if active and active.id == scan_id:
            return jsonify({"error": "Stop the running scan before deleting it."}), 409
        row = store.get_scan(scan_id)
        if not row:
            return jsonify({"error": "Scan not found."}), 404
        if row.get("status") in {"queued", "running"}:
            return jsonify({"error": "That scan is still running."}), 409
        deleted = store.delete_scan(scan_id)
        if not deleted:
            return jsonify({"error": "Scan could not be deleted."}), 409
        manager.jobs.pop(scan_id, None)
        return jsonify({"deleted": scan_id})

    @app.get("/api/scans/<scan_id>/export")
    def export_scan(scan_id: str) -> Response:
        fmt = request.args.get("format", "json").lower()
        job = manager.jobs.get(scan_id)
        if job and job.status in {"queued", "running", "cancelling"}:
            return jsonify({"error": "Wait for the scan to finish before exporting."}), 409
        record = store.get_scan(scan_id)
        if not record:
            return jsonify({"error": "Scan not found."}), 404
        record.pop("log", None)
        stamp = (record.get("createdAt") or "")[:19].replace(":", "").replace("-", "")
        filename_base = f"recondeck-{record['kind']}-{stamp or scan_id}"
        if fmt == "json":
            payload = json.dumps(record, indent=2)
            return Response(
                payload,
                mimetype="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename_base}.json"'
                },
            )
        if fmt == "csv":
            payload = _scan_csv(record)
            return Response(
                payload,
                mimetype="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename_base}.csv"'
                },
            )
        if fmt == "txt":
            full = store.get_scan(scan_id) or record
            payload = (
                f"ReconDeck scan {scan_id}\n"
                f"Target: {record['target']}\n"
                f"Profile: {record.get('profile')}\n"
                f"Engine: {record.get('engine')}\n"
                f"Command: {record.get('command')}\n"
                f"Status: {record.get('status')}\n\n"
                f"{full.get('log', '')}\n"
            )
            return Response(
                payload,
                mimetype="text/plain",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename_base}.log.txt"'
                },
            )
        return jsonify({"error": "Choose JSON, CSV, or TXT format."}), 400

    @app.errorhandler(404)
    def not_found(error: Exception) -> Response:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found."}), 404
        return Response("Not found", status=404)

    @app.errorhandler(413)
    def too_large(error: Exception) -> Response:
        return jsonify({"error": "Request is too large."}), 413

    @app.errorhandler(500)
    def internal_error(error: Exception) -> Response:
        if request.path.startswith("/api/"):
            return jsonify({"error": "ReconDeck hit an internal error. Check the server log."}), 500
        return Response("Internal error", status=500)

    return app


def _status_for(code: str) -> int:
    if code in {"tool_missing", "privilege_required"}:
        return 403
    if code == "scan_busy":
        return 409
    return 400


def _int_arg(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = request.args.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _cell(value: Any) -> str:
    """Prevent spreadsheet formula execution in exported CSV cells."""
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _inventory_csv(hosts: list[dict[str, Any]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "address",
            "hostname",
            "mac",
            "vendor",
            "open_port_count",
            "risk_flags",
            "port",
            "protocol",
            "service",
            "product",
            "version",
            "exposure",
            "exposure_note",
            "category",
            "category_label",
            "cleartext",
            "last_seen",
            "last_port_scan_at",
        ]
    )
    for host in hosts:
        ports = host.get("ports") or [{}]
        if not ports:
            ports = [{}]
        for port in ports:
            risk = port.get("risk") or {}
            writer.writerow(
                [
                    _cell(host.get("address")),
                    _cell(host.get("hostname")),
                    _cell(host.get("mac")),
                    _cell(host.get("vendor")),
                    _cell(host.get("openPorts")),
                    _cell(host.get("riskFlags")),
                    _cell(port.get("port")),
                    _cell(port.get("protocol")),
                    _cell(port.get("service")),
                    _cell(port.get("product")),
                    _cell(port.get("version")),
                    _cell(risk.get("label")),
                    _cell(risk.get("note")),
                    _cell(risk.get("category")),
                    _cell(risk.get("categoryLabel")),
                    _cell("yes" if risk.get("cleartext") else "no"),
                    _cell(host.get("lastSeen")),
                    _cell(host.get("lastPortScanAt")),
                ]
            )
    return output.getvalue()


def _scan_csv(record: dict[str, Any]) -> str:
    results = record.get("results") or {}
    hosts = results.get("hosts", [])
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "scan_id",
            "kind",
            "target",
            "engine",
            "host_address",
            "hostname",
            "mac",
            "vendor",
            "port",
            "protocol",
            "state",
            "service",
            "product",
            "version",
            "exposure",
            "exposure_note",
        ]
    )
    for host in hosts:
        ports = host.get("ports") or [{}]
        if not ports:
            ports = [{}]
        for port in ports:
            risk = port.get("risk") or {}
            writer.writerow(
                [
                    _cell(record.get("id")),
                    _cell(record.get("kind")),
                    _cell(record.get("target")),
                    _cell(record.get("engine")),
                    _cell(host.get("address")),
                    _cell(host.get("hostname")),
                    _cell(host.get("mac")),
                    _cell(host.get("vendor")),
                    _cell(port.get("port")),
                    _cell(port.get("protocol")),
                    _cell(port.get("state")),
                    _cell(port.get("service")),
                    _cell(port.get("product")),
                    _cell(port.get("version")),
                    _cell(risk.get("label")),
                    _cell(risk.get("note")),
                ]
            )
    if not hosts:
        writer.writerow(
            [
                _cell(record.get("id")),
                _cell(record.get("kind")),
                _cell(record.get("target")),
                _cell(record.get("engine")),
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ]
        )
    return output.getvalue()
