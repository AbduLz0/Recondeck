"""SQLite persistence for scans and the observed-host inventory."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .risk import count_attention


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self.mark_interrupted_scans()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=8)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    duration REAL,
                    command TEXT,
                    error TEXT,
                    summary TEXT,
                    results TEXT,
                    log TEXT,
                    request TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_scans_created
                    ON scans(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_scans_status
                    ON scans(status);

                CREATE TABLE IF NOT EXISTS hosts (
                    address TEXT PRIMARY KEY,
                    hostname TEXT,
                    mac TEXT,
                    vendor TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_scan_id TEXT,
                    open_ports_count INTEGER NOT NULL DEFAULT 0,
                    risk_count INTEGER NOT NULL DEFAULT 0,
                    ports TEXT,
                    port_stats TEXT,
                    last_port_scan_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_hosts_last_seen
                    ON hosts(last_seen DESC);
                """
            )
            self._migrate_host_columns(conn)

    @staticmethod
    def _migrate_host_columns(conn: sqlite3.Connection) -> None:
        existing = {
            row["name"] for row in conn.execute("PRAGMA table_info(hosts)").fetchall()
        }
        for name, definition in {
            "port_stats": "TEXT",
            "last_port_scan_at": "TEXT",
        }.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE hosts ADD COLUMN {name} {definition}")
        # Upgrade evidence from an earlier ReconDeck schema. Older versions
        # stored open ports but not the port-scan timestamp or coverage counts.
        conn.execute(
            """
            UPDATE hosts
            SET last_port_scan_at = last_seen
            WHERE last_port_scan_at IS NULL
              AND ports IS NOT NULL
              AND ports NOT IN ('', '[]')
            """
        )

    def create_scan(self, record: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans
                    (id, kind, target, profile, engine, status, created_at,
                     started_at, finished_at, duration, command, error, summary,
                     results, log, request)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["kind"],
                    record["target"],
                    record["profile"],
                    record["engine"],
                    record["status"],
                    record["created_at"],
                    record.get("started_at"),
                    record.get("finished_at"),
                    record.get("duration"),
                    record.get("command", ""),
                    record.get("error"),
                    json.dumps(record.get("summary") or {}),
                    None,
                    record.get("log", ""),
                    json.dumps(record.get("request") or {}),
                ),
            )

    def mark_running(self, scan_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status = 'running', started_at = ? WHERE id = ?",
                (utc_now(), scan_id),
            )

    def finish_scan(
        self,
        scan_id: str,
        *,
        status: str,
        started_at: str | None,
        finished_at: str,
        duration: float,
        summary: dict[str, Any],
        results: dict[str, Any] | None,
        error: str | None,
        log: str,
        request: dict[str, Any],
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE scans SET status = ?, started_at = ?, finished_at = ?,
                    duration = ?, summary = ?, results = ?, error = ?, log = ?,
                    request = ?
                WHERE id = ?
                """,
                (
                    status,
                    started_at,
                    finished_at,
                    duration,
                    json.dumps(summary),
                    json.dumps(results) if results is not None else None,
                    error,
                    log,
                    json.dumps(request),
                    scan_id,
                ),
            )
            if results and status == "completed":
                self._update_inventory(conn, scan_id, results, finished_at)

    def _update_inventory(
        self,
        conn: sqlite3.Connection,
        scan_id: str,
        results: dict[str, Any],
        seen_at: str,
    ) -> None:
        is_port_scan = results.get("kind") == "ports"
        for host in results.get("hosts", []):
            address = host.get("address")
            if not address:
                continue
            existing = conn.execute(
                "SELECT * FROM hosts WHERE address = ?", (address,)
            ).fetchone()
            discovered_ports = host.get("ports") or []
            discovered_stats = host.get("portStats") if is_port_scan else None
            if existing:
                stored_ports = _loads(existing["ports"], [])
                stored_stats = _loads(existing["port_stats"], None)
                # The asset view reflects the most recent port scan, including a
                # scan that found zero open ports. Discovery only refreshes identity
                # data and leaves prior port evidence intact. Full scan history is
                # still available separately through the asset endpoint.
                ports_for_inventory = discovered_ports if is_port_scan else stored_ports
                port_stats_for_inventory = (
                    discovered_stats
                    if is_port_scan and discovered_stats is not None
                    else stored_stats
                )
                last_port_scan_at = (
                    seen_at if is_port_scan else existing["last_port_scan_at"]
                )
                hostname = host.get("hostname") or existing["hostname"]
                mac = host.get("mac") or existing["mac"]
                vendor = host.get("vendor") or existing["vendor"]
                first_seen = existing["first_seen"]
                last_scan_id = scan_id if is_port_scan else existing["last_scan_id"]
            else:
                ports_for_inventory = discovered_ports
                port_stats_for_inventory = discovered_stats
                last_port_scan_at = seen_at if is_port_scan else None
                hostname = host.get("hostname")
                mac = host.get("mac")
                vendor = host.get("vendor")
                first_seen = seen_at
                last_scan_id = scan_id

            conn.execute(
                """
                INSERT INTO hosts
                    (address, hostname, mac, vendor, first_seen, last_seen,
                     last_scan_id, open_ports_count, risk_count, ports,
                     port_stats, last_port_scan_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(address) DO UPDATE SET
                    hostname = excluded.hostname,
                    mac = excluded.mac,
                    vendor = excluded.vendor,
                    last_seen = excluded.last_seen,
                    last_scan_id = excluded.last_scan_id,
                    open_ports_count = excluded.open_ports_count,
                    risk_count = excluded.risk_count,
                    ports = excluded.ports,
                    port_stats = excluded.port_stats,
                    last_port_scan_at = excluded.last_port_scan_at
                """,
                (
                    address,
                    hostname,
                    mac,
                    vendor,
                    first_seen,
                    seen_at,
                    last_scan_id,
                    len(ports_for_inventory),
                    count_attention(ports_for_inventory),
                    json.dumps(ports_for_inventory),
                    json.dumps(port_stats_for_inventory)
                    if port_stats_for_inventory is not None
                    else None,
                    last_port_scan_at,
                ),
            )

    def mark_interrupted_scans(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = 'interrupted', finished_at = ?,
                    error = 'ReconDeck stopped before this scan finished.'
                WHERE status IN ('queued', 'running')
                """,
                (utc_now(),),
            )

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_from_row(row) if row else None

    def list_scans(
        self,
        *,
        limit: int = 50,
        kind: str | None = None,
        status: str | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if kind in {"discover", "ports"}:
            clauses.append("kind = ?")
            values.append(kind)
        if status in {"completed", "failed", "cancelled", "running", "interrupted"}:
            clauses.append("status = ?")
            values.append(status)
        if query:
            clauses.append("(target LIKE ? OR profile LIKE ? OR engine LIKE ?)")
            like = f"%{query[:100]}%"
            values.extend([like, like, like])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(max(1, min(limit, 200)))
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT id, kind, target, profile, engine, status, created_at,
                       started_at, finished_at, duration, command, error, summary,
                       request
                FROM scans {where}
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                values,
            ).fetchall()
        return [self._scan_from_row(row) for row in rows]

    def active_scan(self) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, kind, target, profile, engine, status, created_at,
                       started_at, finished_at, duration, command, error, summary,
                       request
                FROM scans WHERE status IN ('queued', 'running')
                ORDER BY created_at DESC, rowid DESC LIMIT 1
                """
            ).fetchone()
        return self._scan_from_row(row) if row else None

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM scans WHERE id = ? AND status NOT IN ('queued', 'running')",
                (scan_id,),
            )
            deleted = cur.rowcount > 0
            if deleted:
                self._rebuild_inventory(conn)
        return deleted

    def _rebuild_inventory(self, conn: sqlite3.Connection) -> None:
        """Recompute observed hosts from the scans that remain in history."""
        conn.execute("DELETE FROM hosts")
        rows = conn.execute(
            """
            SELECT id, results, finished_at FROM scans
            WHERE status = 'completed' AND results IS NOT NULL
            ORDER BY finished_at ASC, created_at ASC
            """
        ).fetchall()
        for row in rows:
            self._update_inventory(
                conn, row["id"], _loads(row["results"], {}), row["finished_at"] or utc_now()
            )

    def stats(self) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            totals = conn.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
                    MAX(created_at) AS last_scan
                FROM scans
                """
            ).fetchone()
            host_totals = conn.execute(
                """
                SELECT COUNT(*) AS hosts,
                       COALESCE(SUM(open_ports_count), 0) AS open_ports,
                       COALESCE(SUM(risk_count), 0) AS risk_flags
                FROM hosts
                """
            ).fetchone()
            inventory = conn.execute("SELECT ports FROM hosts").fetchall()
            scan_rows = conn.execute(
                "SELECT created_at, kind, status FROM scans ORDER BY created_at ASC"
            ).fetchall()

        service_counts: dict[str, int] = {}
        for row in inventory:
            for port in _loads(row["ports"], []):
                name = port.get("service") or f"port {port.get('port', '?')}"
                service_counts[name] = service_counts.get(name, 0) + 1
        services = [
            {"name": name, "count": count}
            for name, count in sorted(
                service_counts.items(), key=lambda item: (-item[1], item[0])
            )[:6]
        ]

        local_zone = datetime.now().astimezone().tzinfo
        today = datetime.now().astimezone().date()
        activity = []
        for offset in range(6, -1, -1):
            day = today - timedelta(days=offset)
            count = 0
            for row in scan_rows:
                try:
                    created = datetime.fromisoformat(row["created_at"]).astimezone(local_zone)
                    if created.date() == day:
                        count += 1
                except (TypeError, ValueError):
                    continue
            activity.append({"date": day.isoformat(), "count": count})

        return {
            "totalScans": totals["total"] or 0,
            "completedScans": totals["completed"] or 0,
            "failedScans": totals["failed"] or 0,
            "hosts": host_totals["hosts"] or 0,
            "openPorts": host_totals["open_ports"] or 0,
            "riskFlags": host_totals["risk_flags"] or 0,
            "lastScan": totals["last_scan"],
            "services": services,
            "activity": activity,
        }

    def inventory(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM hosts ORDER BY last_seen DESC LIMIT ?",
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [self._host_from_row(row) for row in rows]

    @staticmethod
    def _host_from_row(row: sqlite3.Row) -> dict[str, Any]:
        ports = _loads(row["ports"], [])
        keys = set(row.keys())
        return {
            "address": row["address"],
            "hostname": row["hostname"],
            "mac": row["mac"],
            "vendor": row["vendor"],
            "firstSeen": row["first_seen"],
            "lastSeen": row["last_seen"],
            "lastScanId": row["last_scan_id"],
            "openPorts": row["open_ports_count"],
            "riskFlags": row["risk_count"],
            "ports": ports[:256],
            "portStats": _loads(row["port_stats"], None) if "port_stats" in keys else None,
            "lastPortScanAt": row["last_port_scan_at"]
            if "last_port_scan_at" in keys
            else None,
        }

    def asset(self, address: str) -> dict[str, Any] | None:
        """Return one host plus the recent scans that observed it."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM hosts WHERE address = ?", (address,)
            ).fetchone()
            if not row:
                return None
            scan_rows = conn.execute(
                """
                SELECT id, kind, target, profile, engine, status, created_at,
                       finished_at, duration, summary, results
                FROM scans
                WHERE status = 'completed' AND results IS NOT NULL
                ORDER BY COALESCE(finished_at, created_at) DESC, rowid DESC
                LIMIT 200
                """
            ).fetchall()
        history: list[dict[str, Any]] = []
        for scan_row in scan_rows:
            results = _loads(scan_row["results"], {}) or {}
            host_entry = next(
                (
                    host
                    for host in results.get("hosts", [])
                    if host.get("address") == address
                ),
                None,
            )
            if host_entry is None:
                continue
            summary = _loads(scan_row["summary"], {}) or {}
            history.append(
                {
                    "id": scan_row["id"],
                    "kind": scan_row["kind"],
                    "target": scan_row["target"],
                    "profile": scan_row["profile"],
                    "engine": scan_row["engine"],
                    "status": scan_row["status"],
                    "createdAt": scan_row["created_at"],
                    "finishedAt": scan_row["finished_at"],
                    "duration": scan_row["duration"],
                    "summary": summary,
                    "openPorts": len(host_entry.get("ports") or []),
                    "portStats": host_entry.get("portStats"),
                    "hostname": host_entry.get("hostname"),
                }
            )
            if len(history) >= 14:
                break
        return {"host": self._host_from_row(row), "scans": history}

    @staticmethod
    def _scan_from_row(row: sqlite3.Row) -> dict[str, Any]:
        keys = set(row.keys())
        summary = _loads(row["summary"], {}) if "summary" in keys else {}
        results = _loads(row["results"], None) if "results" in keys and row["results"] else None
        log = row["log"] if "log" in keys and row["log"] else ""
        record = {
            "id": row["id"],
            "kind": row["kind"],
            "target": row["target"],
            "profile": row["profile"],
            "engine": row["engine"],
            "status": row["status"],
            "createdAt": row["created_at"],
            "startedAt": row["started_at"],
            "finishedAt": row["finished_at"],
            "duration": row["duration"],
            "command": row["command"],
            "error": row["error"],
            "summary": summary,
            "request": _loads(row["request"], {}) if "request" in keys else {},
            "hasResults": results is not None,
        }
        if results is not None:
            record["results"] = results
        if log:
            record["log"] = log
        return record


def _loads(value: Any, fallback: Any) -> Any:
    if value is None or value == "":
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback
