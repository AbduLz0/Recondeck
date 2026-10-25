"""Fast, local-only tests for ReconDeck's safety-critical pieces."""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from recondeck import create_app  # noqa: E402
from recondeck.risk import assess_service  # noqa: E402
from recondeck.scanner import (  # noqa: E402
    ScanError,
    parse_arp_scan,
    parse_nmap_xml,
    prepare_scan,
    validate_discovery_target,
    validate_port_target,
    validate_ports,
)
from recondeck.store import Store, utc_now  # noqa: E402


SYSTEM = {
    "tools": {
        "nmap": {
            "available": True,
            "path": "/usr/bin/nmap",
            "version": "7.94TEST",
            "raw_access": False,
        },
        "arp_scan": {
            "available": True,
            "path": "/usr/sbin/arp-scan",
            "version": "1.10.0",
            "usable": False,
        },
    },
    "interfaces": [
        {
            "name": "eth-test",
            "address": "192.0.2.10",
            "prefix": 24,
            "network": "192.0.2.0",
            "cidr": "192.0.2.0/24",
            "isDefault": True,
        }
    ],
    "rawAccess": False,
    "privileged": False,
}

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94TEST">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.0.2.20" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Devices"/>
    <hostnames><hostname name="lab.example.test" type="PTR"/></hostnames>
    <ports>
      <extraports state="closed" count="998"/>
      <port protocol="tcp" portid="23">
        <state state="open" reason="syn-ack"/>
        <service name="telnet" product="BusyBox" version="1.2" extrainfo="test banner">
          <cpe>cpe:/a:example:busybox:1.2</cpe>
        </service>
        <script id="banner" output="BusyBox telnetd"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.4" accuracy="92"/></os>
    <times srtt="1200"/>
  </host>
</nmaprun>
"""

SAMPLE_ARP = """Interface: eth-test, type: EN10MB, MAC: 00:11:22:33:44:55, IPv4: 192.0.2.10
Starting arp-scan 1.10.0 with 256 hosts
192.0.2.1\t00:11:22:33:44:55\tExample Router
192.0.2.20\taa:bb:cc:dd:ee:ff\t(DUP: 2) Example Devices
192.0.2.20\taa:bb:cc:dd:ee:ff\t(DUP: 1) Example Devices
Ending arp-scan 1.10.0: 256 hosts scanned in 2.2 seconds
"""


class ValidationTests(unittest.TestCase):
    def test_accepts_expected_targets(self):
        self.assertEqual(validate_discovery_target("192.0.2.1"), "192.0.2.1")
        self.assertEqual(validate_discovery_target("192.0.2.0/30"), "192.0.2.0/30")
        self.assertEqual(validate_port_target("localhost"), "localhost")
        self.assertEqual(validate_port_target("192.0.2.1-10"), "192.0.2.1-10")

    def test_rejects_shell_and_unsafe_targets(self):
        for target in [
            "127.0.0.1; rm -rf /",
            "127.0.0.1 && whoami",
            "$(whoami)",
            "`id`",
            "127.0.0.1\n--script=evil",
            "-oN/tmp/out",
            "http://example.test",
        ]:
            with self.subTest(target=target):
                with self.assertRaises(ScanError):
                    validate_port_target(target)

    def test_rejects_oversized_targets(self):
        with self.assertRaises(ScanError):
            validate_discovery_target("10.0.0.0/8")
        with self.assertRaises(ScanError):
            validate_port_target("10.0.0.0/16")

    def test_port_specs(self):
        spec, count = validate_ports("22,80,443,8000-8005")
        self.assertEqual(spec, "22,80,443,8000-8005")
        self.assertEqual(count, 9)
        for spec in ["", "0", "65536", "80-22", "22,", "22;id", "-1"]:
            with self.subTest(spec=spec):
                with self.assertRaises(ScanError):
                    validate_ports(spec)

    def test_commands_are_fixed_argument_lists(self):
        config = prepare_scan(
            {"kind": "ports", "target": "192.0.2.20", "profile": "quick"},
            SYSTEM,
        )
        try:
            self.assertIsInstance(config.command, list)
            self.assertNotIn(";", " ".join(config.command))
            self.assertEqual(config.command[-1], "192.0.2.20")
            self.assertIn("-sT", config.command)
            self.assertIn("-oX", config.command)
        finally:
            config.cleanup()

    def test_safe_audit_uses_curated_scripts(self):
        config = prepare_scan(
            {
                "kind": "ports",
                "target": "192.0.2.20",
                "profile": "safe",
                "options": {"scripts": True, "serviceDetection": True},
            },
            SYSTEM,
        )
        try:
            joined = " ".join(config.command)
            self.assertIn("--script=banner,http-title,http-headers", joined)
            self.assertIn("ssl-cert", joined)
            self.assertNotIn("--script=default", joined)
            self.assertNotIn("exploit", joined)
            self.assertEqual(config.request["options"]["safeChecks"], True)
            self.assertEqual(config.request["options"]["scripts"], False)
        finally:
            config.cleanup()

    def test_service_categories(self):
        ftp = assess_service(21, "ftp")
        self.assertEqual(ftp["category"], "file-sharing")
        self.assertTrue(ftp["cleartext"])
        rdp = assess_service(3389, "ms-wbt-server")
        self.assertEqual(rdp["category"], "remote-access")
        self.assertEqual(rdp["level"], "high")
        ipp = assess_service(631, "ipp")
        self.assertEqual(ipp["category"], "printing")
        self.assertFalse(ipp["cleartext"])

    def test_privileged_features_are_refused_without_raw_access(self):
        with self.assertRaises(ScanError) as caught:
            prepare_scan(
                {
                    "kind": "ports",
                    "target": "192.0.2.20",
                    "profile": "quick",
                    "options": {"osDetection": True},
                },
                SYSTEM,
            )
        self.assertEqual(caught.exception.code, "privilege_required")

        with self.assertRaises(ScanError) as caught:
            prepare_scan(
                {"kind": "discover", "target": "192.0.2.0/24", "engine": "arp"},
                SYSTEM,
            )
        self.assertEqual(caught.exception.code, "privilege_required")


class ParserTests(unittest.TestCase):
    def test_nmap_xml_parser(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
            handle.write(SAMPLE_NMAP_XML)
            path = Path(handle.name)
        try:
            results, summary = parse_nmap_xml(path, "ports")
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(summary["hostsFound"], 1)
        self.assertEqual(summary["openPorts"], 1)
        self.assertEqual(summary["attention"], 1)
        host = results["hosts"][0]
        self.assertEqual(host["address"], "192.0.2.20")
        self.assertEqual(host["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(host["vendor"], "Example Devices")
        self.assertEqual(host["ports"][0]["service"], "telnet")
        self.assertEqual(host["ports"][0]["risk"]["level"], "high")
        self.assertEqual(host["ports"][0]["risk"]["category"], "remote-access")
        self.assertTrue(host["ports"][0]["risk"]["cleartext"])
        self.assertEqual(host["ports"][0]["scripts"][0]["output"], "BusyBox telnetd")
        self.assertEqual(host["portStats"]["open"], 1)
        self.assertEqual(host["portStats"]["closed"], 999)
        self.assertEqual(host["portStats"]["scanned"], 1000)
        self.assertEqual(host["os"][0]["accuracy"], 92)

    def test_arp_parser_deduplicates_and_strips_duplicate_tag(self):
        results, summary = parse_arp_scan(SAMPLE_ARP)
        self.assertEqual(summary["hostsFound"], 2)
        self.assertEqual(results["hosts"][1]["vendor"], "Example Devices")
        self.assertEqual(results["hosts"][1]["address"], "192.0.2.20")


class MigrationTests(unittest.TestCase):
    def test_old_schema_is_upgraded_without_losing_hosts(self):
        import sqlite3

        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "legacy.db"
            conn = sqlite3.connect(db)
            conn.executescript(
                """
                CREATE TABLE scans (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL,
                    profile TEXT NOT NULL, engine TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                    duration REAL, command TEXT, error TEXT, summary TEXT,
                    results TEXT, log TEXT, request TEXT
                );
                CREATE TABLE hosts (
                    address TEXT PRIMARY KEY, hostname TEXT, mac TEXT, vendor TEXT,
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                    last_scan_id TEXT, open_ports_count INTEGER NOT NULL DEFAULT 0,
                    risk_count INTEGER NOT NULL DEFAULT 0, ports TEXT
                );
                INSERT INTO hosts
                    (address, hostname, first_seen, last_seen, open_ports_count, ports)
                VALUES
                    ('192.0.2.40', 'legacy.test', '2026-01-01T00:00:00+00:00',
                     '2026-01-01T00:10:00+00:00', 1,
                     '[{"port": 80, "protocol": "tcp", "service": "http"}]');
                """
            )
            conn.commit()
            conn.close()
            store = Store(db)
            host = store.inventory()[0]
            self.assertEqual(host["address"], "192.0.2.40")
            self.assertEqual(host["openPorts"], 1)
            self.assertIsNotNone(host["lastPortScanAt"])
            self.assertIsNone(host["portStats"])
            asset = store.asset("192.0.2.40")
            self.assertEqual(asset["host"]["hostname"], "legacy.test")

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.db")
        self.now = utc_now()

    def tearDown(self):
        self.temp.cleanup()

    def _scan(self, scan_id, kind, results):
        self.store.create_scan(
            {
                "id": scan_id,
                "kind": kind,
                "target": "192.0.2.20",
                "profile": "discover" if kind == "discover" else "quick",
                "engine": "nmap",
                "status": "running",
                "created_at": self.now,
                "command": "nmap test",
                "request": {"kind": kind},
            }
        )
        self.store.finish_scan(
            scan_id,
            status="completed",
            started_at=self.now,
            finished_at=utc_now(),
            duration=0.2,
            summary=results["summary"],
            results=results,
            error=None,
            log="scan complete",
            request={"kind": kind},
        )

    def test_inventory_merges_identity_and_port_data(self):
        discovery = {
            "kind": "discover",
            "hosts": [
                {
                    "address": "192.0.2.20",
                    "hostname": "lab.example.test",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "vendor": "Example Devices",
                    "ports": [],
                }
            ],
            "summary": {"hostsFound": 1},
        }
        port_scan = {
            "kind": "ports",
            "hosts": [
                {
                    "address": "192.0.2.20",
                    "hostname": "lab.example.test",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "service": "ssh",
                            "risk": {"level": "low", "label": "Remote shell", "note": "test"},
                        }
                    ],
                    "portStats": {
                        "open": 1,
                        "closed": 99,
                        "filtered": 0,
                        "other": 0,
                        "unfiltered": 0,
                        "scanned": 100,
                    },
                }
            ],
            "summary": {"hostsFound": 1, "openPorts": 1},
        }
        self._scan("disc-1", "discover", discovery)
        self._scan("ports-1", "ports", port_scan)
        hosts = self.store.inventory()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["hostname"], "lab.example.test")
        self.assertEqual(hosts[0]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(hosts[0]["openPorts"], 1)
        self.assertEqual(hosts[0]["portStats"]["scanned"], 100)
        self.assertIsNotNone(hosts[0]["lastPortScanAt"])
        asset = self.store.asset("192.0.2.20")
        self.assertIsNotNone(asset)
        self.assertEqual(len(asset["scans"]), 2)
        self.assertEqual(asset["scans"][0]["portStats"]["open"], 1)
        stats = self.store.stats()
        self.assertEqual(stats["completedScans"], 2)
        self.assertEqual(stats["openPorts"], 1)

    def test_latest_port_scan_replaces_asset_ports(self):
        discovery = {
            "kind": "discover",
            "hosts": [
                {
                    "address": "192.0.2.20",
                    "hostname": "lab.example.test",
                    "ports": [],
                }
            ],
            "summary": {"hostsFound": 1},
        }
        open_scan = {
            "kind": "ports",
            "hosts": [
                {
                    "address": "192.0.2.20",
                    "ports": [
                        {
                            "port": 631,
                            "protocol": "tcp",
                            "service": "ipp",
                            "risk": {
                                "level": "low",
                                "label": "Print service",
                                "category": "printing",
                            },
                        }
                    ],
                    "portStats": {
                        "open": 1,
                        "closed": 99,
                        "filtered": 0,
                        "other": 0,
                        "unfiltered": 0,
                        "scanned": 100,
                    },
                }
            ],
            "summary": {"hostsFound": 1, "openPorts": 1},
        }
        empty_scan = {
            "kind": "ports",
            "hosts": [
                {
                    "address": "192.0.2.20",
                    "ports": [],
                    "portStats": {
                        "open": 0,
                        "closed": 100,
                        "filtered": 0,
                        "other": 0,
                        "unfiltered": 0,
                        "scanned": 100,
                    },
                }
            ],
            "summary": {"hostsFound": 1, "openPorts": 0},
        }
        self._scan("disc-1", "discover", discovery)
        self._scan("ports-1", "ports", open_scan)
        self._scan("ports-2", "ports", empty_scan)
        host = self.store.inventory()[0]
        self.assertEqual(host["openPorts"], 0)
        self.assertEqual(host["ports"], [])
        self.assertEqual(host["portStats"]["scanned"], 100)
        asset = self.store.asset("192.0.2.20")
        self.assertEqual(len(asset["scans"]), 3)

    def test_delete_scan_rebuilds_inventory(self):
        discovery = {
            "kind": "discover",
            "hosts": [
                {
                    "address": "192.0.2.20",
                    "hostname": "lab.example.test",
                    "ports": [],
                }
            ],
            "summary": {"hostsFound": 1},
        }
        self._scan("disc-1", "discover", discovery)
        self.assertEqual(len(self.store.inventory()), 1)
        self.assertTrue(self.store.delete_scan("disc-1"))
        self.assertEqual(self.store.inventory(), [])


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app(data_dir=self.temp.name)
        self.client = self.app.test_client()
        self.token = self.app.config["API_TOKEN"]
        probe = self.app.extensions["recondeck_probe"]
        probe._cached = SYSTEM
        probe._cached_at = time.monotonic()

    def tearDown(self):
        self.temp.cleanup()

    def request(self, method, path, **kwargs):
        headers = kwargs.pop("headers", {})
        headers.setdefault("X-ReconDeck-Token", self.token)
        kwargs.setdefault("environ_base", {"REMOTE_ADDR": "127.0.0.1"})
        return self.client.open(path, method=method, headers=headers, **kwargs)

    def test_local_index_contains_boot_token(self):
        response = self.client.get("/", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)
        self.assertIn('name="recon-token"', response.get_data(as_text=True))

    def test_api_requires_token(self):
        response = self.client.get(
            "/api/scans", environ_base={"REMOTE_ADDR": "127.0.0.1"}
        )
        self.assertEqual(response.status_code, 403)

    def test_rejects_unrecognised_host_header(self):
        response = self.request("GET", "/api/scans", headers={"Host": "evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_invalid_scan_is_rejected_before_process_start(self):
        response = self.request(
            "POST",
            "/api/scans",
            json={"kind": "ports", "target": "127.0.0.1;id", "profile": "quick"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("characters", response.get_json()["error"])

    def test_asset_endpoint_returns_evidence(self):
        store = self.app.extensions["recondeck_store"]
        now = utc_now()
        store.create_scan(
            {
                "id": "asset-scan-1",
                "kind": "ports",
                "target": "192.0.2.20",
                "profile": "safe",
                "engine": "nmap",
                "status": "running",
                "created_at": now,
                "command": "nmap safe",
                "request": {"kind": "ports", "profile": "safe"},
            }
        )
        store.finish_scan(
            "asset-scan-1",
            status="completed",
            started_at=now,
            finished_at=now,
            duration=1.2,
            summary={"hostsFound": 1, "openPorts": 1},
            results={
                "kind": "ports",
                "hosts": [
                    {
                        "address": "192.0.2.20",
                        "hostname": "lab.example.test",
                        "ports": [
                            {
                                "port": 445,
                                "protocol": "tcp",
                                "service": "microsoft-ds",
                                "risk": {
                                    "level": "high",
                                    "label": "SMB",
                                    "category": "file-sharing",
                                    "categoryLabel": "File sharing",
                                },
                            }
                        ],
                        "portStats": {
                            "open": 1,
                            "closed": 999,
                            "filtered": 0,
                            "other": 0,
                            "unfiltered": 0,
                            "scanned": 1000,
                        },
                    }
                ],
                "summary": {"hostsFound": 1, "openPorts": 1},
            },
            error=None,
            log="safe audit complete",
            request={"kind": "ports", "profile": "safe"},
        )
        detail = self.request("GET", "/api/assets/192.0.2.20")
        self.assertEqual(detail.status_code, 200)
        asset = detail.get_json()["asset"]
        self.assertEqual(asset["host"]["openPorts"], 1)
        self.assertEqual(asset["host"]["portStats"]["scanned"], 1000)
        self.assertEqual(len(asset["scans"]), 1)
        self.assertEqual(asset["scans"][0]["profile"], "safe")
        exported = self.request("GET", "/api/inventory/export?format=csv")
        body = exported.get_data(as_text=True)
        self.assertIn("192.0.2.20", body)
        self.assertIn("file-sharing", body.lower())
        self.assertIn("File sharing", body)

    def test_missing_asset_and_empty_inventory_export(self):
        missing = self.request("GET", "/api/assets/192.0.2.99")
        self.assertEqual(missing.status_code, 404)
        exported = self.request("GET", "/api/inventory/export?format=csv")
        self.assertEqual(exported.status_code, 200)
        self.assertIn("address,hostname,mac", exported.get_data(as_text=True))
        self.assertIn("attachment", exported.headers.get("Content-Disposition", ""))

    def test_json_content_type_is_required(self):
        response = self.request(
            "POST",
            "/api/scans",
            data=json.dumps({"kind": "ports", "target": "127.0.0.1"}),
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 415)


if __name__ == "__main__":
    unittest.main()
