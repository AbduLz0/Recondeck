"""Scan orchestration, target validation, command construction and parsing.

Only a fixed set of Nmap / arp-scan invocations can be produced. Targets,
interfaces, profiles and ports are validated against allow-lists, and every
process is started with a list of arguments (never through a shell).
"""

from __future__ import annotations

import ipaddress
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .risk import assess_service
from .store import Store, utc_now


class ScanError(ValueError):
    def __init__(self, message: str, code: str = "invalid_request"):
        super().__init__(message)
        self.message = message
        self.code = code


class ScanBusy(ScanError):
    def __init__(self, active_id: str):
        super().__init__(
            "Another scan is already running. Wait for it to finish or stop it first.",
            "scan_busy",
        )
        self.active_id = active_id


SAFE_AUDIT_SCRIPTS = (
    "banner,http-title,http-headers,http-security-headers,http-methods,"
    "ssl-cert,ssl-enum-ciphers,ssh-hostkey,ssh-auth-methods,"
    "ssh2-enum-algos,smb-os-discovery"
)

PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "label": "Quick sweep",
        "description": "The 100 most common TCP ports.",
        "args": ["--top-ports", "100"],
        "max_hosts": 256,
        "timeout": 600,
    },
    "standard": {
        "label": "Standard sweep",
        "description": "The 1,000 most common TCP ports.",
        "args": ["--top-ports", "1000"],
        "max_hosts": 128,
        "timeout": 1200,
    },
    "full": {
        "label": "Deep sweep",
        "description": "Every TCP port, 1–65535.",
        "args": ["-p-"],
        "max_hosts": 8,
        "timeout": 3600,
    },
    "services": {
        "label": "Service audit",
        "description": "Top 1,000 ports with service and version detection.",
        "args": ["--top-ports", "1000", "-sV", "--version-light"],
        "max_hosts": 64,
        "timeout": 2400,
        "service_default": True,
    },
    "safe": {
        "label": "Safe audit",
        "description": "Top 1,000 ports with versions and curated non-intrusive NSE checks.",
        "args": [
            "--top-ports",
            "1000",
            "-sV",
            "--version-light",
            f"--script={SAFE_AUDIT_SCRIPTS}",
        ],
        "max_hosts": 16,
        "timeout": 3600,
        "service_default": True,
        "safe_checks": True,
    },
    "custom": {
        "label": "Custom ports",
        "description": "A port list or range that you specify.",
        "args": [],
        "max_hosts": 128,
        "timeout": 1800,
    },
}

TIMING = {
    "polite": "-T3",
    "normal": "-T4",
    "aggressive": "-T5",
}

DISCOVERY_MAX_HOSTS = 1024
PORT_MAX_HOSTS = 256

_CIDR_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$")
_RANGE_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$"
)
_SHORT_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_TARGET_SAFE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:/_\-]*$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")
_ARP_LINE_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s*(?P<rest>.*)$"
)
_PROGRESS_RE = re.compile(r"About\s+([\d.]+)%\s+done", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _make_temp_xml() -> Path:
    fd, temp_name = tempfile.mkstemp(prefix="recondeck-", suffix=".xml")
    os.close(fd)
    return Path(temp_name)


def _valid_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError as exc:
        raise ScanError(f"“{value}” is not a valid IPv4 address.") from exc


def _parse_range(value: str) -> tuple[str, str] | None:
    match = _RANGE_RE.match(value)
    if match:
        start = _valid_ipv4(match.group(1))
        end = _valid_ipv4(match.group(2))
        if int(ipaddress.IPv4Address(start)) > int(ipaddress.IPv4Address(end)):
            raise ScanError("The range start must not be greater than its end.")
        return start, end
    match = _SHORT_RANGE_RE.match(value)
    if match:
        base = _valid_ipv4(match.group(1))
        last = int(match.group(2))
        if last > 255:
            raise ScanError("A short IP range must end between 0 and 255.")
        start_ip = ipaddress.IPv4Address(base)
        start_octet = int(base.rsplit(".", 1)[1])
        if last < start_octet:
            raise ScanError("A short IP range must end at a number no lower than it starts.")
        end_ip = ipaddress.IPv4Address(
            str(start_ip).rsplit(".", 1)[0] + f".{last}"
        )
        return str(start_ip), str(end_ip)
    return None


def target_host_count(target: str) -> int:
    """Estimate how many addresses a target expression covers."""
    cidr = _CIDR_RE.match(target)
    if cidr:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ScanError(f"“{target}” is not a valid IPv4 network.") from exc
        return network.num_addresses
    ip_range = _parse_range(target)
    if ip_range:
        start, end = ip_range
        return int(ipaddress.IPv4Address(end)) - int(ipaddress.IPv4Address(start)) + 1
    try:
        ipaddress.IPv4Address(target)
        return 1
    except ValueError:
        return 1


def validate_discovery_target(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ScanError("Enter an IP address, IPv4 network, or address range.")
    target = raw.strip()
    if not target:
        raise ScanError("Enter a target to discover.")
    if len(target) > 64 or not _TARGET_SAFE_RE.match(target):
        raise ScanError("That target contains characters ReconDeck does not accept.")
    if _CIDR_RE.match(target):
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ScanError(f"“{target}” is not a valid IPv4 network.") from exc
        if network.version != 4:
            raise ScanError("Network discovery currently supports IPv4 networks only.")
        target = str(network)
        if network.num_addresses > DISCOVERY_MAX_HOSTS:
            raise ScanError(
                f"That network covers {network.num_addresses:,} addresses. "
                f"Discovery is capped at {DISCOVERY_MAX_HOSTS:,}."
            )
        return target
    try:
        return _valid_ipv4(target)
    except ScanError:
        pass
    ip_range = _parse_range(target)
    if ip_range:
        count = target_host_count(target)
        if count > DISCOVERY_MAX_HOSTS:
            raise ScanError(
                f"That range covers {count:,} addresses. "
                f"Discovery is capped at {DISCOVERY_MAX_HOSTS:,}."
            )
        return target
    raise ScanError("Discovery targets must be an IPv4 address, network (CIDR), or range.")


def validate_port_target(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ScanError("Enter a hostname, IP address, or IPv4 network.")
    target = raw.strip()
    if not target:
        raise ScanError("Enter a target to scan.")
    if len(target) > 80 or not _TARGET_SAFE_RE.match(target):
        raise ScanError("That target contains characters ReconDeck does not accept.")
    if _CIDR_RE.match(target):
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ScanError(f"“{target}” is not a valid IPv4 network.") from exc
        if network.version != 4:
            raise ScanError("Port scanning currently supports IPv4 targets only.")
        target = str(network)
        if network.num_addresses > PORT_MAX_HOSTS:
            raise ScanError(
                f"That network covers {network.num_addresses:,} addresses. "
                f"Port scans are capped at {PORT_MAX_HOSTS} addresses."
            )
        return target
    try:
        return _valid_ipv4(target)
    except ScanError:
        pass
    if _parse_range(target):
        if target_host_count(target) > PORT_MAX_HOSTS:
            raise ScanError(f"Port scans are capped at {PORT_MAX_HOSTS} addresses.")
        return target
    if not _HOSTNAME_RE.match(target):
        raise ScanError("Enter a valid hostname, IPv4 address, network, or address range.")
    return target


def validate_ports(raw: Any) -> tuple[str, int]:
    if not isinstance(raw, str) or not raw.strip():
        raise ScanError("Enter at least one port for a custom scan.")
    spec = raw.strip().replace(" ", "")
    if len(spec) > 512 or not re.match(r"^[\d,\-]+$", spec):
        raise ScanError("Ports must use numbers, commas and hyphens — for example 22,80,443.")
    seen: set[int] = set()
    for chunk in spec.split(","):
        if not chunk:
            raise ScanError("A port list contains an empty entry.")
        if "-" in chunk:
            parts = chunk.split("-")
            if len(parts) != 2 or not all(p.isdigit() for p in parts):
                raise ScanError(f"“{chunk}” is not a valid port range.")
            start, end = (int(p) for p in parts)
            if start > end:
                raise ScanError("A port range must start at a number no greater than its end.")
            if start < 1 or end > 65535:
                raise ScanError("Ports must be between 1 and 65535.")
            seen.update((start, end))
        else:
            if not chunk.isdigit():
                raise ScanError(f"“{chunk}” is not a valid port.")
            port = int(chunk)
            if port < 1 or port > 65535:
                raise ScanError("Ports must be between 1 and 65535.")
            seen.add(port)
    if not seen:
        raise ScanError("Enter at least one port.")
    return spec, _estimate_port_count(spec)


def _estimate_port_count(spec: str) -> int:
    total = 0
    for chunk in spec.split(","):
        if "-" in chunk:
            start, end = (int(p) for p in chunk.split("-", 1))
            total += end - start + 1
        else:
            total += 1
    return total


def _as_bool(value: Any) -> bool:
    return value is True or value == "true" or value == "on" or value == 1


def _pick_interface(interfaces: list[dict], target: str, requested: Any) -> dict | None:
    if isinstance(requested, str) and requested.strip():
        if not _INTERFACE_RE.match(requested.strip()):
            raise ScanError("That interface name is not valid.")
        for iface in interfaces:
            if iface["name"] == requested.strip():
                return iface
        raise ScanError(
            "The selected interface is no longer available. Refresh and try again."
        )
    try:
        network = ipaddress.ip_network(target, strict=False)
        first = network.network_address
    except ValueError:
        ip_range = _parse_range(target)
        first = ipaddress.IPv4Address(ip_range[0]) if ip_range else None
    if first is not None:
        for iface in interfaces:
            try:
                if iface.get("network") and ipaddress.IPv4Address(first) in ipaddress.ip_network(
                    iface["network"], strict=False
                ):
                    return iface
            except ValueError:
                continue
    return next((i for i in interfaces if i.get("isDefault")), interfaces[0] if interfaces else None)


def _target_is_local(target: str, interfaces: list[dict]) -> bool:
    try:
        network = ipaddress.ip_network(target, strict=False)
        first = network.network_address
    except ValueError:
        ip_range = _parse_range(target)
        if not ip_range:
            return False
        first = ipaddress.IPv4Address(ip_range[0])
    for iface in interfaces:
        if iface.get("network"):
            try:
                if ipaddress.IPv4Address(first) in ipaddress.ip_network(
                    iface["network"], strict=False
                ):
                    return True
            except ValueError:
                continue
    return False


@dataclass
class ScanConfig:
    kind: str
    target: str
    profile: str
    engine: str
    command: list[str]
    command_preview: str
    timeout: int
    request: dict[str, Any]
    interface: str | None = None
    profile_label: str = ""
    temp_path: Path | None = None
    notes: list[str] = field(default_factory=list)

    def cleanup(self) -> None:
        if self.temp_path:
            try:
                self.temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def prepare_scan(data: dict[str, Any], system: dict[str, Any]) -> ScanConfig:
    if not isinstance(data, dict):
        raise ScanError("Expected a JSON scan request.")
    kind = data.get("kind")
    if kind not in {"discover", "ports"}:
        raise ScanError("Choose a discovery or port scan.")
    interfaces = system.get("interfaces", [])
    tools = system.get("tools", {})
    nmap = tools.get("nmap", {})
    arp_scan = tools.get("arp_scan", {})
    if not nmap.get("available"):
        raise ScanError("Nmap is not installed or is not available on PATH.", "tool_missing")

    if kind == "discover":
        target = validate_discovery_target(data.get("target"))
        engine = data.get("engine", "auto")
        if engine not in {"auto", "arp", "nmap"}:
            raise ScanError("Choose Auto, ARP scan, or Nmap ping discovery.")
        requested_interface = data.get("interface")
        selected_interface = _pick_interface(interfaces, target, requested_interface)
        local_target = _target_is_local(target, interfaces)
        resolved_engine = engine
        if engine == "auto":
            if (
                local_target
                and selected_interface
                and arp_scan.get("available")
                and arp_scan.get("usable")
            ):
                resolved_engine = "arp"
            else:
                resolved_engine = "nmap"
        elif engine == "arp":
            if not arp_scan.get("available"):
                raise ScanError(
                    "arp-scan is not installed. Use Nmap ping discovery or install arp-scan.",
                    "tool_missing",
                )
            if not arp_scan.get("usable"):
                raise ScanError(
                    "arp-scan needs raw packet access. Grant it CAP_NET_RAW or run the "
                    "launcher with appropriate privileges — or choose Auto / Nmap ping.",
                    "privilege_required",
                )
            if not selected_interface:
                raise ScanError(
                    "No active IPv4 interface was found for an ARP scan.", "no_interface"
                )
        command_prefix = [nmap["path"]]
        if resolved_engine == "arp":
            interface_name = selected_interface["name"] if selected_interface else None
            if not interface_name:
                raise ScanError("Choose a network interface for the ARP scan.")
            command = [
                arp_scan["path"],
                f"--interface={interface_name}",
                target,
            ]
            preview = " ".join(command)
            engine_label = f"arp-scan · {interface_name}"
            timeout = 600
            interface = interface_name
            notes = [
                "ARP scans only see devices on the local Layer 2 segment.",
            ]
        else:
            temp_path = _make_temp_xml()
            base_command = [
                command_prefix[0],
                "-sn",
                "-T4",
                "--stats-every",
                "2s",
            ]
            command = base_command + ["-oX", str(temp_path), target]
            preview = " ".join(base_command + [target])
            engine_label = "Nmap ping"
            timeout = 600
            interface = selected_interface["name"] if selected_interface else None
            notes = ["Some firewalls drop discovery probes. Use a port scan with "
                     "“treat hosts as online” if a host is missing."]
            request = {
                "kind": "discover",
                "target": target,
                "profile": "discover",
                "engine": engine,
                "interface": interface,
                "resolvedEngine": resolved_engine,
            }
            return ScanConfig(
                kind=kind,
                target=target,
                profile="discover",
                engine=resolved_engine,
                command=command,
                command_preview=preview,
                timeout=timeout,
                request=request,
                interface=interface,
                profile_label="Network discovery",
                temp_path=temp_path,
                notes=notes,
            )
        request = {
            "kind": "discover",
            "target": target,
            "profile": "discover",
            "engine": engine,
            "interface": interface,
            "resolvedEngine": resolved_engine,
        }
        return ScanConfig(
            kind=kind,
            target=target,
            profile="discover",
            engine=resolved_engine,
            command=command,
            command_preview=preview,
            timeout=timeout,
            request=request,
            interface=interface,
            profile_label="Network discovery",
            notes=notes,
        )

    # Port scan
    profile = data.get("profile", "quick")
    if profile not in PROFILES:
        raise ScanError("Choose a valid scan profile.")
    meta = PROFILES[profile]
    target = validate_port_target(data.get("target"))
    host_count = target_host_count(target)
    if host_count > meta["max_hosts"]:
        raise ScanError(
            f"The {meta['label']} profile is capped at {meta['max_hosts']} addresses "
            f"for safety; this target covers about {host_count:,}. "
            "Narrow the target or choose a lighter profile.",
            "target_too_large",
        )

    options = data.get("options") if isinstance(data.get("options"), dict) else {}
    timing = options.get("timing", "normal")
    if timing not in TIMING:
        raise ScanError("Choose a valid timing profile.")
    service_detection = _as_bool(options.get("serviceDetection"))
    scripts = _as_bool(options.get("scripts"))
    os_detection = _as_bool(options.get("osDetection"))
    skip_ping = _as_bool(options.get("skipPing"))

    raw_ports = data.get("ports", "")
    port_spec: str | None = None
    port_count: int | None = None
    if profile == "custom":
        port_spec, port_count = validate_ports(raw_ports)
        if port_count > 65535:
            raise ScanError("That contains more ports than exist.")
        # A wide custom scan is effectively a full scan; use the same cap.
        if port_count > 5000 and host_count > 16:
            raise ScanError(
                "A custom scan of more than 5,000 ports is capped at 16 addresses. "
                "Narrow the target first.",
                "target_too_large",
            )
    elif raw_ports not in (None, ""):
        # Ignore stale port input for non-custom profiles.
        raw_ports = ""

    if os_detection and not nmap.get("raw_access"):
        raise ScanError(
            "OS detection needs raw socket access. Grant Nmap CAP_NET_RAW or choose "
            "another option.",
            "privilege_required",
        )

    args: list[str] = [nmap["path"], "-sS" if nmap.get("raw_access") else "-sT"]
    args.append(TIMING[timing])
    args.extend(meta["args"])
    if port_spec:
        args.extend(["-p", port_spec])
    if service_detection or profile in {"services", "safe"}:
        if profile not in {"services", "safe"}:
            args.extend(["-sV", "--version-light"])
    effective_scripts = bool(scripts) and profile != "safe"
    if effective_scripts:
        args.append("--script=default")
    if os_detection:
        args.extend(["-O", "--osscan-limit"])
    if skip_ping:
        args.append("-Pn")
    args.extend(["--stats-every", "1s"])

    temp_path = _make_temp_xml()
    final_command = args + ["-oX", str(temp_path), target]
    display_args = [*args, target]
    preview = " ".join(display_args)
    notes = []
    if not nmap.get("raw_access"):
        notes.append("Running as an unprivileged TCP connect scan.")
    if effective_scripts:
        notes.append("NSE default scripts can be active against the target. Use only with permission.")
    if profile == "safe":
        notes.append(
            "Safe audit uses a curated set of non-intrusive NSE checks for banners, "
            "HTTP metadata, TLS certificates, SSH host keys, and SMB identity."
        )
    request = {
        "kind": "ports",
        "target": target,
        "profile": profile,
        "ports": raw_ports,
        "options": {
            "timing": timing,
            "serviceDetection": service_detection or profile in {"services", "safe"},
            "scripts": effective_scripts,
            "safeChecks": profile == "safe",
            "osDetection": os_detection,
            "skipPing": skip_ping,
        },
        "resolvedEngine": "nmap-syn" if nmap.get("raw_access") else "nmap-connect",
    }
    return ScanConfig(
        kind=kind,
        target=target,
        profile=profile,
        engine="nmap",
        command=final_command,
        command_preview=preview,
        timeout=meta["timeout"],
        request=request,
        profile_label=meta["label"],
        temp_path=temp_path,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# System probe


class SystemProbe:
    def __init__(self, cache_seconds: int = 15):
        self.cache_seconds = cache_seconds
        self._cached: dict[str, Any] | None = None
        self._cached_at = 0.0
        self._lock = threading.Lock()

    def get(self, refresh: bool = False) -> dict[str, Any]:
        with self._lock:
            if (
                self._cached is not None
                and not refresh
                and time.monotonic() - self._cached_at < self.cache_seconds
            ):
                return self._cached
            self._cached = self._probe()
            self._cached_at = time.monotonic()
            return self._cached

    def _probe(self) -> dict[str, Any]:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        nmap_path = shutil.which("nmap")
        arp_path = shutil.which("arp-scan")
        nmap_raw = bool(nmap_path) and (
            is_root or _has_file_capability(nmap_path, "cap_net_raw")
        )
        arp_usable = bool(arp_path) and (
            is_root or _has_file_capability(arp_path, "cap_net_raw")
        )
        tools = {
            "nmap": {
                "available": bool(nmap_path),
                "path": nmap_path,
                "version": _tool_version(nmap_path) if nmap_path else None,
                "raw_access": nmap_raw,
            },
            "arp_scan": {
                "available": bool(arp_path),
                "path": arp_path,
                "version": _tool_version(arp_path) if arp_path else None,
                "usable": arp_usable,
                "requires_root": True,
            },
        }
        interfaces = _interfaces()
        return {
            "hostname": socket.gethostname(),
            "user": _username(),
            "privileged": is_root,
            "rawAccess": nmap_raw,
            "tools": tools,
            "interfaces": interfaces,
            "platform": "Linux",
            "version": "1.0.0",
            "generatedAt": _utc_now(),
        }


def _tool_version(path: str | None) -> str | None:
    if not path:
        return None
    try:
        completed = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        first = (completed.stdout or completed.stderr).splitlines()
        if not first:
            return "installed"
        line = first[0].strip()
        if path.endswith("nmap"):
            match = re.search(r"Nmap version\s+([^\s]+)", line)
            return match.group(1) if match else line[:60]
        match = re.search(r"arp-scan\s+([^\s]+)", line)
        return match.group(1) if match else line[:60]
    except (OSError, subprocess.SubprocessError):
        return "installed"


def _username() -> str:
    try:
        import getpass

        return getpass.getuser()
    except Exception:
        return "local user"


def _has_file_capability(path: str, capability: str) -> bool:
    getcap = shutil.which("getcap")
    if not getcap:
        return False
    try:
        result = subprocess.run(
            [getcap, path],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return capability in (result.stdout or "")
    except (OSError, subprocess.SubprocessError):
        return False


def _interfaces() -> list[dict[str, Any]]:
    raw: list[dict[str, Any]] = []
    try:
        result = subprocess.run(
            ["ip", "-j", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        if result.returncode == 0:
            import json

            raw = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raw = []

    gateways = _default_gateways()
    default_dev = gateways.get("dev")
    interfaces: list[dict[str, Any]] = []
    for link in raw:
        name = link.get("ifname")
        if not name or name == "lo" or link.get("operstate") == "DOWN":
            continue
        inet = next(
            (
                info
                for info in link.get("addr_info", [])
                if info.get("family") == "inet" and info.get("local")
            ),
            None,
        )
        if not inet:
            continue
        try:
            iface = ipaddress.ip_interface(f"{inet['local']}/{inet.get('prefixlen', 24)}")
        except ValueError:
            continue
        mac = _mac_address(name)
        interfaces.append(
            {
                "name": name,
                "address": str(iface.ip),
                "prefix": iface.network.prefixlen,
                "network": str(iface.network.network_address),
                "cidr": str(iface.network),
                "mac": mac,
                "gateway": gateways.get("gateway") if name == default_dev else None,
                "isDefault": name == default_dev,
                "state": link.get("operstate", "UP"),
            }
        )
    interfaces.sort(key=lambda item: (not item["isDefault"], item["name"]))
    return interfaces


def _default_gateways() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["ip", "-j", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if result.returncode != 0:
            return {}
        import json

        routes = json.loads(result.stdout or "[]")
        if routes:
            return {"dev": routes[0].get("dev", ""), "gateway": routes[0].get("gateway", "")}
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return {}


def _mac_address(interface: str) -> str | None:
    try:
        value = Path(f"/sys/class/net/{interface}/address").read_text().strip()
        if value and value != "00:00:00:00:00:00":
            return value.lower()
    except OSError:
        pass
    return None


# ---------------------------------------------------------------------------
# XML / text parsing


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_nmap_xml(path: Path, kind: str) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ScanError(
            "Nmap finished but its XML output could not be read. "
            "Open the scan log for details.",
            "parse_error",
        ) from exc

    hosts: list[dict[str, Any]] = []
    hosts_total = 0
    for host_el in root.findall("host"):
        hosts_total += 1
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue
        address = None
        mac = None
        vendor = None
        for address_el in host_el.findall("address"):
            addr_type = address_el.get("addrtype")
            if addr_type == "ipv4":
                address = address_el.get("addr")
            elif addr_type == "mac":
                mac = (address_el.get("addr") or "").lower() or None
                vendor = address_el.get("vendor") or None
        if not address:
            continue
        hostnames = [
            node.get("name", "")
            for node in host_el.findall("hostnames/hostname")
            if node.get("name")
        ]
        hostname = hostnames[0] if hostnames else None
        latency = None
        times_el = host_el.find("times")
        if times_el is not None and times_el.get("srtt"):
            try:
                latency = round(float(times_el.get("srtt")) / 1000, 2)
            except ValueError:
                latency = None
        ports: list[dict[str, Any]] = []
        port_stats = {
            "open": 0,
            "closed": 0,
            "filtered": 0,
            "unfiltered": 0,
            "other": 0,
        }
        if kind == "ports":
            # Nmap groups repeated states under <extraports>. Count those first,
            # then count the explicitly listed ports. This makes the per-host
            # coverage ("open / closed / filtered") visible in the GUI.
            for extra_el in host_el.findall("ports/extraports"):
                count = _safe_int(extra_el.get("count"), 0)
                port_stats[_port_state_key(extra_el.get("state"))] += count
            for port_el in host_el.findall("ports/port"):
                state_el = port_el.find("state")
                state_name = state_el.get("state") if state_el is not None else "other"
                port_stats[_port_state_key(state_name)] += 1
                if state_name != "open":
                    continue
                try:
                    port_number = int(port_el.get("portid", "0"))
                except ValueError:
                    continue
                protocol = port_el.get("protocol", "tcp")
                service_el = port_el.find("service")
                service = _attr(service_el, "name")
                product = _attr(service_el, "product")
                version = _attr(service_el, "version")
                extrainfo = _attr(service_el, "extrainfo")
                tunnel = _attr(service_el, "tunnel")
                cpes = [
                    node.text.strip()
                    for node in port_el.findall("service/cpe")
                    if node.text and node.text.strip()
                ][:4]
                risk = assess_service(port_number, service)
                scripts = _parse_scripts(port_el.findall("script"))
                port_entry: dict[str, Any] = {
                    "port": port_number,
                    "protocol": protocol,
                    "state": "open",
                    "reason": state_el.get("reason") or "",
                    "service": service or "unknown",
                    "product": product or "",
                    "version": version or "",
                    "extra": extrainfo or "",
                    "tunnel": tunnel or "",
                    "cpes": cpes,
                    "risk": risk,
                }
                if scripts:
                    port_entry["scripts"] = scripts
                ports.append(port_entry)
            port_stats["scanned"] = sum(port_stats.values())
        os_matches = []
        for match in host_el.findall("os/osmatch")[:3]:
            if match.get("name"):
                os_matches.append(
                    {
                        "name": match.get("name"),
                        "accuracy": int(match.get("accuracy", "0") or 0),
                    }
                )
        host_scripts = _parse_scripts(host_el.findall("hostscript/script"))
        host_entry: dict[str, Any] = {
            "address": address,
            "hostname": hostname,
            "hostnames": hostnames[:5],
            "mac": mac,
            "vendor": vendor,
            "status": "up",
            "latency": latency,
            "ports": ports,
            "openPorts": len(ports),
            "portStats": port_stats if kind == "ports" else None,
            "os": os_matches,
            "reason": status_el.get("reason") or "up",
        }
        if host_scripts:
            host_entry["scripts"] = host_scripts
        hosts.append(host_entry)

    # Nmap puts open ports in host order; keep the fastest responses first for
    # a tidy UI while preserving deterministic output.
    hosts.sort(key=lambda item: (ipaddress.ip_address(item["address"]),))
    open_ports = sum(len(host["ports"]) for host in hosts)
    services = sorted(
        {
            port["service"]
            for host in hosts
            for port in host["ports"]
            if port.get("service") not in (None, "", "unknown")
        }
    )
    attention = sum(
        1
        for host in hosts
        for port in host["ports"]
        if port.get("risk", {}).get("level") in {"high", "medium"}
    )
    categories: dict[str, int] = {}
    cleartext_ports = 0
    filtered_ports = 0
    for host in hosts:
        stats = host.get("portStats") or {}
        filtered_ports += stats.get("filtered", 0) + stats.get("other", 0)
        for port in host["ports"]:
            category = (port.get("risk") or {}).get("category") or "other"
            categories[category] = categories.get(category, 0) + 1
            if (port.get("risk") or {}).get("cleartext"):
                cleartext_ports += 1
    summary = {
        "hostsFound": len(hosts),
        "hostsTotal": hosts_total,
        "openPorts": open_ports,
        "filteredPorts": filtered_ports,
        "services": len(services),
        "attention": attention,
        "cleartextPorts": cleartext_ports,
        "categories": categories,
        "engine": "nmap",
    }
    results = {
        "kind": kind,
        "hosts": hosts,
        "services": services,
        "summary": summary,
    }
    return results, summary


def _attr(element: ET.Element | None, key: str) -> str:
    if element is None:
        return ""
    return (element.get(key) or "").strip()


def _safe_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _port_state_key(state: Any) -> str:
    value = str(state or "other").lower()
    if value == "open":
        return "open"
    if value == "closed":
        return "closed"
    if value in {"filtered", "open|filtered"}:
        return "filtered"
    if value == "unfiltered":
        return "unfiltered"
    return "other"


def _parse_scripts(nodes: list[ET.Element]) -> list[dict[str, str]]:
    scripts: list[dict[str, str]] = []
    for node in nodes[:16]:
        # Nmap writes the rendered script output in an attribute in most XML
        # versions. Fall back to text/itertext for older or unusual output.
        output = (node.get("output") or node.text or "").strip()
        if not output:
            output = "".join(node.itertext()).strip()
        scripts.append(
            {
                "id": (node.get("id") or "script")[:80],
                "output": output[:5000],
                "truncated": len(output) > 5000,
            }
        )
    return scripts


def parse_arp_scan(log: str) -> tuple[dict[str, Any], dict[str, Any]]:
    hosts_by_ip: dict[str, dict[str, Any]] = {}
    for line in log.splitlines():
        match = _ARP_LINE_RE.match(line.strip())
        if not match:
            continue
        ip = match.group("ip")
        try:
            ip = str(ipaddress.IPv4Address(ip))
        except ValueError:
            continue
        mac = match.group("mac").lower().replace("-", ":")
        rest = re.sub(r"^\(DUP:\s*\d+\)\s*", "", match.group("rest").strip())
        rest = re.sub(r"^\(DUP:\s*\d+\)", "", rest).strip()
        vendor = rest[:160] or None
        hosts_by_ip[ip] = {
            "address": ip,
            "hostname": None,
            "hostnames": [],
            "mac": mac,
            "vendor": vendor,
            "status": "up",
            "latency": None,
            "ports": [],
            "openPorts": 0,
            "os": [],
            "reason": "arp-reply",
        }
    hosts = sorted(hosts_by_ip.values(), key=lambda item: ipaddress.ip_address(item["address"]))
    summary = {
        "hostsFound": len(hosts),
        "hostsTotal": len(hosts),
        "openPorts": 0,
        "services": 0,
        "attention": 0,
        "engine": "arp-scan",
    }
    results = {"kind": "discover", "hosts": hosts, "services": [], "summary": summary}
    return results, summary


# ---------------------------------------------------------------------------
# Jobs


@dataclass
class ScanJob:
    id: str
    config: ScanConfig
    created_at: str
    status: str = "queued"
    progress: float = 0.0
    started_at: str | None = None
    finished_at: str | None = None
    duration: float | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    results: dict[str, Any] | None = None
    error: str | None = None
    log_lines: list[str] = field(default_factory=list)
    process: subprocess.Popen | None = None
    cancel_requested: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_log(self, line: str) -> None:
        if line is None:
            return
        clean = line.rstrip("\r\n")
        if not clean:
            return
        clean = clean[:4000]
        with self.lock:
            if len(self.log_lines) < 6000:
                self.log_lines.append(clean)
            elif len(self.log_lines) == 6000:
                self.log_lines.append("[log truncated at 6,000 lines]")

    def log_text(self) -> str:
        with self.lock:
            return "\n".join(self.log_lines)

    def log_chunk(self, after: int) -> tuple[list[str], int]:
        with self.lock:
            total = len(self.log_lines)
            if after < 0 or after > total:
                after = 0
            return list(self.log_lines[after:]), total


class ScanManager:
    def __init__(
        self,
        store: Store,
        probe: SystemProbe,
        on_finished: Callable[[str], None] | None = None,
    ):
        self.store = store
        self.probe = probe
        self.on_finished = on_finished
        self.jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()

    def active(self) -> ScanJob | None:
        with self._lock:
            for job in self.jobs.values():
                if job.status in {"queued", "running", "cancelling"}:
                    return job
        row = self.store.active_scan()
        if not row:
            return None
        return self.jobs.get(row["id"])

    def start(self, request: dict[str, Any]) -> ScanJob:
        system = self.probe.get()
        config = prepare_scan(request, system)
        with self._lock:
            current = self.active()
            if current:
                config.cleanup()
                raise ScanBusy(current.id)
            scan_id = uuid.uuid4().hex[:10]
            created_at = _utc_now()
            job = ScanJob(
                id=scan_id,
                config=config,
                created_at=created_at,
            )
            self.jobs[scan_id] = job
            self.store.create_scan(
                {
                    "id": scan_id,
                    "kind": config.kind,
                    "target": config.target,
                    "profile": config.profile,
                    "engine": config.engine,
                    "status": "queued",
                    "created_at": created_at,
                    "command": config.command_preview,
                    "request": config.request,
                }
            )
        thread = threading.Thread(
            target=self._run_job,
            args=(job, system),
            name=f"recondeck-{scan_id}",
            daemon=True,
        )
        thread.start()
        return job

    def _run_job(self, job: ScanJob, system: dict[str, Any]) -> None:
        started_monotonic = time.monotonic()
        job.status = "running"
        job.started_at = _utc_now()
        job.progress = 2.0
        self.store.mark_running(job.id)
        job.add_log(f"$ {job.config.command_preview}")
        job.add_log(
            f"ReconDeck {('discovery' if job.config.kind == 'discover' else 'port scan')} "
            f"· {job.config.profile_label} · target {job.config.target}"
        )
        for note in job.config.notes:
            job.add_log(f"· {note}")
        returncode: int | None = None
        try:
            env = os.environ.copy()
            env.setdefault("LC_ALL", "C")
            proc = subprocess.Popen(
                job.config.command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
                start_new_session=True,
            )
            job.process = proc
            assert proc.stdout is not None
            line_queue: queue.Queue[str | None] = queue.Queue()

            def read_output() -> None:
                try:
                    assert proc.stdout is not None
                    for line in proc.stdout:
                        line_queue.put(line)
                finally:
                    line_queue.put(None)

            reader = threading.Thread(
                target=read_output,
                name=f"recondeck-output-{job.id}",
                daemon=True,
            )
            reader.start()
            deadline = started_monotonic + job.config.timeout
            timed_out = False
            while True:
                try:
                    raw_line = line_queue.get(timeout=0.35)
                except queue.Empty:
                    raw_line = ""
                    if time.monotonic() > deadline:
                        timed_out = True
                        job.error = (
                            f"The scan exceeded ReconDeck's {job.config.timeout // 60}-minute "
                            "safety limit and was stopped."
                        )
                        self._terminate(job)
                        break
                    if job.cancel_requested:
                        break
                    continue
                if raw_line is None:
                    break
                job.add_log(raw_line)
                match = _PROGRESS_RE.search(raw_line)
                if match:
                    try:
                        percent = max(0.0, min(100.0, float(match.group(1))))
                        job.progress = max(job.progress, round(4 + percent * 0.9, 1))
                    except ValueError:
                        pass
                if time.monotonic() > deadline:
                    timed_out = True
                    job.error = (
                        f"The scan exceeded ReconDeck's {job.config.timeout // 60}-minute "
                        "safety limit and was stopped."
                    )
                    self._terminate(job)
                    break
            if not timed_out:
                try:
                    returncode = proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    self._terminate(job)
                    returncode = proc.wait(timeout=5)
            else:
                try:
                    returncode = proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    returncode = proc.poll()
            if job.cancel_requested:
                job.status = "cancelled"
                job.progress = 0.0
                job.error = "Scan stopped by user."
            elif job.error:
                job.status = "failed"
            elif returncode != 0:
                job.status = "failed"
                job.error = _friendly_error(job.log_text(), returncode)
            else:
                if job.config.kind == "ports":
                    results, summary = parse_nmap_xml(job.config.temp_path, job.config.kind)
                elif job.config.engine == "arp":
                    results, summary = parse_arp_scan(job.log_text())
                else:
                    results, summary = parse_nmap_xml(job.config.temp_path, job.config.kind)
                job.results = results
                job.summary = summary
                job.status = "completed"
                job.progress = 100.0
                summary["durationSeconds"] = round(time.monotonic() - started_monotonic, 2)
        except FileNotFoundError:
            job.status = "failed"
            job.error = "The scanner executable could not be found."
            job.add_log(job.error)
        except ScanError as exc:
            job.status = "failed"
            job.error = exc.message
            job.add_log(job.error)
        except Exception as exc:  # pragma: no cover - defensive boundary
            job.status = "failed"
            job.error = f"The scan failed unexpectedly: {exc.__class__.__name__}."
            job.add_log(f"Unexpected error: {exc}")
        finally:
            job.process = None
            job.finished_at = _utc_now()
            job.duration = round(time.monotonic() - started_monotonic, 2)
            if job.status in {"running", "queued"}:
                job.status = "failed"
                job.error = job.error or "The scan ended unexpectedly."
            if job.status == "failed":
                job.progress = 0.0
            # Add a human-readable closing marker to the live log.
            if job.status == "completed":
                job.add_log(
                    f"✓ Scan complete · {job.summary.get('hostsFound', 0)} host(s) · "
                    f"{job.summary.get('openPorts', 0)} open port(s) · {job.duration}s"
                )
            elif job.status == "cancelled":
                job.add_log("■ Scan stopped.")
            else:
                job.add_log(f"✕ {job.error or 'Scan failed.'}")
            final_summary = dict(job.summary or {})
            final_summary["durationSeconds"] = job.duration
            self.store.finish_scan(
                job.id,
                status=job.status,
                started_at=job.started_at,
                finished_at=job.finished_at or _utc_now(),
                duration=job.duration or 0.0,
                summary=final_summary,
                results=job.results,
                error=job.error,
                log=job.log_text(),
                request=job.config.request,
            )
            job.config.cleanup()
            if self.on_finished:
                try:
                    self.on_finished(job.id)
                except Exception:
                    pass

    def _terminate(self, job: ScanJob) -> None:
        proc = job.process
        if not proc or proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=3)
        except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass

    def cancel(self, scan_id: str) -> ScanJob:
        with self._lock:
            job = self.jobs.get(scan_id)
            if not job:
                raise ScanError("That scan is not running in this session.", "not_found")
            if job.status not in {"queued", "running"}:
                raise ScanError("That scan has already finished.", "not_running")
            job.cancel_requested = True
            job.status = "cancelling"
        job.add_log("Stop requested. Ending the scan…")
        self._terminate(job)
        return job

    def serialize_job(
        self, job: ScanJob, *, after_log: int = 0, include_results: bool = True
    ) -> dict[str, Any]:
        logs, log_count = job.log_chunk(after_log)
        record: dict[str, Any] = {
            "id": job.id,
            "kind": job.config.kind,
            "target": job.config.target,
            "profile": job.config.profile,
            "profileLabel": job.config.profile_label,
            "engine": job.config.engine,
            "status": job.status,
            "createdAt": job.created_at,
            "startedAt": job.started_at,
            "finishedAt": job.finished_at,
            "duration": job.duration,
            "command": job.config.command_preview,
            "error": job.error,
            "summary": job.summary,
            "progress": job.progress,
            "logs": logs,
            "logCount": log_count,
            "request": job.config.request,
            "hasResults": job.results is not None,
        }
        if include_results and job.results is not None:
            record["results"] = job.results
        return record

    def dynamic_state(self) -> dict[str, Any]:
        """Small live status payload used by the header and dashboard."""
        active = self.active()
        if not active:
            return {"active": None}
        return {
            "active": {
                "id": active.id,
                "kind": active.config.kind,
                "target": active.config.target,
                "status": active.status,
                "progress": active.progress,
                "startedAt": active.started_at,
            }
        }


def _friendly_error(log: str, returncode: int) -> str:
    lower = log.lower()
    if "requires root privileges" in lower or "operation not permitted" in lower:
        return (
            "Nmap needs elevated raw-packet access for that scan. "
            "ReconDeck stayed in unprivileged mode; try again without the privileged option."
        )
    if "failed to resolve" in lower or "could not resolve" in lower:
        return "Nmap could not resolve that target. Check the hostname and your connection."
    if "permission denied" in lower:
        return "The scanner was denied access. Check the tool's capabilities."
    if "no route to host" in lower:
        return "No route to the target. Check the address and your network connection."
    lines = [line.strip() for line in log.splitlines() if line.strip()]
    tail = next(
        (
            line
            for line in reversed(lines)
            if not line.startswith("$") and not line.startswith("ReconDeck")
        ),
        "",
    )
    if tail and len(tail) < 240:
        return f"Nmap exited with code {returncode}. {tail}"
    return f"Nmap exited with code {returncode}."


