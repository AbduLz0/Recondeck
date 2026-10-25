"""Small, deliberately conservative service-exposure notes.

ReconDeck is a reconnaissance tool, not a vulnerability scanner. These
annotations are review prompts based on a port's usual purpose; an open port
is never, by itself, proof that a host is vulnerable.
"""

from __future__ import annotations

RISK_LEVELS = {"high", "medium", "low", "info"}

# port -> (label, note, level)
_PORT_NOTES: dict[int, tuple[str, str, str]] = {
    21: ("Cleartext file transfer", "FTP sends credentials in the clear. Prefer SFTP or FTPS.", "high"),
    22: ("Remote shell", "Confirm that SSH is intended to be reachable and uses key-based auth.", "low"),
    23: ("Cleartext remote shell", "Telnet is unencrypted. Replace it with SSH.", "high"),
    25: ("Mail transfer", "Confirm this mail service is intended to be internet-facing.", "low"),
    53: ("DNS service", "Review recursion and zone-transfer exposure if this is not a resolver.", "low"),
    80: ("Unencrypted web", "Check for a redirect to HTTPS and review the application.", "low"),
    111: ("RPC portmapper", "Restrict RPC to trusted networks where possible.", "medium"),
    135: ("Windows RPC", "Restrict Windows RPC to trusted management networks.", "medium"),
    139: ("NetBIOS", "Legacy SMB discovery is often unnecessary on modern networks.", "medium"),
    161: ("SNMP", "Check community strings and prefer SNMPv3.", "medium"),
    389: ("Directory service", "Plain LDAP may expose directory traffic; prefer LDAPS.", "medium"),
    443: ("Encrypted web", "Review the web application, TLS configuration, and certificates.", "info"),
    445: ("SMB file sharing", "A high-value lateral-movement surface. Restrict and patch it.", "high"),
    465: ("Encrypted mail", "Confirm the mail service is expected here.", "info"),
    587: ("Mail submission", "Confirm authentication and TLS are enforced.", "low"),
    631: ("Print service", "Printers commonly expose management interfaces; segment them.", "low"),
    873: ("Rsync", "Rsync modules can expose files. Check authentication and exports.", "medium"),
    993: ("Encrypted mail", "Confirm the mail service is expected here.", "info"),
    995: ("Encrypted mail", "Confirm the mail service is expected here.", "info"),
    1433: ("Database exposure", "Microsoft SQL Server should not be reachable from untrusted networks.", "high"),
    1521: ("Database exposure", "Oracle listener exposure should be tightly restricted.", "high"),
    2049: ("NFS export", "Review export restrictions and network exposure.", "medium"),
    2375: ("Unauthenticated Docker API", "Docker's plain API often grants host control. Never expose it.", "high"),
    2376: ("Docker API", "Restrict the Docker API to trusted management systems.", "high"),
    3000: ("Web application", "Identify the application before exposing it broadly.", "low"),
    3306: ("Database exposure", "MySQL should generally be limited to trusted application hosts.", "medium"),
    3389: ("Remote desktop", "RDP is a common brute-force and ransomware target. Restrict access.", "high"),
    5432: ("Database exposure", "PostgreSQL should generally be limited to trusted application hosts.", "medium"),
    5900: ("Remote desktop", "VNC is often weakly authenticated. Restrict access.", "high"),
    5985: ("Windows remote management", "WinRM exposure should be limited to management networks.", "high"),
    5986: ("Windows remote management", "WinRM exposure should be limited to management networks.", "high"),
    6379: ("In-memory database", "Redis is unauthenticated by default. Never expose it.", "high"),
    6443: ("Kubernetes API", "Kubernetes control planes need strong authentication and network policy.", "high"),
    8000: ("Alternative web service", "Identify the application before exposing it broadly.", "low"),
    8008: ("Alternative web service", "Identify the application before exposing it broadly.", "low"),
    8080: ("Alternative web service", "Identify the application before exposing it broadly.", "low"),
    8081: ("Alternative web service", "Identify the application before exposing it broadly.", "low"),
    8443: ("Alternative web service", "Review the web application and TLS configuration.", "info"),
    8888: ("Alternative web service", "Identify the application before exposing it broadly.", "low"),
    9000: ("Application service", "Identify the service before exposing it broadly.", "low"),
    9090: ("Management interface", "Management interfaces should be restricted to trusted networks.", "medium"),
    9200: ("Search engine API", "Elasticsearch is often unauthenticated. Restrict it carefully.", "high"),
    9300: ("Search cluster transport", "Cluster transport should stay on a private network.", "medium"),
    10250: ("Kubelet API", "Kubelet exposure can permit pod or host actions. Restrict it.", "high"),
    11211: ("Cache service", "Memcached has no authentication by default.", "high"),
    27017: ("Database exposure", "MongoDB is often left unauthenticated. Restrict access.", "high"),
}

# Service names catch non-default ports discovered with -sV.
_SERVICE_NOTES: dict[str, tuple[str, str, str]] = {
    "ftp": ("Cleartext file transfer", "FTP sends credentials in the clear. Prefer SFTP or FTPS.", "high"),
    "telnet": ("Cleartext remote shell", "Telnet is unencrypted. Replace it with SSH.", "high"),
    "microsoft-ds": ("SMB file sharing", "A high-value lateral-movement surface. Restrict and patch it.", "high"),
    "netbios-ssn": ("NetBIOS", "Legacy SMB discovery is often unnecessary on modern networks.", "medium"),
    "ms-wbt-server": ("Remote desktop", "RDP is a common brute-force and ransomware target. Restrict access.", "high"),
    "vnc": ("Remote desktop", "VNC is often weakly authenticated. Restrict access.", "high"),
    "redis": ("In-memory database", "Redis is unauthenticated by default. Never expose it.", "high"),
    "mongodb": ("Database exposure", "MongoDB is often left unauthenticated. Restrict access.", "high"),
    "elasticsearch": ("Search engine API", "Elasticsearch is often unauthenticated. Restrict it carefully.", "high"),
    "docker": ("Container API", "The Docker API can grant host control. Restrict it.", "high"),
    "mysql": ("Database exposure", "MySQL should generally be limited to trusted application hosts.", "medium"),
    "postgresql": ("Database exposure", "PostgreSQL should generally be limited to trusted application hosts.", "medium"),
    "ldap": ("Directory service", "Plain LDAP may expose directory traffic; prefer LDAPS.", "medium"),
    "snmp": ("SNMP", "Check community strings and prefer SNMPv3.", "medium"),
    "rpcbind": ("RPC portmapper", "Restrict RPC to trusted networks where possible.", "medium"),
    "rsync": ("Rsync", "Rsync modules can expose files. Check authentication and exports.", "medium"),
    "http": ("Unencrypted web", "Check for a redirect to HTTPS and review the application.", "low"),
    "https": ("Encrypted web", "Review the web application, TLS configuration, and certificates.", "info"),
    "ssh": ("Remote shell", "Confirm that SSH is intended to be reachable and uses key-based auth.", "low"),
    "domain": ("DNS service", "Review recursion and zone-transfer exposure if this is not a resolver.", "low"),
    "ipp": ("Print service", "Printers commonly expose management interfaces; segment them.", "low"),
    "smtp": ("Mail transfer", "Confirm this mail service is intended to be internet-facing.", "low"),
}


def assess_port(port: int, service: str | None = None) -> dict:
    """Return a small exposure annotation for an open port."""
    note = _PORT_NOTES.get(port)
    if note is None and service:
        note = _SERVICE_NOTES.get(service.lower())
    if note is None:
        return {
            "level": "info",
            "label": "Open service",
            "note": "Confirm this service is expected and appropriately restricted.",
        }
    label, detail, level = note
    return {"level": level, "label": label, "note": detail}


def count_attention(ports: list[dict]) -> int:
    """Count high-confidence review signals, used only as a dashboard tally."""
    return sum(1 for port in ports if port.get("risk", {}).get("level") in {"high", "medium"})


CATEGORY_LABELS = {
    "remote-access": "Remote access",
    "file-sharing": "File sharing",
    "database": "Data stores",
    "management": "Management",
    "web": "Web services",
    "mail": "Mail",
    "infrastructure": "Infrastructure",
    "printing": "Printing",
    "other": "Other services",
}

_PORT_CATEGORY: dict[int, str] = {
    21: "file-sharing",
    22: "remote-access",
    23: "remote-access",
    25: "mail",
    53: "infrastructure",
    80: "web",
    111: "infrastructure",
    135: "management",
    139: "file-sharing",
    161: "management",
    389: "management",
    443: "web",
    445: "file-sharing",
    465: "mail",
    587: "mail",
    631: "printing",
    873: "file-sharing",
    993: "mail",
    995: "mail",
    1433: "database",
    1521: "database",
    2049: "file-sharing",
    2375: "management",
    2376: "management",
    3000: "web",
    3306: "database",
    3389: "remote-access",
    5432: "database",
    5900: "remote-access",
    5985: "management",
    5986: "management",
    6379: "database",
    6443: "management",
    8000: "web",
    8008: "web",
    8080: "web",
    8081: "web",
    8443: "web",
    8888: "web",
    9000: "web",
    9090: "management",
    9200: "database",
    9300: "database",
    10250: "management",
    11211: "database",
    27017: "database",
}

_SERVICE_CATEGORY: dict[str, str] = {
    "ftp": "file-sharing",
    "telnet": "remote-access",
    "ssh": "remote-access",
    "http": "web",
    "https": "web",
    "microsoft-ds": "file-sharing",
    "netbios-ssn": "file-sharing",
    "ms-wbt-server": "remote-access",
    "vnc": "remote-access",
    "redis": "database",
    "mongodb": "database",
    "elasticsearch": "database",
    "docker": "management",
    "mysql": "database",
    "postgresql": "database",
    "ldap": "management",
    "snmp": "management",
    "rpcbind": "infrastructure",
    "rsync": "file-sharing",
    "domain": "infrastructure",
    "ipp": "printing",
    "smtp": "mail",
    "submission": "mail",
    "imaps": "mail",
    "pop3s": "mail",
}

_CLEARTEXT_PORTS = {21, 23, 80, 110, 143, 389, 512, 513, 514}
_CLEARTEXT_SERVICES = {"ftp", "telnet", "http", "pop3", "imap", "ldap", "rlogin", "rsh", "rexec"}


def assess_service(port: int, service: str | None = None) -> dict:
    """Extend the exposure note with a service category and cleartext cue."""
    assessment = assess_port(port, service)
    service_key = (service or "").lower()
    category = _PORT_CATEGORY.get(port) or _SERVICE_CATEGORY.get(service_key) or "other"
    assessment["category"] = category
    assessment["categoryLabel"] = CATEGORY_LABELS.get(category, "Other services")
    assessment["cleartext"] = port in _CLEARTEXT_PORTS or service_key in _CLEARTEXT_SERVICES
    return assessment
