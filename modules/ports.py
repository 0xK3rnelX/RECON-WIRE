"""Port and service enumeration module (P1-1).

Performs async TCP connect probe and service identification for critical web and infrastructure ports.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, asdict
from typing import TYPE_CHECKING

from modules.findings import push_finding

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.ports")

# Comprehensive network service & administration ports (65+ critical ports)
COMMON_PORTS: dict[int, str] = {
    # Core Network & File Transfer
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    88: "KERBEROS",
    110: "POP3",
    111: "RPCBIND",
    135: "MSRPC",
    139: "NETBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SUBMISSION",
    636: "LDAPS",
    873: "RSYNC",
    993: "IMAPS",
    995: "POP3S",
    2049: "NFS",

    # Web Applications & Proxies
    3000: "NODE/GRAFANA",
    4200: "ANGULAR-DEV",
    5000: "FLASK/DEV",
    8000: "HTTP-ALT",
    8008: "HTTP-ALT2",
    8080: "HTTP-PROXY",
    8081: "HTTP-PROXY2",
    8443: "HTTPS-ALT",
    8888: "HTTP-ADMIN",
    9000: "PORTAINER/SONAR",
    9443: "HTTPS-MGMT",

    # Remote Management & Virtualization
    3389: "RDP",
    5900: "VNC",
    5901: "VNC-DISPLAY1",
    5985: "WINRM-HTTP",
    5986: "WINRM-HTTPS",
    10000: "WEBMIN",

    # Databases & Caches
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    5432: "POSTGRESQL",
    5984: "COUCHDB",
    6379: "REDIS",
    7474: "NEO4J",
    8086: "INFLUXDB",
    9200: "ELASTICSEARCH",
    9300: "ES-CLUSTER",
    11211: "MEMCACHED",
    27017: "MONGODB",
    27018: "MONGODB-SHARD",

    # Message Brokers & Queues
    1883: "MQTT",
    5672: "RABBITMQ",
    8883: "MQTT-SSL",
    9092: "KAFKA",
    15672: "RABBITMQ-MGMT",

    # Containers & Cloud Orchestration
    2375: "DOCKER-PLAIN",
    2376: "DOCKER-TLS",
    2379: "ETCD",
    6443: "KUBERNETES-API",
    8200: "HASHICORP-VAULT",
    8500: "CONSUL",
    10250: "KUBELET",

    # Hosting Control Panels
    2082: "CPANEL",
    2083: "CPANEL_SSL",
    2086: "WHM",
    2087: "WHM_SSL",
}


@dataclass
class PortResult:
    port: int
    service: str
    state: str = "OPEN"
    banner: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class PortModule:
    """Async TCP port scanner and service banner grabber."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def _probe_port(self, host: str, port: int, service_name: str, semaphore: asyncio.Semaphore) -> PortResult | None:
        async with semaphore:
            timeout = min(3.0, float(self.state.config.timeout))
            try:
                # Async TCP socket connection
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                banner = ""
                try:
                    # Attempt quick banner grab
                    if port in (21, 22, 25, 110, 143):
                        banner_bytes = await asyncio.wait_for(reader.read(256), timeout=1.0)
                        banner = banner_bytes.decode("utf-8", errors="replace").strip()
                    elif port in (80, 8080, 8000, 8888, 3000, 5000):
                        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                        await writer.drain()
                        hdr_bytes = await asyncio.wait_for(reader.read(256), timeout=1.0)
                        banner = hdr_bytes.decode("utf-8", errors="replace").splitlines()[0] if hdr_bytes else ""
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                return PortResult(port=port, service=service_name, banner=banner)
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None

    async def run(self) -> list[PortResult]:
        status = self.state.module_statuses.get("PORTS")
        if status:
            status.state = "RUNNING"
            status.message = "Probing service ports..."

        target_host = self.state.config.hostname
        semaphore = asyncio.Semaphore(self.state.config.max_concurrent)
        tasks = [
            self._probe_port(target_host, port, svc, semaphore)
            for port, svc in COMMON_PORTS.items()
        ]

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports: list[PortResult] = [r for r in raw_results if isinstance(r, PortResult)]
        open_ports.sort(key=lambda p: p.port)

        self.state.port_results = open_ports

        # Vulnerability / Exposure Findings
        high_risk_ports = {
            21: ("FTP Service Exposed", "CRITICAL", "Plaintext FTP daemon open to public network"),
            23: ("Telnet Service Exposed", "CRITICAL", "Insecure unencrypted Telnet management protocol open"),
            445: ("SMB Port Exposed", "HIGH", "Direct SMB exposure poses high lateral movement / exploit risk"),
            3389: ("RDP Port Exposed", "HIGH", "Remote Desktop open externally — brute-force / ransomware vector"),
            3306: ("MySQL Database Exposed", "HIGH", "Direct MySQL database port publicly accessible"),
            5432: ("PostgreSQL Exposed", "HIGH", "Database listener publicly reachable"),
            6379: ("Redis Exposed", "CRITICAL", "In-memory database port open without boundary protection"),
            9200: ("Elasticsearch Exposed", "CRITICAL", "Search cluster REST API exposed to WAN"),
            27017: ("MongoDB Exposed", "CRITICAL", "NoSQL database open to public internet"),
        }

        for p in open_ports:
            if p.port in high_risk_ports:
                title, sev, detail = high_risk_ports[p.port]
                await push_finding(
                    self.state.findings_queue,
                    module="PORTS",
                    severity=sev,
                    title=f"{title} (Port {p.port})",
                    detail=f"{detail}. Service: {p.service}. Banner: {p.banner or 'None'}",
                    evidence=f"TCP Port {p.port}/{p.service} open on {target_host}",
                )

        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(open_ports)} open ports found"

        return open_ports
