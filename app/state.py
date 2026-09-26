"""Shared application state — the single nervous system of RECON-WIRE.

Every module writes to its own field. Every tab reads from here.
No module ever imports another module. All data flows through AppState.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ScanConfig:
    """Immutable scan configuration built by cli.py."""
    url: str
    hostname: str
    domain: str               # apex domain extracted from hostname
    scheme: str               # http | https
    port: int                 # 443 default for https, 80 for http
    timeout: int
    max_subdomains: int
    geoip_enabled: bool
    axfr_enabled: bool
    output_dir: Path
    max_concurrent: int
    output_json: Path | None = None
    output_markdown: Path | None = None
    output_text: Path | None = None
    output_sarif: Path | None = None
    delay: float = 0.0          # Delay in seconds between requests (adaptive stealth)
    jitter: float = 0.0         # Random jitter max seconds (0 to jitter)
    user_agent: str | None = None  # Custom or randomized User-Agent
    scan_ports: bool = True     # Run port enumeration
    scan_endpoints: bool = True # Run endpoint and web crawl
    scan_fuzz: bool = True      # Run sensitive files bruteforce
    scan_cloud: bool = True     # Run cloud buckets hunter
    scan_takeover: bool = True  # Run subdomain takeover hunter (PA-3)
    scan_harvest: bool = True   # Run email & secrets scraper (PA-2)
    scan_waf: bool = True       # Run WAF fingerprinting (PB-2)
    scan_asn: bool = True       # Run IP range & ASN discovery (PC-1)
    scan_params: bool = True    # Run parameter discovery (PD-1)
    scan_csp: bool = True       # Run CSP evaluator & bypass engine (PD-2)
    scan_vhost: bool = True     # Run virtual host prober (PC-2)


@dataclass
class ModuleStatus:
    """Per-module progress tracking."""
    name: str
    state: str = "PENDING"    # PENDING | RUNNING | DONE | ERROR
    progress: int = 0         # 0–100
    message: str = ""         # last status message


@dataclass
class AppState:
    """Central state container passed to every module and every tab widget.

    Instantiated once in app/core.py.  Modules write their result fields;
    tab widgets read them.  Under asyncio's single-threaded event loop,
    list.append() and dict[] assignment are safe without locking.
    """
    config: ScanConfig

    # findings queue — all modules push Finding objects here
    findings_queue: asyncio.Queue = field(default_factory=asyncio.Queue)

    # per-module result stores
    dns_results: dict[str, Any] = field(default_factory=dict)
    subdomain_results: list[Any] = field(default_factory=list)
    header_results: dict[str, Any] = field(default_factory=dict)
    tech_results: list[Any] = field(default_factory=list)
    whois_results: dict[str, Any] = field(default_factory=dict)
    tls_results: dict[str, Any] = field(default_factory=dict)
    port_results: list[Any] = field(default_factory=list)
    endpoint_results: list[Any] = field(default_factory=list)
    fuzz_results: list[Any] = field(default_factory=list)
    cloud_results: list[Any] = field(default_factory=list)
    takeover_results: list[Any] = field(default_factory=list)
    harvest_results: dict[str, Any] = field(default_factory=dict)
    waf_results: list[Any] = field(default_factory=list)
    asn_results: dict[str, Any] = field(default_factory=dict)
    param_results: list[Any] = field(default_factory=list)
    csp_results: list[Any] = field(default_factory=list)
    vhost_results: list[Any] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)

    # module status — read by status_bar and overview_tab
    module_statuses: dict[str, ModuleStatus] = field(default_factory=dict)

    # scan metadata
    scan_start: datetime = field(default_factory=datetime.utcnow)
    scan_complete: bool = False

    def __post_init__(self) -> None:
        """Seed module statuses so every tab has something to read."""
        for name in (
            "DNS", "SUBDOMAINS", "HEADERS", "TECH", "WHOIS", "TLS",
            "PORTS", "ENDPOINTS", "FUZZ", "CLOUD", "TAKEOVER",
            "HARVEST", "WAF", "ASN", "PARAMS", "CSP", "VHOST"
        ):
            self.module_statuses[name] = ModuleStatus(name=name)



    @property
    def elapsed(self) -> float:
        """Seconds since scan started."""
        return (datetime.utcnow() - self.scan_start).total_seconds()
