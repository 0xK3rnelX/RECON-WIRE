"""Automated unit and integration test suite for RECON-WIRE."""

import pytest
from pathlib import Path
from app.state import AppState, ScanConfig
from app.cli import _normalize_url, _extract_apex_domain
from modules.vhost import VHOST_PREFIXES
from modules.params import PARAM_WORDLIST
from modules.csp import GADGET_CDNS
from modules.fuzz import FUZZ_TARGETS
from modules.harvest import SECRET_PATTERNS
from modules.ports import COMMON_PORTS
from modules.subdomain import SUBDOMAIN_WORDLIST
from modules.takeover import TAKEOVER_SIGNATURES


def test_url_normalization():
    assert _normalize_url("example.com") == "https://example.com"
    assert _normalize_url("http://example.com/") == "http://example.com"
    assert _normalize_url("https://sub.domain.co.uk/test/") == "https://sub.domain.co.uk/test"


def test_apex_domain_extraction():
    assert _extract_apex_domain("example.com") == "example.com"
    assert _extract_apex_domain("sub.example.com") == "example.com"
    assert _extract_apex_domain("test.sub.example.co.uk") == "example.co.uk"


def test_signatures_and_wordlists_integrity():
    assert len(VHOST_PREFIXES) >= 100
    assert len(PARAM_WORDLIST) >= 100
    assert len(GADGET_CDNS) >= 15
    assert len(FUZZ_TARGETS) >= 50
    assert len(SECRET_PATTERNS) >= 15
    assert len(COMMON_PORTS) >= 50
    assert len(SUBDOMAIN_WORDLIST) >= 300
    assert len(TAKEOVER_SIGNATURES) >= 30


def test_app_state_initialization(tmp_path: Path):
    cfg = ScanConfig(
        url="https://example.com",
        hostname="example.com",
        domain="example.com",
        scheme="https",
        port=443,
        timeout=5,
        max_subdomains=10,
        geoip_enabled=True,
        axfr_enabled=True,
        output_dir=tmp_path,
        max_concurrent=10,
    )
    state = AppState(config=cfg)

    # Verify all module statuses are initialized
    required_modules = [
        "DNS", "SUBDOMAINS", "HEADERS", "TECH", "WHOIS", "TLS",
        "PORTS", "ENDPOINTS", "FUZZ", "CLOUD", "TAKEOVER",
        "HARVEST", "WAF", "ASN", "PARAMS", "CSP", "VHOST"
    ]
    for mod in required_modules:
        assert mod in state.module_statuses
        assert state.module_statuses[mod].state == "PENDING"
