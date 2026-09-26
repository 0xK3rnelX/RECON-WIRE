"""CLI argument parsing, URL validation, and pre-flight checks.

Returns a ScanConfig on success, prints to stderr and sys.exit(1) on failure.
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

from app.state import ScanConfig


def _extract_apex_domain(hostname: str) -> str:
    """Best-effort apex domain extraction (no PSL dependency).

    Handles common TLDs like .co.uk, .com.au, .org.uk etc.
    Falls back to last two labels for standard TLDs.
    """
    COMPOUND_TLDS = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au",
        "co.nz", "net.nz", "org.nz",
        "co.za", "org.za", "web.za",
        "co.in", "net.in", "org.in",
        "co.jp", "or.jp", "ne.jp",
        "com.br", "net.br", "org.br",
        "com.mx", "org.mx", "net.mx",
        "com.cn", "net.cn", "org.cn",
        "co.kr", "or.kr", "ne.kr",
        "com.sg", "org.sg", "net.sg",
        "com.hk", "org.hk", "net.hk",
        "co.il", "org.il", "net.il",
        "com.tw", "org.tw", "net.tw",
        "co.th", "or.th", "in.th",
        "com.tr", "org.tr", "net.tr",
    }
    parts = hostname.rstrip(".").split(".")
    if len(parts) <= 2:
        return hostname
    # Check if last two labels form a compound TLD
    potential_compound = ".".join(parts[-2:])
    if potential_compound in COMPOUND_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalize_url(raw: str) -> str:
    """Ensure scheme is present, strip trailing slash."""
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw.rstrip("/")


def _preflight_dns(hostname: str) -> bool:
    """Resolve hostname via socket.getaddrinfo — return True if it resolves."""
    try:
        socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return True
    except (socket.gaierror, OSError):
        return False


def parse_and_validate() -> ScanConfig:
    """Parse CLI args, validate, return ScanConfig or die."""
    parser = argparse.ArgumentParser(
        prog="recon-wire",
        description="RECON-WIRE — Production-grade web reconnaissance TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py https://example.com\n"
            "  python main.py https://example.com --timeout 15 --subdomains 500\n"
            "  python main.py https://example.com --no-geoip --rate 100\n"
        ),
    )
    parser.add_argument("url", help="Target URL (http:// or https://)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--subdomains", type=int, default=200, help="Max subdomains to brute-force (default: 200)")
    parser.add_argument("--no-geoip", dest="geoip_enabled", action="store_false", help="Disable GeoIP lookups")
    parser.add_argument("--no-axfr", dest="axfr_enabled", action="store_false", help="Disable AXFR zone transfer attempts")
    parser.add_argument("--output-dir", type=Path, default=Path("."), help="Base export output directory (default: cwd)")
    parser.add_argument("--rate", type=int, default=50, dest="max_concurrent", help="Max concurrent requests (default: 50)")

    # Output options — default is terminal text output only (no file saved)
    parser.add_argument("--json", "-oJ", nargs="?", const="", default=None, metavar="FILE", help="Save scan results to JSON file (optional filepath)")
    parser.add_argument("--markdown", "--md", "-oM", nargs="?", const="", default=None, metavar="FILE", help="Save scan results to Markdown report (optional filepath)")
    parser.add_argument("--text", "--txt", "-oT", nargs="?", const="", default=None, metavar="FILE", help="Save scan results to plain text file (optional filepath)")
    parser.add_argument("--sarif", "-oS", nargs="?", const="", default=None, metavar="FILE", help="Save scan results in SARIF format for CI/CD / GitHub Security (optional filepath)")

    # P2-2: Adaptive rate limiting & stealth options
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between requests for stealth (default: 0.0)")
    parser.add_argument("--jitter", type=float, default=0.0, help="Max random jitter added to delay (default: 0.0)")
    parser.add_argument("--user-agent", "-ua", type=str, default=None, help="Custom User-Agent header (or 'random' for pool rotation)")

    # Vector modules toggles
    parser.add_argument("--no-ports", dest="scan_ports", action="store_false", help="Disable port scanner module")
    parser.add_argument("--no-endpoints", dest="scan_endpoints", action="store_false", help="Disable web crawl and endpoint discovery")
    parser.add_argument("--no-fuzz", dest="scan_fuzz", action="store_false", help="Disable sensitive file and directory fuzzing")
    parser.add_argument("--no-cloud", dest="scan_cloud", action="store_false", help="Disable public cloud bucket hunting")
    parser.add_argument("--no-takeover", dest="scan_takeover", action="store_false", help="Disable subdomain takeover detection")
    parser.add_argument("--no-harvest", dest="scan_harvest", action="store_false", help="Disable email and secret harvesting")
    parser.add_argument("--no-waf", dest="scan_waf", action="store_false", help="Disable WAF fingerprinting")
    parser.add_argument("--no-asn", dest="scan_asn", action="store_false", help="Disable IP range and ASN lookup")
    parser.add_argument("--no-params", dest="scan_params", action="store_false", help="Disable hidden parameter discovery")
    parser.add_argument("--no-csp", dest="scan_csp", action="store_false", help="Disable Content Security Policy evaluation")
    parser.add_argument("--no-vhost", dest="scan_vhost", action="store_false", help="Disable virtual host brute forcing")
    parser.set_defaults(
        geoip_enabled=True, axfr_enabled=True, scan_ports=True, scan_endpoints=True,
        scan_fuzz=True, scan_cloud=True, scan_takeover=True, scan_harvest=True,
        scan_waf=True, scan_asn=True, scan_params=True, scan_csp=True, scan_vhost=True
    )



    args = parser.parse_args()

    # ── Normalize URL ──
    url = _normalize_url(args.url)
    parsed = urlparse(url)

    # ── Validate scheme ──
    if parsed.scheme not in ("http", "https"):
        print(f"[ERROR] Invalid scheme '{parsed.scheme}'. Use http:// or https://", file=sys.stderr)
        sys.exit(1)

    hostname = parsed.hostname or ""
    if not hostname:
        print(f"[ERROR] Could not extract hostname from '{url}'", file=sys.stderr)
        sys.exit(1)

    # ── Determine port ──
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if parsed.scheme == "https" else 80

    # ── Pre-flight DNS ──
    if not _preflight_dns(hostname):
        print(f"[ERROR] DNS resolution failed for '{hostname}'. Target unreachable.", file=sys.stderr)
        sys.exit(1)

    # ── Validate / create output dir ──
    output_dir: Path = args.output_dir
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"[ERROR] Cannot create output directory '{output_dir}': {exc}", file=sys.stderr)
        sys.exit(1)

    domain = _extract_apex_domain(hostname)

    # ── Parse output file destinations if requested ──
    clean_domain = domain.replace(".", "_")
    output_json_path: Path | None = None
    if args.json is not None:
        if args.json == "":
            output_json_path = output_dir / f"recon_wire_{clean_domain}.json"
        else:
            output_json_path = Path(args.json)

    output_md_path: Path | None = None
    if args.markdown is not None:
        if args.markdown == "":
            output_md_path = output_dir / f"recon_wire_{clean_domain}.md"
        else:
            output_md_path = Path(args.markdown)

    output_txt_path: Path | None = None
    if args.text is not None:
        if args.text == "":
            output_txt_path = output_dir / f"recon_wire_{clean_domain}.txt"
        else:
            output_txt_path = Path(args.text)

    output_sarif_path: Path | None = None
    if args.sarif is not None:
        if args.sarif == "":
            output_sarif_path = output_dir / f"recon_wire_{clean_domain}.sarif"
        else:
            output_sarif_path = Path(args.sarif)

    return ScanConfig(
        url=url,
        hostname=hostname,
        domain=domain,
        scheme=parsed.scheme,
        port=port,
        timeout=args.timeout,
        max_subdomains=args.subdomains,
        geoip_enabled=args.geoip_enabled,
        axfr_enabled=args.axfr_enabled,
        output_dir=output_dir.resolve(),
        max_concurrent=args.max_concurrent,
        output_json=output_json_path.resolve() if output_json_path else None,
        output_markdown=output_md_path.resolve() if output_md_path else None,
        output_text=output_txt_path.resolve() if output_txt_path else None,
        output_sarif=output_sarif_path.resolve() if output_sarif_path else None,
        delay=max(0.0, args.delay),
        jitter=max(0.0, args.jitter),
        user_agent=args.user_agent,
        scan_ports=args.scan_ports,
        scan_endpoints=args.scan_endpoints,
        scan_fuzz=args.scan_fuzz,
        scan_cloud=args.scan_cloud,
        scan_takeover=args.scan_takeover,
        scan_harvest=args.scan_harvest,
        scan_waf=args.scan_waf,
        scan_asn=args.scan_asn,
        scan_params=args.scan_params,
        scan_csp=args.scan_csp,
        scan_vhost=args.scan_vhost,
    )


