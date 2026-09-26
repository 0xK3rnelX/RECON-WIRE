"""Consolidated export engine — JSON, Markdown, and Plain-Text reports.

All format serializers live in this single file inside app/.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.export")


def _make_serializable(obj: Any) -> Any:
    """Recursively convert non-serializable types for JSON serialization."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return str(obj)


class _SafeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime, Path, dataclass, and custom types."""
    def default(self, o: Any) -> Any:
        return _make_serializable(o)


def export_json(state: AppState, filepath: Path | None = None) -> Path:
    """Serialize all scan results to a JSON file.

    Returns the path to the written file.
    """
    if filepath is None:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        domain = state.config.domain.replace(".", "_")
        filename = f"recon_wire_{domain}_{timestamp}.json"
        filepath = state.config.output_dir / filename

    filepath.parent.mkdir(parents=True, exist_ok=True)

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0}
    for f in state.findings:
        sev = getattr(f, "severity", "INFO")
        if sev in counts:
            counts[sev] += 1
        counts["total"] += 1

    report: dict[str, Any] = {
        "meta": {
            "tool": "RECON-WIRE",
            "version": "1.0.0",
            "scan_start": state.scan_start.isoformat(),
            "scan_complete": state.scan_complete,
            "elapsed_seconds": round(state.elapsed, 2),
            "export_time": datetime.utcnow().isoformat(),
        },
        "config": {
            "url": state.config.url,
            "hostname": state.config.hostname,
            "domain": state.config.domain,
            "scheme": state.config.scheme,
            "port": state.config.port,
            "timeout": state.config.timeout,
            "max_subdomains": state.config.max_subdomains,
            "geoip_enabled": state.config.geoip_enabled,
            "axfr_enabled": state.config.axfr_enabled,
            "max_concurrent": state.config.max_concurrent,
        },
        "findings": [f.to_dict() if hasattr(f, "to_dict") else _make_serializable(f) for f in state.findings],
        "findings_summary": counts,
        "dns": state.dns_results,
        "subdomains": [
            r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r)
            for r in state.subdomain_results
        ],
        "headers": state.header_results,
        "tech_stack": [
            r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r)
            for r in state.tech_results
        ],
        "whois": state.whois_results,
        "tls": state.tls_results,
        "ports": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.port_results],
        "endpoints": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.endpoint_results],
        "fuzzing": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.fuzz_results],
        "cloud_buckets": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.cloud_results],
        "waf": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.waf_results],
        "asn": state.asn_results,
        "takeover": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.takeover_results],
        "harvest": state.harvest_results,
        "params": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.param_results],
        "csp": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.csp_results],
        "vhosts": [r.to_dict() if hasattr(r, "to_dict") else _make_serializable(r) for r in state.vhost_results],
        "module_statuses": {

            name: {
                "state": ms.state,
                "progress": ms.progress,
                "message": ms.message,
            }
            for name, ms in state.module_statuses.items()
        },
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, cls=_SafeEncoder, ensure_ascii=False)
        logger.info("JSON report exported to %s", filepath)
    except Exception as exc:
        logger.error("JSON export failed: %s", exc, exc_info=True)
        raise

    return filepath


def export_markdown(state: AppState, filepath: Path | None = None) -> Path:
    """Build a comprehensive markdown security report and write to disk.

    Returns the path to the written file.
    """
    if filepath is None:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        domain = state.config.domain.replace(".", "_")
        filename = f"recon_wire_{domain}_{timestamp}.md"
        filepath = state.config.output_dir / filename

    filepath.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append("# RECON-WIRE Security Report")
    lines.append(f"**Target:** {state.config.url}  ")
    lines.append(f"**Domain:** {state.config.domain}  ")
    lines.append(f"**Scan Date:** {state.scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    elapsed = int(state.elapsed)
    mins, secs = divmod(elapsed, 60)
    lines.append(f"**Duration:** {mins}m {secs}s  ")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in state.findings:
        sev = getattr(f, "severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())

    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"| {sev} | {counts[sev]} |")
    lines.append(f"| **TOTAL** | **{total}** |")
    lines.append("")

    score = state.header_results.get("score")
    grade = state.header_results.get("grade")
    if score is not None:
        lines.append(f"**Header Security Score:** {score}/100 (Grade {grade})  \n")

    # Findings
    lines.append("## Findings")
    lines.append("")
    if state.findings:
        lines.append("| # | SEV | MODULE | TITLE | EVIDENCE |")
        lines.append("|---|-----|--------|-------|----------|")
        for i, f in enumerate(state.findings, 1):
            sev = getattr(f, "severity", "INFO")
            mod = getattr(f, "module", "?")
            title = getattr(f, "title", str(f))
            evidence = (getattr(f, "evidence", "") or "")[:100]
            lines.append(f"| {i} | {sev} | {mod} | {title} | {evidence} |")
        lines.append("")
    else:
        lines.append("*No findings detected.*  \n")

    # DNS
    lines.append("## DNS Records")
    lines.append("")
    if state.dns_results:
        lines.append("| TYPE | VALUE | TTL |")
        lines.append("|------|-------|-----|")
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]:
            for rec in state.dns_results.get(rtype, []):
                value = str(rec.get("value", ""))[:80]
                ttl = rec.get("ttl", "")
                lines.append(f"| {rtype} | `{value}` | {ttl} |")
        lines.append("")
    else:
        lines.append("*DNS results not available.*  \n")

    # Subdomains
    lines.append("## Subdomains")
    lines.append("")
    if state.subdomain_results:
        live = [r for r in state.subdomain_results if getattr(r, "is_live", False)]
        lines.append(f"**Resolved:** {len(state.subdomain_results)} | **Live:** {len(live)}\n")
        lines.append("| SUBDOMAIN | IP | STATUS | TITLE |")
        lines.append("|-----------|-----|--------|-------|")
        for r in state.subdomain_results[:100]:
            status = getattr(r, "status_code", "—") or "—"
            title = (getattr(r, "title", "—") or "—")[:40]
            lines.append(f"| {r.subdomain} | {r.ip} | {status} | {title} |")
        lines.append("")
    else:
        lines.append("*No subdomains discovered.*  \n")

    # Tech Stack
    lines.append("## Tech Stack")
    lines.append("")
    if state.tech_results:
        lines.append("| Technology | Version | Category |")
        lines.append("|------------|---------|----------|")
        for tech in state.tech_results:
            name = getattr(tech, "name", str(tech))
            version = getattr(tech, "version", "—") or "—"
            category = getattr(tech, "category", "?")
            lines.append(f"| {name} | {version} | {category} |")
        lines.append("")
    else:
        lines.append("*No technologies detected.*  \n")

    # WHOIS
    lines.append("## WHOIS")
    lines.append("")
    if state.whois_results:
        for k, v in state.whois_results.items():
            if not isinstance(v, (list, dict)):
                lines.append(f"- **{k}:** {v}")
        lines.append("")

    # TLS
    lines.append("## TLS / Certificate")
    lines.append("")
    if state.tls_results:
        leaf = state.tls_results.get("leaf_cert", {})
        if leaf:
            lines.append(f"- **Subject CN:** {leaf.get('subject_cn', 'N/A')}")
            lines.append(f"- **Issuer:** {leaf.get('issuer_cn', 'N/A')}")
            lines.append(f"- **Days Remaining:** {leaf.get('days_remaining', 'N/A')}")
        lines.append("")

    # Ports
    if state.port_results:
        lines.append("## Open Ports & Services")
        lines.append("")
        lines.append("| PORT | SERVICE | BANNER |")
        lines.append("|------|---------|--------|")
        for p in state.port_results:
            lines.append(f"| {p.port} | {p.service} | {p.banner or '—'} |")
        lines.append("")

    # Endpoints
    if state.endpoint_results:
        lines.append(f"## Discovered Endpoints ({len(state.endpoint_results)})")
        lines.append("")
        lines.append("| CATEGORY | METHOD | PATH / URL |")
        lines.append("|----------|--------|------------|")
        for ep in state.endpoint_results[:60]:
            lines.append(f"| {ep.category} | {ep.method} | `{ep.path}` |")
        lines.append("")

    # Fuzzing
    if state.fuzz_results:
        lines.append(f"## Exposed Files & Directories ({len(state.fuzz_results)})")
        lines.append("")
        lines.append("| STATUS | PATH | SIZE |")
        lines.append("|--------|------|------|")
        for f in state.fuzz_results:
            lines.append(f"| {f.status_code} | `{f.path}` | {f.content_length} bytes |")
        lines.append("")

    # Cloud
    if state.cloud_results:
        lines.append(f"## Cloud Storage Buckets ({len(state.cloud_results)})")
        lines.append("")
        lines.append("| PROVIDER | BUCKET | STATUS | URL |")
        lines.append("|----------|--------|--------|-----|")
        for cb in state.cloud_results:
            lines.append(f"| {cb.provider} | {cb.bucket_name} | {cb.status} | {cb.url} |")
        lines.append("")

    # WAF
    if state.waf_results:
        lines.append(f"## Web Application Firewall (WAF) ({len(state.waf_results)})")
        lines.append("")
        lines.append("| WAF / VENDOR | CONFIDENCE | VECTOR | DETAILS |")
        lines.append("|--------------|------------|--------|---------|")
        for w in state.waf_results:
            lines.append(f"| {w.name} ({w.vendor}) | {w.confidence} | {w.matched_vector} | {w.details} |")
        lines.append("")

    # ASN / BGP
    asn_nets = state.asn_results.get("networks", [])
    if asn_nets:
        lines.append(f"## Autonomous System & IP Routing (ASN / BGP) ({len(asn_nets)})")
        lines.append("")
        lines.append("| IP | ASN | ORGANIZATION | BGP PREFIX | COUNTRY |")
        lines.append("|----|-----|--------------|------------|---------|")
        for net in asn_nets:
            raw_asn = str(net.get("asn", "")).removeprefix("AS")
            asn_val = f"AS{raw_asn}" if raw_asn else "—"
            lines.append(f"| {net.get('ip', '')} | {asn_val} | {net.get('asn_org', '')} | {net.get('bgp_prefix', '')} | {net.get('country', '')} |")
        lines.append("")

    # Takeover
    if state.takeover_results:
        lines.append(f"## Subdomain Takeover Analysis ({len(state.takeover_results)})")
        lines.append("")
        lines.append("| STATUS | SUBDOMAIN | PROVIDER | CNAME | EVIDENCE |")
        lines.append("|--------|-----------|----------|-------|----------|")
        for t in state.takeover_results:
            status = "VULNERABLE" if t.vulnerable else "SAFE"
            lines.append(f"| {status} | `{t.subdomain}` | {t.provider} | `{t.cname}` | {t.verification_evidence} |")
        lines.append("")

    # Harvest
    emails = state.harvest_results.get("emails", [])
    secrets = state.harvest_results.get("secrets", [])
    if emails or secrets:
        lines.append("## Harvested Emails & Exposed Secrets")
        lines.append("")
        if emails:
            lines.append("### Discovered Emails")
            for e in emails:
                lines.append(f"- `{e}`")
            lines.append("")
        if secrets:
            lines.append("### Exposed Credentials & API Keys")
            lines.append("| TYPE | MASKED SECRET | ENTROPY | LOCATION |")
            lines.append("|------|---------------|---------|----------|")
            for s in secrets:
                lines.append(f"| {s.get('type')} | `{s.get('masked')}` | {s.get('entropy', 0.0):.2f} | `{s.get('url')}` |")
            lines.append("")

    # CSP
    if state.csp_results:
        lines.append("## Content Security Policy (CSP)")
        lines.append("")
        for csp_eval in state.csp_results:
            lines.append(f"**Score:** {csp_eval.score}/100 | **Grade:** {csp_eval.grade} | **Report-Only:** {'Yes' if csp_eval.report_only else 'No'}  \n")
            if csp_eval.bypass_vectors:
                lines.append(f"**Potential Bypasses:** {', '.join(csp_eval.bypass_vectors)}  \n")
            if csp_eval.flaws:
                lines.append("| SEV | DIRECTIVE | ISSUE | IMPACT / REMEDIATION |")
                lines.append("|-----|-----------|-------|----------------------|")
                for fl in csp_eval.flaws:
                    lines.append(f"| {fl.severity} | `{fl.directive}` | {fl.issue} | {fl.impact} - {fl.recommendation} |")
                lines.append("")

    # Params
    if state.param_results:
        lines.append(f"## Discovered Parameters ({len(state.param_results)})")
        lines.append("")
        lines.append("| PARAMETER | BEHAVIOR | ENDPOINT | EVIDENCE |")
        lines.append("|-----------|----------|----------|----------|")
        for pr in state.param_results:
            lines.append(f"| `{pr.param}` | {pr.anomaly_type} | `{pr.endpoint}` | {pr.evidence} |")
        lines.append("")

    # VHosts
    if state.vhost_results:
        lines.append(f"## Virtual Host Discovery ({len(state.vhost_results)})")
        lines.append("")
        lines.append("| HOST | IP | STATUS | TITLE | DIFFERENCE |")
        lines.append("|------|----|--------|-------|------------|")
        for vh in state.vhost_results:
            lines.append(f"| `{vh.host}` | {vh.ip} | {vh.status_code} | {vh.title} | {vh.diff_type} |")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by RECON-WIRE at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*")


    content = "\n".join(lines)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("Markdown report exported to %s", filepath)
    except Exception as exc:
        logger.error("Markdown export failed: %s", exc, exc_info=True)
        raise

    return filepath


def export_text(state: AppState, filepath: Path | None = None) -> Path:
    """Build a clean plain-text security report and write to disk.

    Returns the path to the written file.
    """
    if filepath is None:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        domain = state.config.domain.replace(".", "_")
        filename = f"recon_wire_{domain}_{timestamp}.txt"
        filepath = state.config.output_dir / filename

    lines: list[str] = []
    bar = "=" * 78
    subbar = "-" * 78

    lines.append(bar)
    lines.append(" RECON-WIRE RECONNAISSANCE REPORT")
    lines.append(bar)
    lines.append(f"Target URL   : {state.config.url}")
    lines.append(f"Hostname     : {state.config.hostname}")
    lines.append(f"Apex Domain  : {state.config.domain}")
    lines.append(f"Scan Started : {state.scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    elapsed = int(state.elapsed)
    mins, secs = divmod(elapsed, 60)
    lines.append(f"Duration     : {mins}m {secs}s")
    lines.append("")

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in state.findings:
        sev = getattr(f, "severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())

    lines.append(subbar)
    lines.append(f"FINDINGS SUMMARY: Total={total} (CRIT: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, MED: {counts['MEDIUM']}, LOW: {counts['LOW']}, INFO: {counts['INFO']})")
    lines.append(subbar)
    lines.append("")

    # DNS
    lines.append("[DNS RECORDS]")
    if state.dns_results:
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
            records = state.dns_results.get(rtype, [])
            for r in records:
                val = str(r.get("value", ""))
                ttl = str(r.get("ttl", ""))
                geo = r.get("geo")
                geo_str = f" | {geo.get('city', '')}, {geo.get('country', '')}" if isinstance(geo, dict) else ""
                lines.append(f"  {rtype:<6} {val:<45} (TTL: {ttl}){geo_str}")
    else:
        lines.append("  No DNS records found.")
    lines.append("")

    # Subdomains
    lines.append(f"[DISCOVERED SUBDOMAINS ({len(state.subdomain_results)})]")
    if state.subdomain_results:
        for s in state.subdomain_results:
            status = str(s.status_code) if getattr(s, "status_code", None) else ("200" if getattr(s, "is_live", False) else "404")
            ip = getattr(s, "ip", "N/A") or "N/A"
            srv = f" [{s.server}]" if getattr(s, "server", None) else ""
            lines.append(f"  {s.subdomain:<40} {ip:<18} [{status}]{srv}")
    else:
        lines.append("  No live subdomains identified.")
    lines.append("")

    # Technologies
    lines.append(f"[TECHNOLOGY STACK ({len(state.tech_results)})]")
    if state.tech_results:
        for t in state.tech_results:
            name = getattr(t, "name", str(t))
            cat = getattr(t, "category", "")
            ver = f" v{t.version}" if getattr(t, "version", None) else ""
            lines.append(f"  {name}{ver} ({cat})")
    else:
        lines.append("  No specific technology signatures detected.")
    lines.append("")

    # Headers
    lines.append("[HTTP HEADERS & SECURITY]")
    hdr = state.header_results
    if hdr:
        lines.append(f"  Status: {hdr.get('final_status', 'N/A')}")
        lines.append(f"  Server: {hdr.get('server', 'N/A')}")
        score = hdr.get("score")
        if score is not None:
            grade = hdr.get("grade", "F")
            lines.append(f"  Security Score: {score}/100 (Grade: {grade})")
        missing = hdr.get("missing_security_headers", [])
        if missing:
            lines.append(f"  Missing Security Headers: {', '.join(missing)}")
    else:
        lines.append("  No header data available.")
    lines.append("")

    # Ports
    if state.port_results:
        lines.append(f"[OPEN PORTS & SERVICES ({len(state.port_results)})]")
        for p in state.port_results:
            lines.append(f"  Port {p.port:<6} {p.service:<15} {p.banner}")
        lines.append("")

    # Endpoints
    if state.endpoint_results:
        lines.append(f"[DISCOVERED ENDPOINTS ({len(state.endpoint_results)})]")
        for ep in state.endpoint_results[:30]:
            lines.append(f"  [{ep.category:<6}] {ep.method:<4} {ep.path}")
        lines.append("")

    # Fuzzing
    if state.fuzz_results:
        lines.append(f"[EXPOSED FILES & DIRECTORIES ({len(state.fuzz_results)})]")
        for f in state.fuzz_results:
            lines.append(f"  [{f.status_code}] {f.path:<35} ({f.content_length} bytes)")
        lines.append("")

    # Cloud
    if state.cloud_results:
        lines.append(f"[PUBLIC CLOUD BUCKETS ({len(state.cloud_results)})]")
        for cb in state.cloud_results:
            lines.append(f"  [{cb.provider}] {cb.bucket_name} [{cb.status}] -> {cb.url}")
        lines.append("")

    # WAF
    if state.waf_results:
        lines.append(f"[WEB APPLICATION FIREWALL (WAF) ({len(state.waf_results)})]")
        for w in state.waf_results:
            lines.append(f"  [{w.confidence}] {w.name} ({w.vendor}) - Vector: {w.matched_vector}")
            if w.details:
                lines.append(f"      Signature: {w.details}")
        lines.append("")

    # ASN / BGP
    asn_nets = state.asn_results.get("networks", [])
    if asn_nets:
        lines.append(f"[ASN & BGP NETWORK INFRASTRUCTURE ({len(asn_nets)})]")
        for net in asn_nets:
            raw_asn = str(net.get('asn', '')).removeprefix('AS')
            asn_str = f"AS{raw_asn}" if raw_asn else "N/A"
            lines.append(f"  IP: {net.get('ip', 'N/A'):<16} {asn_str:<10} {net.get('asn_org', '')}")
            lines.append(f"      Prefix: {net.get('bgp_prefix', 'N/A')} | Country: {net.get('country', 'N/A')} | RIR: {net.get('rir', 'N/A')}")
        lines.append("")

    # Takeover
    if state.takeover_results:
        lines.append(f"[SUBDOMAIN TAKEOVER HUNTING ({len(state.takeover_results)})]")
        for t in state.takeover_results:
            badge = "VULNERABLE" if t.vulnerable else "SAFE"
            lines.append(f"  [{badge:<10}] {t.subdomain} -> {t.cname} ({t.provider})")
            if t.verification_evidence:
                lines.append(f"      Evidence: {t.verification_evidence}")
        lines.append("")

    # Harvest
    emails = state.harvest_results.get("emails", [])
    secrets = state.harvest_results.get("secrets", [])
    if emails or secrets:
        lines.append(f"[HARVESTED CREDENTIALS & EMAILS]")
        if emails:
            lines.append(f"  Emails ({len(emails)}): " + ", ".join(emails[:10]))
            if len(emails) > 10:
                lines.append(f"      ... and {len(emails) - 10} more")
        if secrets:
            lines.append(f"  Secrets/Keys ({len(secrets)}):")
            for s in secrets:
                lines.append(f"    - [{s.get('type')}] {s.get('masked')} (Entropy: {s.get('entropy', 0.0):.2f}) at {s.get('url')}")
        lines.append("")

    # CSP
    if state.csp_results:
        lines.append("[CONTENT SECURITY POLICY (CSP)]")
        for csp_eval in state.csp_results:
            lines.append(f"  Score: {csp_eval.score}/100 (Grade: {csp_eval.grade}) | Report-Only: {'Yes' if csp_eval.report_only else 'No'}")
            for fl in csp_eval.flaws:
                lines.append(f"    [{fl.severity:<5}] {fl.directive}: {fl.issue}")
            for bp in csp_eval.bypass_vectors:
                lines.append(f"    [BYPASS] {bp}")
        lines.append("")

    # Params
    if state.param_results:
        lines.append(f"[DISCOVERED QUERY PARAMETERS ({len(state.param_results)})]")
        for pr in state.param_results:
            lines.append(f"  [{pr.anomaly_type:<10}] {pr.param:<16} at {pr.endpoint}")
            if pr.evidence:
                lines.append(f"      Evidence: {pr.evidence}")
        lines.append("")

    # VHosts
    if state.vhost_results:
        lines.append(f"[VIRTUAL HOST DISCOVERY ({len(state.vhost_results)})]")
        for vh in state.vhost_results:
            lines.append(f"  [{vh.status_code}] {vh.host:<35} (IP: {vh.ip}) | Diff: {vh.diff_type}")
            if vh.title and vh.title != "—":
                lines.append(f"      Title: {vh.title}")
        lines.append("")

    # Findings
    lines.append(f"[SECURITY FINDINGS ({len(state.findings)})]")
    if state.findings:
        for idx, f in enumerate(state.findings, 1):
            sev = getattr(f, "severity", "INFO")
            title = getattr(f, "title", str(f))
            mod = getattr(f, "module", "RECON")
            detail = getattr(f, "detail", "")
            lines.append(f"  #{idx:<2} [{sev:<8}] [{mod}] {title}")
            if detail:
                lines.append(f"      Detail: {detail}")
    else:
        lines.append("  Clean scan — no security findings.")
    lines.append("")

    lines.append(bar)
    lines.append(f"Report generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} by RECON-WIRE")
    lines.append(bar)

    filepath.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(lines)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("Text report exported to %s", filepath)
    except Exception as exc:
        logger.error("Text export failed: %s", exc, exc_info=True)
        raise

    return filepath


def export_sarif(state: AppState, filepath: Path | None = None) -> Path:
    """Build OASIS SARIF v2.1.0 standard security format for CI/CD and GitHub Security (P3-3)."""
    if filepath is None:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        domain = state.config.domain.replace(".", "_")
        filename = f"recon_wire_{domain}_{timestamp}.sarif"
        filepath = state.config.output_dir / filename

    filepath.parent.mkdir(parents=True, exist_ok=True)

    # Convert findings to SARIF rules & results
    sarif_level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids: set[str] = set()

    for idx, f in enumerate(state.findings, 1):
        rule_id = f"RW-{f.module[:4]}-{abs(hash(f.title)) % 10000:04d}"
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.detail or f.title},
                "defaultConfiguration": {
                    "level": sarif_level_map.get(getattr(f, "severity", "INFO"), "note")
                },
                "properties": {
                    "tags": ["security", "recon", f.module.lower()]
                }
            })

        results.append({
            "ruleId": rule_id,
            "level": sarif_level_map.get(getattr(f, "severity", "INFO"), "note"),
            "message": {
                "text": f"{f.title}: {f.detail}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": state.config.url
                        }
                    }
                }
            ],
            "properties": {
                "evidence": getattr(f, "evidence", ""),
                "severity": getattr(f, "severity", "INFO"),
            }
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RECON-WIRE",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/0xK3rnelX/recon-wire",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ]
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2, ensure_ascii=False)
        logger.info("SARIF report exported to %s", filepath)
    except Exception as exc:
        logger.error("SARIF export failed: %s", exc, exc_info=True)
        raise

    return filepath

