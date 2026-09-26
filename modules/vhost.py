"""Virtual Host (VHost) & Reverse Host Prober Module (PC-2).

Discovers undocumented internal services, staging environments, and administrative
virtual hosts co-located on the same physical web server by injecting dynamic
Host and X-Forwarded-Host headers directly against the resolved server IP.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from dataclasses import dataclass, asdict
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from modules.findings import push_finding
from modules.stealth import apply_stealth_delay

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.vhost")

# Comprehensive enterprise virtual host candidate prefixes (100+ high-value targets)
VHOST_PREFIXES: list[str] = [
    # Administration & Portals
    "admin", "administrator", "root", "corp", "internal", "intranet", "portal",
    "staff", "employee", "team", "dashboard", "panel", "console", "control",
    "cpanel", "whm", "webmin", "cockpit", "superadmin", "manage", "management",
    
    # Development, Staging & QA
    "dev", "develop", "development", "stage", "staging", "stg", "test", "testing",
    "qa", "uat", "beta", "alpha", "sandbox", "preview", "demo", "lab", "poc",
    "old", "new", "legacy", "v2", "v3", "temp", "tmp", "bak", "backup",
    
    # API & Microservices
    "api", "api-dev", "api-stage", "api-internal", "api-v1", "api-v2", "api-v3",
    "apis", "rest", "graphql", "grpc", "gateway", "apigateway", "proxy", "reverse-proxy",
    "router", "ingress", "edge", "broker", "event", "events", "stream", "webhook", "webhooks",
    
    # Authentication & Access Control
    "auth", "authentication", "login", "signin", "sso", "idp", "saml", "oauth",
    "oauth2", "identity", "keycloak", "okta", "auth0", "cas", "iam", "account",
    "accounts", "user", "users", "profile", "secure", "security", "pass", "vault",
    
    # Network, VPN & Remote Access
    "vpn", "remote", "rdp", "ssh", "gateway", "connect", "access", "anyconnect",
    "pulse", "wireguard", "openvpn", "citrix", "teleport", "bastion", "jump",
    
    # CI/CD, Repositories & Build
    "git", "gitlab", "github", "bitbucket", "gitea", "gogs", "repo", "svn",
    "jenkins", "ci", "cd", "bamboo", "teamcity", "circleci", "argo", "argocd",
    "drone", "spinnaker", "sonar", "sonarqube", "nexus", "artifactory", "registry", "harbor",
    
    # Container & Cloud Orchestration
    "k8s", "kubernetes", "rancher", "docker", "swarm", "openshift", "nomad",
    "consul", "istio", "traefik", "envoy", "kong", "mesh", "cluster",
    
    # Monitoring, Logging & Telemetry
    "monitor", "monitoring", "grafana", "kibana", "prometheus", "alertmanager",
    "elastic", "elasticsearch", "opensearch", "jaeger", "zipkin", "zabbix",
    "nagios", "datadog", "graylog", "splunk", "sentry", "status", "health",
    
    # Databases & Storage
    "db", "database", "sql", "mysql", "postgres", "postgresql", "mongo", "mongodb",
    "redis", "memcached", "couchdb", "neo4j", "influxdb", "clickhouse",
    "phpmyadmin", "pma", "adminer", "pgadmin", "storage", "s3", "minio", "bucket",
    
    # Communications & Productivity
    "mail", "webmail", "email", "exchange", "owa", "roundcube", "zimbra", "smtp",
    "confluence", "jira", "wiki", "docs", "chat", "mattermost", "slack", "rocketchat"
]


@dataclass
class VHostResult:
    """Represents a discovered virtual host responding distinctly on the server IP."""
    host: str
    ip: str
    status_code: int
    content_length: int
    title: str
    diff_type: str           # STATUS_CODE | LENGTH_DIFF | TITLE_DIFF
    confidence: str          # HIGH | MEDIUM

    def to_dict(self) -> dict:
        return asdict(self)


def _extract_title(html: str) -> str:
    """Extract HTML <title> text."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:50]
    return ""


class VHostModule:
    """Probes web server IP with arbitrary Host headers to uncover hidden virtual hosts."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def run(self) -> list[VHostResult]:
        """Execute virtual host brute forcing."""
        cfg = self.state.config
        status = self.state.module_statuses.get("VHOST")
        if status:
            status.state = "RUNNING"
            status.message = "Resolving target IP for VHost enumeration"
            status.progress = 10

        results: list[VHostResult] = []

        # 1. Determine target IP
        target_ip = None
        a_records = self.state.dns_results.get("A", [])
        if a_records:
            target_ip = a_records[0].get("value")

        if not target_ip:
            try:
                loop = asyncio.get_running_loop()
                target_ip = await loop.run_in_executor(None, socket.gethostbyname, cfg.hostname)
            except Exception as exc:
                logger.warning("Could not resolve IP for VHost testing: %s", exc)
                if status:
                    status.state = "DONE"
                    status.progress = 100
                    status.message = "No target IP found"
                return []

        # 2. Build candidate VHost list
        candidates: list[str] = []
        domain = cfg.domain
        for prefix in VHOST_PREFIXES:
            candidates.append(f"{prefix}.{domain}")
            candidates.append(f"{prefix}.{cfg.hostname}")
            candidates.append(f"{prefix}-internal.{domain}")
        candidates.extend(["localhost", "127.0.0.1", f"intra.{domain}"])

        # Deduplicate
        candidates = list(dict.fromkeys(candidates))

        scheme = cfg.scheme or "http"
        port_str = f":{cfg.port}" if cfg.port not in (80, 443) else ""
        base_probe_url = f"{scheme}://{target_ip}{port_str}/"

        sem = asyncio.Semaphore(min(cfg.max_concurrent, 10))
        dummy_canary_host = "rw-dummy-vhost-canary-9999.invalid"

        try:
            # Custom HTTP transport with SSL verification disabled for raw IP/Host testing
            async with httpx.AsyncClient(
                verify=False,
                timeout=cfg.timeout,
                follow_redirects=False,
                limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
            ) as client:

                # 3. Establish Baseline Response with non-existent host header
                baseline_resp = None
                for candidate_scheme in ([scheme, "http"] if scheme == "https" else [scheme]):
                    candidate_port = port_str if candidate_scheme == scheme else ""
                    test_probe_url = f"{candidate_scheme}://{target_ip}{candidate_port}/"
                    try:
                        baseline_resp = await client.get(test_probe_url, headers={"Host": dummy_canary_host})
                        base_probe_url = test_probe_url
                        break
                    except Exception:
                        try:
                            baseline_resp = await client.get(test_probe_url, headers={"Host": target_ip})
                            base_probe_url = test_probe_url
                            break
                        except Exception:
                            continue

                if not baseline_resp:
                    if status:
                        status.state = "DONE"
                        status.progress = 100
                        status.message = "Target IP unreachable"
                    return []

                base_status = baseline_resp.status_code
                base_len = len(baseline_resp.content)
                base_title = _extract_title(baseline_resp.text)

                total = len(candidates)
                completed = 0

                async def probe_vhost(host_cand: str) -> None:
                    nonlocal completed
                    async with sem:
                        await apply_stealth_delay(self.state)
                        try:
                            resp = await client.get(
                                base_probe_url,
                                headers={
                                    "Host": host_cand,
                                    "X-Forwarded-Host": host_cand,
                                }
                            )
                            c_status = resp.status_code
                            c_len = len(resp.content)
                            c_title = _extract_title(resp.text)

                            # Ignore identical responses to dummy baseline
                            if c_status == base_status and abs(c_len - base_len) <= 16 and c_title == base_title:
                                return

                            # Detect distinct virtual host response
                            diff_type = None
                            conf = "MEDIUM"

                            if c_status != base_status:
                                diff_type = "STATUS_CODE"
                                if c_status in (200, 301, 302, 401):
                                    conf = "HIGH"
                            elif c_title and c_title != base_title:
                                diff_type = "TITLE_DIFF"
                                conf = "HIGH"
                            elif abs(c_len - base_len) > 100:
                                diff_type = "LENGTH_DIFF"
                                conf = "MEDIUM"

                            if diff_type:
                                results.append(VHostResult(
                                    host=host_cand,
                                    ip=target_ip,
                                    status_code=c_status,
                                    content_length=c_len,
                                    title=c_title or "—",
                                    diff_type=diff_type,
                                    confidence=conf,
                                ))
                        except Exception:
                            pass
                        finally:
                            completed += 1
                            if status and total > 0:
                                status.progress = min(95, 10 + int((completed / total) * 85))

                tasks = [probe_vhost(c) for c in candidates]
                await asyncio.gather(*tasks)

        except Exception as exc:
            logger.error("VHost enumeration error: %s", exc, exc_info=True)

        # De-duplicate results
        seen = set()
        deduped: list[VHostResult] = []
        for r in results:
            if r.host not in seen:
                seen.add(r.host)
                deduped.append(r)

        self.state.vhost_results = deduped

        # Generate findings for discovered virtual hosts
        for v in deduped:
            if v.confidence == "HIGH" or v.status_code in (200, 301, 302, 401):
                await push_finding(
                    self.state.findings_queue,
                    module="VHOST",
                    severity="HIGH" if v.status_code in (200, 401) else "MEDIUM",
                    title=f"Virtual Host Discovered: {v.host} (HTTP {v.status_code})",
                    detail=f"Target web server at {v.ip} accepted Host '{v.host}' with HTTP {v.status_code}. Title: '{v.title}'. Possible unlinked internal interface or staging site.",
                    evidence=f"Host: {v.host} against {base_probe_url} yielded length {v.content_length} bytes (baseline was {base_len} bytes)",
                )

        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(deduped)} virtual hosts discovered"

        return deduped
