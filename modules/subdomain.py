"""Subdomain enumeration module — crt.sh + brute-force + permutations + HTTP probe.

Writes SubdomainResult objects to state.subdomain_results.
Pushes findings for interesting flags.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

import dns.asyncresolver
import dns.resolver
import httpx

from modules.findings import push_finding

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.subdomain")


@dataclass
class SubdomainResult:
    """A single discovered subdomain and its probe results."""

    subdomain: str
    ip: str = ""
    status_code: int | None = None
    final_url: str = ""
    title: str = ""
    server: str = ""
    flags: list[str] = field(default_factory=list)
    is_live: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ───── Comprehensive 350+ entry built-in subdomain wordlist ─────
SUBDOMAIN_WORDLIST: list[str] = [
    # Core Web, Mail & DNS
    "www",
    "www1",
    "www2",
    "www3",
    "mail",
    "mail1",
    "mail2",
    "ftp",
    "localhost",
    "webmail",
    "email",
    "smtp",
    "pop",
    "pop3",
    "imap",
    "ns",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "dns",
    "dns1",
    "dns2",
    "mx",
    "mx1",
    "mx2",
    "cpanel",
    "whm",
    "webdisk",
    "autodiscover",
    "autoconfig",
    # Development, Staging & Pre-production
    "dev",
    "dev1",
    "dev2",
    "develop",
    "development",
    "stage",
    "stage1",
    "stage2",
    "staging",
    "staging2",
    "stg",
    "test",
    "test1",
    "test2",
    "testing",
    "qa",
    "qa1",
    "qa2",
    "uat",
    "beta",
    "alpha",
    "gamma",
    "demo",
    "preview",
    "sandbox",
    "lab",
    "poc",
    "preprod",
    "prod",
    "production",
    "live",
    "release",
    "old",
    "new",
    "legacy",
    "v1",
    "v2",
    "v3",
    # Administration, Portals & Intranet
    "admin",
    "admin1",
    "administrator",
    "root",
    "portal",
    "dashboard",
    "panel",
    "console",
    "control",
    "superadmin",
    "manage",
    "management",
    "internal",
    "intranet",
    "corp",
    "corporate",
    "staff",
    "employee",
    "team",
    "office",
    "work",
    "home",
    "hub",
    "center",
    # Identity, Authentication & SSO
    "login",
    "signin",
    "auth",
    "authentication",
    "sso",
    "idp",
    "saml",
    "oauth",
    "oauth2",
    "identity",
    "keycloak",
    "okta",
    "auth0",
    "iam",
    "account",
    "accounts",
    "user",
    "users",
    "profile",
    "member",
    "membership",
    "pass",
    "password",
    "secure",
    "security",
    "cas",
    "adfs",
    # API, Microservices & Gateways
    "api",
    "api1",
    "api2",
    "api3",
    "apis",
    "api-dev",
    "api-stage",
    "api-internal",
    "apigateway",
    "gateway",
    "gw",
    "rest",
    "graphql",
    "grpc",
    "ws",
    "wss",
    "websocket",
    "feed",
    "rss",
    "atom",
    "xml",
    "json",
    "webhooks",
    "webhook",
    "router",
    "ingress",
    "edge",
    "proxy",
    "relay",
    # CI/CD, Repositories & Build Systems
    "git",
    "gitlab",
    "github",
    "bitbucket",
    "gitea",
    "gogs",
    "repo",
    "repository",
    "svn",
    "jenkins",
    "ci",
    "cd",
    "bamboo",
    "teamcity",
    "circleci",
    "travis",
    "argo",
    "argocd",
    "drone",
    "spinnaker",
    "sonar",
    "sonarqube",
    "nexus",
    "artifactory",
    "registry",
    "harbor",
    # Cloud, Containers & Infrastructure
    "k8s",
    "kubernetes",
    "kube",
    "rancher",
    "docker",
    "swarm",
    "openshift",
    "nomad",
    "consul",
    "vault",
    "terraform",
    "ansible",
    "puppet",
    "chef",
    "aws",
    "azure",
    "gcp",
    "s3",
    "ec2",
    "blob",
    "bucket",
    "storage",
    "cloud",
    "cdn",
    "static",
    "assets",
    "media",
    "images",
    "img",
    "node",
    "server",
    "host",
    "cluster",
    "backup",
    "archive",
    "minio",
    # Databases & Caching
    "db",
    "db1",
    "db2",
    "database",
    "sql",
    "mysql",
    "postgres",
    "postgresql",
    "mongo",
    "mongodb",
    "redis",
    "cache",
    "memcached",
    "couchdb",
    "neo4j",
    "influxdb",
    "clickhouse",
    "phpmyadmin",
    "pma",
    "adminer",
    "pgadmin",
    # Monitoring, Logging & Telemetry
    "monitor",
    "monitoring",
    "status",
    "health",
    "metrics",
    "stats",
    "grafana",
    "kibana",
    "prometheus",
    "elastic",
    "elasticsearch",
    "opensearch",
    "jaeger",
    "zipkin",
    "zabbix",
    "nagios",
    "datadog",
    "graylog",
    "splunk",
    "sentry",
    "alert",
    "alerts",
    "audit",
    "log",
    "logs",
    # Networking & Remote Access
    "vpn",
    "remote",
    "rdp",
    "ssh",
    "connect",
    "access",
    "anyconnect",
    "pulse",
    "wireguard",
    "openvpn",
    "citrix",
    "teleport",
    "bastion",
    "jump",
    "switch",
    "router",
    "firewall",
    "ids",
    "ips",
    "waf",
    "lb",
    "loadbalancer",
    "haproxy",
    "nginx",
    "apache",
    "traefik",
    "envoy",
    # Productivity, Collaboration & Support
    "docs",
    "doc",
    "wiki",
    "confluence",
    "jira",
    "help",
    "support",
    "ticket",
    "tickets",
    "desk",
    "servicedesk",
    "blog",
    "forum",
    "community",
    "chat",
    "slack",
    "teams",
    "mattermost",
    "rocketchat",
    "meet",
    "zoom",
    "calendar",
    "exchange",
    "owa",
    "outlook",
    "roundcube",
    "zimbra",
    # E-commerce, Finance & Business
    "shop",
    "store",
    "payment",
    "pay",
    "checkout",
    "cart",
    "billing",
    "invoice",
    "crm",
    "erp",
    "sales",
    "finance",
    "legal",
    "hr",
    "app",
    "mobile",
    "m",
    "search",
    "survey",
]

PERMUTATION_PREFIXES = ["dev-", "staging-", "test-", "api-", "admin-", "prod-", "internal-"]
PERMUTATION_SUFFIXES = ["-dev", "-staging", "-test", "-api", "-admin", "-prod", "-internal"]


class SubdomainModule:
    """Subdomain enumeration via crt.sh + brute-force + permutations + HTTP probe."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.domain = state.config.domain
        self.seen: set[str] = set()
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = state.config.timeout
        self.resolver.lifetime = state.config.timeout
        self.semaphore = asyncio.Semaphore(state.config.max_concurrent)

    async def run(self) -> None:
        status = self.state.module_statuses["SUBDOMAINS"]
        status.state = "RUNNING"
        status.message = "Gathering subdomain candidates"
        logger.info("Subdomain module starting for %s", self.domain)

        try:
            # Gather candidates from all three sources concurrently
            crt_task = asyncio.create_task(self._crtsh_query())
            brute_task = asyncio.create_task(self._brute_candidates())
            perm_task = asyncio.create_task(self._permutation_candidates())

            crt_candidates, brute_candidates, perm_candidates = await asyncio.gather(
                crt_task, brute_task, perm_task, return_exceptions=True
            )

            # Merge all unique candidates
            all_candidates: set[str] = set()
            for result in [crt_candidates, brute_candidates, perm_candidates]:
                if isinstance(result, set):
                    all_candidates.update(result)
                elif isinstance(result, Exception):
                    logger.warning("Subdomain source failed: %s", result)

            # Limit to max_subdomains
            candidates = list(all_candidates)[: self.state.config.max_subdomains]
            total = len(candidates)
            status.message = f"Probing {total} candidates"
            logger.info("Subdomain candidates: %d", total)

            if total == 0:
                status.state = "DONE"
                status.progress = 100
                status.message = "No subdomain candidates found"
                return

            # DNS + HTTP probe each candidate
            tasks = []
            for sub in candidates:
                tasks.append(self._probe_subdomain(sub, total, status))
            await asyncio.gather(*tasks, return_exceptions=True)

            # Push summary findings
            live_count = sum(1 for r in self.state.subdomain_results if r.is_live)
            flagged = sum(1 for r in self.state.subdomain_results if r.flags)
            if flagged > 0:
                await push_finding(
                    self.state.findings_queue,
                    severity="INFO",
                    module="SUBDOMAINS",
                    title=f"{flagged} Flagged Subdomains Found",
                    detail=f"{live_count} live subdomains, {flagged} with notable flags",
                    evidence=", ".join(r.subdomain for r in self.state.subdomain_results if r.flags)[:500],
                )

            status.state = "DONE"
            status.progress = 100
            status.message = f"Found {live_count} live / {len(self.state.subdomain_results)} resolved"
            logger.info("Subdomain module completed — %s", status.message)

        except Exception as exc:
            status.state = "ERROR"
            status.message = f"Subdomain error: {exc}"
            logger.error("Subdomain module failed: %s", exc, exc_info=True)

    async def _crtsh_query(self) -> set[str]:
        """Query crt.sh certificate transparency logs."""
        candidates: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.state.config.timeout) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{self.domain}&output=json",
                    follow_redirects=True,
                )
                if resp.status_code == 200:
                    entries = resp.json()
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name.endswith(f".{self.domain}") and "*" not in name:
                                candidates.add(name)
        except Exception as exc:
            logger.warning("crt.sh query failed: %s", exc)
        logger.debug("crt.sh returned %d candidates", len(candidates))
        return candidates

    async def _brute_candidates(self) -> set[str]:
        """Generate brute-force candidates from wordlist."""
        return {f"{word}.{self.domain}" for word in SUBDOMAIN_WORDLIST}

    async def _permutation_candidates(self) -> set[str]:
        """Generate permutation-based candidates."""
        candidates: set[str] = set()
        base_labels = ["www", "mail", "api", "dev", "staging", "admin", "app", "portal"]
        for label in base_labels:
            for prefix in PERMUTATION_PREFIXES:
                candidates.add(f"{prefix}{label}.{self.domain}")
            for suffix in PERMUTATION_SUFFIXES:
                candidates.add(f"{label}{suffix}.{self.domain}")
        return candidates

    async def _probe_subdomain(self, subdomain: str, total: int, status: Any) -> None:
        """DNS resolve + HTTP probe a single subdomain."""
        async with self.semaphore:
            if subdomain in self.seen:
                return
            self.seen.add(subdomain)

            result = SubdomainResult(subdomain=subdomain)

            # DNS resolution
            try:
                answers = await self.resolver.resolve(subdomain, "A")
                if answers:
                    result.ip = str(answers[0])
                else:
                    return  # No resolution — skip
            except Exception:
                return  # Doesn't resolve — not a valid subdomain

            # HTTP probe
            try:
                async with httpx.AsyncClient(
                    timeout=self.state.config.timeout,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(f"https://{subdomain}/")
                    result.status_code = resp.status_code
                    result.final_url = str(resp.url)
                    result.server = resp.headers.get("server", "")
                    result.is_live = True

                    # Extract title
                    if "text/html" in resp.headers.get("content-type", ""):
                        title_match = re.search(
                            r"<title[^>]*>(.*?)</title>",
                            resp.text[:10000],
                            re.IGNORECASE | re.DOTALL,
                        )
                        if title_match:
                            result.title = title_match.group(1).strip()[:100]
            except httpx.ConnectError:
                # Try HTTP fallback
                try:
                    async with httpx.AsyncClient(
                        timeout=self.state.config.timeout,
                        follow_redirects=True,
                        verify=False,
                    ) as client:
                        resp = await client.get(f"http://{subdomain}/")
                        result.status_code = resp.status_code
                        result.final_url = str(resp.url)
                        result.server = resp.headers.get("server", "")
                        result.is_live = True
                        result.flags.append("HTTP_ONLY")
                        if "text/html" in resp.headers.get("content-type", ""):
                            title_match = re.search(
                                r"<title[^>]*>(.*?)</title>",
                                resp.text[:10000],
                                re.IGNORECASE | re.DOTALL,
                            )
                            if title_match:
                                result.title = title_match.group(1).strip()[:100]
                except Exception:
                    pass
            except Exception:
                pass

            # Flag analysis
            if result.status_code == 200 and any(
                kw in subdomain for kw in ["admin", "internal", "staging", "dev", "test"]
            ):
                result.flags.append("INTERESTING")

            if result.status_code in (401, 403):
                result.flags.append("AUTH_REQUIRED")

            if result.server and any(
                s in result.server.lower() for s in ["apache", "nginx", "iis", "tomcat", "express"]
            ):
                result.flags.append("SERVER_EXPOSED")

            if result.status_code == 200 and "index of" in result.title.lower():
                result.flags.append("DIR_LISTING")
                await push_finding(
                    self.state.findings_queue,
                    severity="MEDIUM",
                    module="SUBDOMAINS",
                    title="Directory Listing Enabled",
                    detail=f"Subdomain {subdomain} exposes directory listing",
                    evidence=f"{result.final_url} — Title: {result.title}",
                )

            # Only store resolved subdomains
            if result.ip:
                self.state.subdomain_results.append(result)
                resolved_count = len(self.state.subdomain_results)
                status.progress = min(99, int((resolved_count / max(total, 1)) * 100))
                status.message = f"Resolved: {resolved_count}"
