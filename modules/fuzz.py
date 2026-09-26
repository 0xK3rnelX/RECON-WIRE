"""Sensitive file and directory fuzzing module (P1-3).

Checks high-risk paths (/.env, /.git/HEAD, /robots.txt, backup files, admin portals).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, asdict
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from modules.findings import push_finding
from modules.stealth import build_client, apply_stealth_delay

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.fuzz")

# High-signal sensitive files, backup archives, configurations, and administrative portals
FUZZ_TARGETS: list[tuple[str, str, str]] = [
    # Version Control Exposures
    ("/.git/HEAD", "CRITICAL", "Exposed Git repository metadata"),
    ("/.git/config", "CRITICAL", "Exposed Git configuration (remote URLs & tokens)"),
    ("/.git/index", "CRITICAL", "Exposed Git staging index"),
    ("/.gitignore", "LOW", "Git ignore definitions (discloses hidden paths)"),
    ("/.svn/entries", "CRITICAL", "Exposed Subversion (SVN) repository entries"),
    ("/.hg/hgrc", "CRITICAL", "Exposed Mercurial configuration"),

    # Environment & Cloud Credentials
    ("/.env", "CRITICAL", "Environment secrets file (.env)"),
    ("/.env.local", "CRITICAL", "Local environment overrides"),
    ("/.env.production", "CRITICAL", "Production environment secrets"),
    ("/.env.backup", "CRITICAL", "Backup environment configuration"),
    ("/.env.save", "CRITICAL", "Saved environment configuration"),
    ("/.aws/credentials", "CRITICAL", "AWS CLI credential file"),
    ("/.docker/config.json", "CRITICAL", "Docker registry authentication file"),
    ("/.ssh/id_rsa", "CRITICAL", "Leaked OpenSSH private key"),
    ("/id_rsa", "CRITICAL", "Leaked private key file"),

    # Database Dumps & SQL Archives
    ("/backup.sql", "CRITICAL", "Direct SQL database dump file"),
    ("/database.sql", "CRITICAL", "Full database export file"),
    ("/db.sql", "CRITICAL", "Database dump backup"),
    ("/dump.sql", "CRITICAL", "Database dump export"),
    ("/users.sql", "CRITICAL", "User database dump"),
    ("/data.sql", "CRITICAL", "Application SQL data backup"),

    # Compressed Backup Archives
    ("/backup.zip", "HIGH", "Publicly accessible full archive backup"),
    ("/backup.tar.gz", "HIGH", "Gzip compressed backup archive"),
    ("/backup.tgz", "HIGH", "Compressed backup tarball"),
    ("/site_backup.zip", "HIGH", "Full website backup archive"),
    ("/www.zip", "HIGH", "Web root archive export"),
    ("/archive.zip", "HIGH", "Compressed archive file"),
    ("/backup.7z", "HIGH", "7-Zip compressed archive"),

    # Application Configurations & Backups
    ("/wp-config.php.bak", "CRITICAL", "WordPress configuration backup file"),
    ("/wp-config.php~", "CRITICAL", "WordPress temporary configuration editor backup"),
    ("/config.php.bak", "HIGH", "PHP configuration backup file"),
    ("/configuration.php.bak", "HIGH", "Joomla/General configuration backup"),
    ("/config.json", "MEDIUM", "Application JSON configuration file"),
    ("/config.yml", "MEDIUM", "Application YAML configuration file"),
    ("/appsettings.json", "HIGH", "ASP.NET Core settings & connection strings"),
    ("/web.config", "MEDIUM", "IIS ASP.NET application web configuration"),

    # Framework Actuators & Metrics
    ("/actuator/env", "CRITICAL", "Spring Boot Actuator environment (plaintext secrets)"),
    ("/actuator/health", "INFO", "Spring Boot Actuator health status"),
    ("/actuator/beans", "HIGH", "Spring Boot configured application beans"),
    ("/actuator/heapdump", "CRITICAL", "JVM memory heap dump (contains in-memory secrets)"),
    ("/actuator/mappings", "MEDIUM", "Spring Boot endpoint route mappings"),
    ("/metrics", "INFO", "Prometheus application runtime metrics"),
    ("/prometheus", "INFO", "Prometheus telemetry exporter"),

    # API Documentation & Schema Exposures
    ("/swagger-ui.html", "LOW", "Swagger UI interactive API documentation"),
    ("/swagger/v1/swagger.json", "MEDIUM", "Swagger REST API schema specification"),
    ("/openapi.json", "MEDIUM", "OpenAPI JSON endpoint definitions"),
    ("/api-docs", "LOW", "Interactive API documentation"),
    ("/graphql", "LOW", "GraphQL query interface endpoint"),

    # Server Status & Diagnostic Info
    ("/phpinfo.php", "MEDIUM", "PHP configuration info disclosure"),
    ("/info.php", "MEDIUM", "PHP system info disclosure"),
    ("/server-status", "MEDIUM", "Apache/Nginx server status monitor"),
    ("/server-info", "MEDIUM", "Apache web server detailed configuration"),
    ("/robots.txt", "INFO", "Robots exclusion directive file"),
    ("/sitemap.xml", "INFO", "Sitemap index file"),
    ("/.well-known/security.txt", "INFO", "Security vulnerability contact policy file"),

    # Administrative Interfaces & Database Managers
    ("/admin/", "LOW", "Administrative interface portal"),
    ("/administrator/", "LOW", "Administrator login page"),
    ("/admin.php", "LOW", "PHP admin authentication entrance"),
    ("/login", "INFO", "Standard login entrance"),
    ("/dashboard/", "INFO", "Administrative dashboard portal"),
    ("/phpmyadmin/", "MEDIUM", "phpMyAdmin database management portal"),
    ("/pma/", "MEDIUM", "phpMyAdmin shorthand portal"),
    ("/adminer.php", "MEDIUM", "Adminer single-file database manager"),
    ("/solr/", "MEDIUM", "Apache Solr admin console"),
    ("/kibana/", "MEDIUM", "Elasticsearch Kibana dashboard interface"),
]


@dataclass
class FuzzResult:
    path: str
    url: str
    status_code: int
    content_length: int
    content_type: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class FuzzModule:
    """High-speed async directory and sensitive file fuzzer."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def _check_path(self, client, base_url: str, path: str, sev: str, desc: str, semaphore: asyncio.Semaphore) -> FuzzResult | None:
        async with semaphore:
            await apply_stealth_delay(self.state.config)
            full_url = urljoin(base_url, path)
            try:
                resp = await client.get(path)
                status = resp.status_code
                cl = int(resp.headers.get("Content-Length", len(resp.content)))
                ct = resp.headers.get("Content-Type", "")

                # Check if it is a real response (200 OK or 403 Forbidden on sensitive paths)
                if status == 200:
                    # Filter out soft-404 custom error pages
                    body_lower = resp.text[:1000].lower()
                    if "not found" in body_lower or "404" in body_lower:
                        return None

                    # If .git/HEAD, verify it has git ref
                    if path == "/.git/HEAD" and "ref:" not in resp.text:
                        return None

                    await push_finding(
                        self.state.findings_queue,
                        module="FUZZ",
                        severity=sev,
                        title=f"Sensitive File Disclosed: {path}",
                        detail=f"{desc} returned HTTP 200 OK. Size: {cl} bytes, Type: {ct}",
                        evidence=f"URL: {full_url} (HTTP {status})",
                    )
                    return FuzzResult(path=path, url=full_url, status_code=status, content_length=cl, content_type=ct)

                elif status in (401, 403) and ("admin" in path or ".env" in path or ".git" in path):
                    await push_finding(
                        self.state.findings_queue,
                        module="FUZZ",
                        severity="LOW",
                        title=f"Restricted Resource Found: {path}",
                        detail=f"{desc} responded with HTTP {status} (Resource exists but access is forbidden).",
                        evidence=f"URL: {full_url} (HTTP {status})",
                    )
                    return FuzzResult(path=path, url=full_url, status_code=status, content_length=cl, content_type=ct)

            except Exception:
                return None
            return None

    async def run(self) -> list[FuzzResult]:
        status = self.state.module_statuses.get("FUZZ")
        if status:
            status.state = "RUNNING"
            status.message = "Fuzzing sensitive files & directories..."

        cfg = self.state.config
        semaphore = asyncio.Semaphore(cfg.max_concurrent)
        hits: list[FuzzResult] = []

        try:
            async with build_client(cfg) as client:
                # Set client base_url
                client.base_url = cfg.url
                tasks = [
                    self._check_path(client, cfg.url, p, sev, desc, semaphore)
                    for p, sev, desc in FUZZ_TARGETS
                ]
                raw = await asyncio.gather(*tasks, return_exceptions=True)
                hits = [r for r in raw if isinstance(r, FuzzResult)]
        except Exception as exc:
            logger.error("Fuzz module encountered error: %s", exc)

        self.state.fuzz_results = hits

        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(hits)} exposed files / paths identified"

        return hits
