"""Web crawl and endpoint discovery module (P1-2).

Extracts inline links, script sources, API endpoints (/api/, /swagger, GraphQL), and form actions.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from modules.findings import push_finding
from modules.stealth import apply_stealth_delay, build_client

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.endpoints")


@dataclass
class EndpointResult:
    url: str
    path: str
    category: str  # API | SCRIPT | FORM | LINK
    method: str = "GET"

    def to_dict(self) -> dict:
        return asdict(self)


class EndpointModule:
    """Async web crawler and endpoint extractor."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def run(self) -> list[EndpointResult]:
        status = self.state.module_statuses.get("ENDPOINTS")
        if status:
            status.state = "RUNNING"
            status.message = "Crawling web assets & discovering endpoints..."

        cfg = self.state.config
        discovered: dict[str, EndpointResult] = {}
        base_url = cfg.url

        try:
            await apply_stealth_delay(cfg)
            async with build_client(cfg) as client:
                resp = await client.get(base_url)
                html = resp.text

                # Parse HTML
                soup = BeautifulSoup(html, "html.parser")
                target_host = cfg.hostname.lower()

                # 1. Scripts
                for tag in soup.find_all("script", src=True):
                    src = tag["src"]
                    full = urljoin(base_url, src)
                    path = urlparse(full).path
                    if full not in discovered:
                        discovered[full] = EndpointResult(url=full, path=path, category="SCRIPT")

                # 2. Links
                for tag in soup.find_all(["a", "link"], href=True):
                    href = tag["href"]
                    full = urljoin(base_url, href)
                    parsed = urlparse(full)
                    if parsed.netloc.lower() in (target_host, f"www.{target_host}"):
                        path = parsed.path or "/"
                        cat = (
                            "API"
                            if any(k in path.lower() for k in ("/api/", "/v1/", "/v2/", "/graphql", "/swagger"))
                            else "LINK"
                        )
                        if full not in discovered:
                            discovered[full] = EndpointResult(url=full, path=path, category=cat)

                # 3. Form action endpoints
                for form in soup.find_all("form", action=True):
                    act = form["action"]
                    meth = form.get("method", "GET").upper()
                    full = urljoin(base_url, act)
                    path = urlparse(full).path
                    discovered[full] = EndpointResult(url=full, path=path, category="FORM", method=meth)

                # 4. Regex API & route extractors in HTML/inline JS
                api_patterns = [
                    r'["\'](/api/v\d+/[a-zA-Z0-9_\-/]+)["\']',
                    r'["\'](/v[123]/[a-zA-Z0-9_\-/]+)["\']',
                    r'["\'](/[a-zA-Z0-9_\-]+/graphql)["\']',
                    r'["\'](/swagger[a-zA-Z0-9_\-/]*)["\']',
                ]
                for pat in api_patterns:
                    for match in re.findall(pat, html):
                        full = urljoin(base_url, match)
                        if full not in discovered:
                            discovered[full] = EndpointResult(url=full, path=match, category="API")

                # Check for sensitive endpoints
                sensitive_hits = [
                    (e, e.path)
                    for e in discovered.values()
                    if any(term in e.path.lower() for term in ("graphql", "swagger", "api-docs", "admin", "debug"))
                ]

                for ep, path in sensitive_hits:
                    sev = "MEDIUM" if "admin" in path.lower() or "debug" in path.lower() else "INFO"
                    await push_finding(
                        self.state.findings_queue,
                        module="ENDPOINTS",
                        severity=sev,
                        title=f"Interesting Endpoint Discovered: {path}",
                        detail=f"Discovered {ep.category} endpoint during web crawl: {ep.url}",
                        evidence=f"Endpoint: {ep.url} (Method: {ep.method})",
                    )

        except Exception as exc:
            logger.error("Endpoint crawler raised error: %s", exc)

        results = list(discovered.values())
        self.state.endpoint_results = results

        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(results)} endpoints extracted"

        return results
