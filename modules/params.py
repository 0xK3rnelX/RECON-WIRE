"""Parameter Discovery & Reflection Mining Module (PD-1).

Performs automated probing for hidden query parameters, reflection vectors,
and dynamic response anomalies across target entry points and crawled endpoints.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from modules.findings import push_finding
from modules.stealth import apply_stealth_delay, build_client

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.params")

# Comprehensive parameter mining wordlist (150+ high-impact parameters)
PARAM_WORDLIST: list[str] = [
    # Debugging & State Manipulation
    "debug",
    "test",
    "testing",
    "dev",
    "developer",
    "trace",
    "verbose",
    "diag",
    "diagnostic",
    "log",
    "logs",
    "env",
    "environment",
    "config",
    "configuration",
    "dump",
    "status",
    "version",
    # Redirection, SSRF & Forwarding
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "uri",
    "dest",
    "destination",
    "next",
    "return",
    "return_to",
    "target",
    "forward",
    "forward_to",
    "goto",
    "link",
    "domain",
    "host",
    "callback",
    "cb",
    "webhook",
    "feed",
    "fetch",
    "proxy",
    "relay",
    "ping",
    "out",
    # File Inclusion, Reading & Path Traversal
    "file",
    "filename",
    "filepath",
    "path",
    "folder",
    "directory",
    "dir",
    "root",
    "doc",
    "document",
    "page",
    "pg",
    "template",
    "tpl",
    "layout",
    "view",
    "source",
    "src",
    "load",
    "include",
    "read",
    "download",
    "attach",
    "attachment",
    "pdf",
    "image",
    # Command Execution & System Administration
    "cmd",
    "command",
    "exec",
    "execute",
    "run",
    "cli",
    "eval",
    "shell",
    "process",
    "task",
    "job",
    "daemon",
    "service",
    "action",
    "do",
    "step",
    "method",
    "func",
    "function",
    "handler",
    # Authentication, Session & Secrets
    "token",
    "auth",
    "authentication",
    "api_key",
    "apikey",
    "key",
    "secret",
    "access_token",
    "refresh_token",
    "jwt",
    "session",
    "session_id",
    "sid",
    "ticket",
    "pass",
    "password",
    "code",
    "hash",
    "pin",
    "otp",
    "creds",
    "credentials",
    "bearer",
    "signature",
    "sig",
    # Identity, Access & Role Privilege
    "admin",
    "administrator",
    "root",
    "user",
    "username",
    "user_id",
    "uid",
    "id",
    "account",
    "acc",
    "role",
    "group",
    "permission",
    "scope",
    "email",
    "mail",
    "member",
    "team",
    "org",
    "organization",
    "tenant",
    "profile",
    "whoami",
    "impersonate",
    # Data Querying, Filtering & Injection (SQLi / NoSQL / Search)
    "query",
    "q",
    "search",
    "s",
    "find",
    "filter",
    "sort",
    "order",
    "by",
    "limit",
    "offset",
    "page_size",
    "col",
    "column",
    "table",
    "tbl",
    "field",
    "select",
    "where",
    "group_by",
    "format",
    "output",
    "type",
    "mode",
    "data",
    "payload",
    "json",
    "xml",
    "csv",
    "schema",
    # Administrative Actions & Data Exfiltration
    "export",
    "import",
    "backup",
    "restore",
    "upload",
    "download",
    "delete",
    "remove",
    "drop",
    "clear",
    "reset",
    "update",
    "modify",
    "save",
    "sync",
    "enable",
    "disable",
]


@dataclass
class ParamResult:
    """Represents a discovered or anomalous parameter."""

    endpoint: str
    param: str
    method: str
    anomaly_type: str  # REFLECTION | STATUS_SHIFT | BODY_DIFF | HEADER_SET
    status_code: int
    content_length: int
    evidence: str
    confidence: str  # HIGH | MEDIUM

    def to_dict(self) -> dict:
        return asdict(self)


class ParamModule:
    """Discovers hidden HTTP parameters and reflective vectors."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def run(self) -> list[ParamResult]:
        """Execute parameter mining against target entry points."""
        cfg = self.state.config
        status = self.state.module_statuses.get("PARAMS")
        if status:
            status.state = "RUNNING"
            status.message = "Initializing parameter discovery"
            status.progress = 10

        results: list[ParamResult] = []

        # Collect candidate endpoints: base URL plus discovered distinct paths
        candidate_urls: list[str] = [cfg.url]
        seen_paths = {urlparse(cfg.url).path}

        for ep in getattr(self.state, "endpoint_results", []):
            path = getattr(ep, "path", "")
            if (
                path
                and path.startswith("/")
                and path not in seen_paths
                and not any(
                    path.lower().endswith(ext)
                    for ext in (".png", ".jpg", ".jpeg", ".gif", ".css", ".svg", ".woff", ".ico")
                )
            ):
                full_url = urljoin(cfg.url, path)
                candidate_urls.append(full_url)
                seen_paths.add(path)
            if len(candidate_urls) >= 5:
                break

        total_probes = len(candidate_urls) * len(PARAM_WORDLIST)
        completed_probes = 0
        sem = asyncio.Semaphore(min(cfg.max_concurrent, 10))

        try:
            async with build_client(self.state, timeout=cfg.timeout, follow_redirects=True) as client:
                for _url_idx, target_url in enumerate(candidate_urls, 1):
                    # 1. Establish baseline response for this endpoint
                    baseline_resp = None
                    try:
                        baseline_resp = await client.get(target_url)
                    except Exception:
                        if target_url.startswith("https://"):
                            fallback_url = target_url.replace("https://", "http://", 1)
                            try:
                                baseline_resp = await client.get(fallback_url)
                                target_url = fallback_url
                            except Exception as exc:
                                logger.debug("Failed fallback baseline for %s: %s", fallback_url, exc)
                                continue
                        else:
                            continue

                    base_status = baseline_resp.status_code
                    base_len = len(baseline_resp.content)
                    base_headers = dict(baseline_resp.headers)

                    # 2. Concurrently test candidate parameters
                    async def probe_param(
                        param_name: str,
                        url: str = target_url,
                        b_status: int = base_status,
                        b_len: int = base_len,
                        b_headers: dict = base_headers,
                    ) -> None:
                        nonlocal completed_probes
                        canary = f"rwcanary_{param_name}"
                        probe_params = {param_name: canary}

                        async with sem:
                            await apply_stealth_delay(self.state)
                            try:
                                resp = await client.get(url, params=probe_params)
                                cur_len = len(resp.content)
                                cur_status = resp.status_code
                                text = resp.text

                                # Check Reflection
                                if canary in text:
                                    results.append(
                                        ParamResult(
                                            endpoint=url,
                                            param=param_name,
                                            method="GET",
                                            anomaly_type="REFLECTION",
                                            status_code=cur_status,
                                            content_length=cur_len,
                                            evidence=f"Value '{canary}' reflected in response body",
                                            confidence="HIGH",
                                        )
                                    )
                                # Check Status Code Shift
                                elif cur_status != b_status:
                                    results.append(
                                        ParamResult(
                                            endpoint=url,
                                            param=param_name,
                                            method="GET",
                                            anomaly_type="STATUS_SHIFT",
                                            status_code=cur_status,
                                            content_length=cur_len,
                                            evidence=f"Status shifted from {b_status} to {cur_status}",
                                            confidence="MEDIUM",
                                        )
                                    )
                                # Check Significant Length Shift (accounting for param name + canary len)
                                elif abs(cur_len - b_len) > (len(param_name) + len(canary) + 64):
                                    results.append(
                                        ParamResult(
                                            endpoint=url,
                                            param=param_name,
                                            method="GET",
                                            anomaly_type="BODY_DIFF",
                                            status_code=cur_status,
                                            content_length=cur_len,
                                            evidence=f"Length difference: {cur_len - b_len:+d} bytes compared to baseline",
                                            confidence="MEDIUM",
                                        )
                                    )
                                # Check New Security/Debugging Headers
                                else:
                                    for h, v in resp.headers.items():
                                        if h.lower() not in b_headers and any(
                                            term in h.lower() for term in ("debug", "location", "set-cookie", "x-")
                                        ):
                                            results.append(
                                                ParamResult(
                                                    endpoint=url,
                                                    param=param_name,
                                                    method="GET",
                                                    anomaly_type="HEADER_SET",
                                                    status_code=cur_status,
                                                    content_length=cur_len,
                                                    evidence=f"Induced new header {h}: {v[:40]}",
                                                    confidence="MEDIUM",
                                                )
                                            )
                                            break
                            except Exception:
                                pass
                            finally:
                                completed_probes += 1
                                if status and total_probes > 0:
                                    status.progress = min(95, 10 + int((completed_probes / total_probes) * 85))

                    # Gather probe tasks for this URL
                    tasks = [probe_param(p, target_url, base_status, base_len, base_headers) for p in PARAM_WORDLIST]
                    await asyncio.gather(*tasks)

        except Exception as exc:
            logger.error("Parameter mining failed: %s", exc, exc_info=True)

        # De-duplicate results
        seen_keys = set()
        deduped: list[ParamResult] = []
        for r in results:
            key = (r.endpoint, r.param, r.anomaly_type)
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(r)

        self.state.param_results = deduped

        # Generate Security Findings
        for res in deduped:
            if res.anomaly_type == "REFLECTION":
                await push_finding(
                    self.state.findings_queue,
                    module="PARAMS",
                    severity="MEDIUM",
                    title=f"Reflected Query Parameter: '{res.param}'",
                    detail=f"Input parameter '{res.param}' reflected in response body at {res.endpoint}. Potential XSS or injection vector.",
                    evidence=res.evidence,
                )
            elif res.anomaly_type == "STATUS_SHIFT":
                await push_finding(
                    self.state.findings_queue,
                    module="PARAMS",
                    severity="LOW",
                    title=f"Parameter Status Change: '{res.param}'",
                    detail=f"Parameter '{res.param}' altered HTTP status code to {res.status_code} at {res.endpoint}.",
                    evidence=res.evidence,
                )
            elif res.confidence == "HIGH":
                await push_finding(
                    self.state.findings_queue,
                    module="PARAMS",
                    severity="LOW",
                    title=f"Discovered Parameter: '{res.param}'",
                    detail=f"Parameter '{res.param}' induced distinct application behavior at {res.endpoint}.",
                    evidence=res.evidence,
                )

        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(deduped)} active parameters found"

        return deduped
