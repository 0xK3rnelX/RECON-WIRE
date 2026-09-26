"""HTTP header security audit module — headers + cookies + CORS + scoring.

Writes structured results to state.header_results.
Pushes findings for each violation.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

import httpx

from modules.findings import push_finding

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.headers")

# ── Required security headers and their check config ──
REQUIRED_HEADERS: list[dict[str, Any]] = [
    {
        "name": "Strict-Transport-Security",
        "severity": "HIGH",
        "detail": "HSTS not set — vulnerable to SSL stripping attacks",
    },
    {
        "name": "Content-Security-Policy",
        "severity": "HIGH",
        "detail": "CSP not set — vulnerable to XSS and data injection attacks",
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "detail": "X-Content-Type-Options not set — browser may MIME-sniff responses",
    },
    {"name": "X-Frame-Options", "severity": "MEDIUM", "detail": "X-Frame-Options not set — vulnerable to clickjacking"},
    {"name": "Referrer-Policy", "severity": "LOW", "detail": "Referrer-Policy not set — may leak sensitive URL paths"},
    {
        "name": "Permissions-Policy",
        "severity": "LOW",
        "detail": "Permissions-Policy not set — browser features not restricted",
    },
    {
        "name": "X-XSS-Protection",
        "severity": "INFO",
        "detail": "X-XSS-Protection not set (legacy but still good practice)",
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "severity": "LOW",
        "detail": "COOP not set — cross-origin isolation incomplete",
    },
    {
        "name": "Cross-Origin-Resource-Policy",
        "severity": "LOW",
        "detail": "CORP not set — cross-origin resource loading unrestricted",
    },
]

# ── Headers that leak server info ──
INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
    "X-Backend-Server",
    "X-Runtime",
    "X-Version",
    "X-Request-Id",
]

# ── HSTS max-age minimum (1 year = 31536000) ──
HSTS_MIN_AGE = 31536000

# ── Scoring weights ──
HEADER_WEIGHTS: dict[str, int] = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy": 20,
    "X-Content-Type-Options": 10,
    "X-Frame-Options": 10,
    "Referrer-Policy": 8,
    "Permissions-Policy": 8,
    "Cross-Origin-Opener-Policy": 5,
    "Cross-Origin-Resource-Policy": 5,
    "X-XSS-Protection": 4,
    "info_disclosure_penalty": -5,  # per info header found
    "cookie_penalty": -5,  # per insecure cookie
    "cors_penalty": -10,  # for wildcard CORS
}


class HeaderModule:
    """Full HTTP header security audit."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.url = state.config.url
        self.timeout = state.config.timeout

    async def run(self) -> None:
        status = self.state.module_statuses["HEADERS"]
        status.state = "RUNNING"
        status.message = "Fetching headers"
        logger.info("Header module starting for %s", self.url)

        try:
            raw_headers, redirect_chain, final_status = await self._fetch_headers()
            status.progress = 30
            status.message = "Auditing security headers"

            security_audit = await self._audit_required_headers(raw_headers)
            status.progress = 50

            misconfig_audit = self._audit_misconfigurations(raw_headers)
            status.progress = 60

            info_audit = self._audit_info_disclosure(raw_headers)
            status.progress = 70
            status.message = "Auditing cookies"

            cookie_audit = self._audit_cookies(raw_headers)
            status.progress = 80
            status.message = "Auditing CORS"

            cors_audit = await self._audit_cors()
            status.progress = 90
            status.message = "Computing score"

            score, grade = self._compute_score(raw_headers, security_audit, info_audit, cookie_audit, cors_audit)

            self.state.header_results = {
                "raw_headers": dict(raw_headers),
                "security_audit": security_audit,
                "misconfig_audit": misconfig_audit,
                "info_disclosure": info_audit,
                "cookie_audit": cookie_audit,
                "cors_audit": cors_audit,
                "score": score,
                "grade": grade,
                "redirect_chain": redirect_chain,
                "final_status": final_status,
            }

            status.state = "DONE"
            status.progress = 100
            status.message = f"Score: {score}/100 (Grade {grade})"
            logger.info("Header module completed — Score: %d/100 Grade: %s", score, grade)

        except Exception as exc:
            status.state = "ERROR"
            status.message = f"Header error: {exc}"
            logger.error("Header module failed: %s", exc, exc_info=True)
            await push_finding(
                self.state.findings_queue,
                severity="MEDIUM",
                module="HEADERS",
                title="Header Module Error",
                detail=str(exc),
                evidence=f"URL: {self.url}",
            )

    async def _fetch_headers(self) -> tuple[httpx.Headers, list[str], int]:
        """Fetch response headers. Try HEAD first, fall back to GET."""
        redirect_chain: list[str] = []
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
            try:
                try:
                    resp = await client.head(self.url)
                except Exception:
                    resp = await client.get(self.url)
            except Exception:
                if self.url.startswith("https://"):
                    fallback = self.url.replace("https://", "http://", 1)
                    try:
                        resp = await client.head(fallback)
                    except Exception:
                        resp = await client.get(fallback)
                else:
                    raise

            # Capture redirect chain
            if hasattr(resp, "history") and resp.history:
                for r in resp.history:
                    redirect_chain.append(str(r.url))
            redirect_chain.append(str(resp.url))

            return resp.headers, redirect_chain, resp.status_code

    async def _audit_required_headers(self, headers: httpx.Headers) -> list[dict[str, Any]]:
        """Check for required security headers and push findings."""
        results: list[dict[str, Any]] = []
        for spec in REQUIRED_HEADERS:
            name = spec["name"]
            present = name.lower() in {k.lower() for k in headers}
            value = headers.get(name, "")
            entry: dict[str, Any] = {
                "header": name,
                "present": present,
                "value": value,
                "issues": [],
            }

            if not present:
                entry["issues"].append(spec["detail"])
                await push_finding(
                    self.state.findings_queue,
                    severity=spec["severity"],
                    module="HEADERS",
                    title=f"Missing {name}",
                    detail=spec["detail"],
                    evidence=f"URL: {self.url}",
                )
            else:
                # Deep validation for specific headers
                issues = self._validate_header_value(name, value)
                entry["issues"] = issues
                for issue in issues:
                    await push_finding(
                        self.state.findings_queue,
                        severity="MEDIUM",
                        module="HEADERS",
                        title=f"Misconfigured {name}",
                        detail=issue,
                        evidence=f"{name}: {value}",
                    )
            results.append(entry)
        return results

    def _validate_header_value(self, name: str, value: str) -> list[str]:
        """Deep-validate specific header values."""
        issues: list[str] = []
        name_lower = name.lower()

        if name_lower == "strict-transport-security":
            age_match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
            if age_match:
                max_age = int(age_match.group(1))
                if max_age < HSTS_MIN_AGE:
                    issues.append(f"HSTS max-age too low ({max_age}s, recommend >= {HSTS_MIN_AGE}s)")
            else:
                issues.append("HSTS missing max-age directive")
            if "includesubdomains" not in value.lower():
                issues.append("HSTS missing includeSubDomains directive")

        elif name_lower == "content-security-policy":
            if "unsafe-inline" in value.lower():
                issues.append("CSP contains 'unsafe-inline' — weakens XSS protection")
            if "unsafe-eval" in value.lower():
                issues.append("CSP contains 'unsafe-eval' — allows dynamic code execution")
            if "*" in value and "default-src" in value.lower():
                issues.append("CSP default-src includes wildcard '*'")

        elif name_lower == "x-frame-options":
            val_upper = value.upper().strip()
            if val_upper not in ("DENY", "SAMEORIGIN"):
                issues.append(f"X-Frame-Options value '{value}' is not DENY or SAMEORIGIN")

        elif name_lower == "x-content-type-options":
            if value.strip().lower() != "nosniff":
                issues.append(f"X-Content-Type-Options should be 'nosniff', got '{value}'")

        elif name_lower == "referrer-policy":
            valid_policies = {
                "no-referrer",
                "no-referrer-when-downgrade",
                "origin",
                "origin-when-cross-origin",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "unsafe-url",
            }
            if value.strip().lower() not in valid_policies:
                issues.append(f"Referrer-Policy value '{value}' is non-standard")

        return issues

    def _audit_misconfigurations(self, headers: httpx.Headers) -> list[dict[str, str]]:
        """Check for header misconfigurations."""
        issues: list[dict[str, str]] = []

        # Cache-control on HTTPS
        cc = headers.get("cache-control", "").lower()
        if self.state.config.scheme == "https" and "public" in cc and "no-store" not in cc:
            issues.append(
                {
                    "header": "Cache-Control",
                    "issue": "HTTPS response cached publicly — sensitive data may be stored in proxies",
                    "value": headers.get("cache-control", ""),
                }
            )

        # X-Frame-Options with CSP frame-ancestors conflict
        if headers.get("x-frame-options") and headers.get("content-security-policy"):
            csp = headers.get("content-security-policy", "")
            if "frame-ancestors" in csp.lower():
                issues.append(
                    {
                        "header": "X-Frame-Options + CSP",
                        "issue": "Both X-Frame-Options and CSP frame-ancestors present — CSP takes precedence",
                        "value": "Redundant clickjacking protection",
                    }
                )

        return issues

    def _audit_info_disclosure(self, headers: httpx.Headers) -> list[dict[str, str]]:
        """Check for information disclosure headers."""
        found: list[dict[str, str]] = []
        for header_name in INFO_DISCLOSURE_HEADERS:
            value = headers.get(header_name)
            if value:
                found.append({"header": header_name, "value": value})
        return found

    def _audit_cookies(self, headers: httpx.Headers) -> list[dict[str, Any]]:
        """Audit Set-Cookie headers for security flags."""
        results: list[dict[str, Any]] = []
        for cookie_header in headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            name_match = re.match(r"^([^=]+)=", cookie_header)
            cookie_name = name_match.group(1) if name_match else "unknown"

            audit: dict[str, Any] = {
                "name": cookie_name,
                "raw": cookie_header[:200],
                "secure": "secure" in cookie_lower,
                "httponly": "httponly" in cookie_lower,
                "samesite": "samesite" in cookie_lower,
                "issues": [],
            }

            if not audit["secure"]:
                audit["issues"].append("Missing Secure flag")
            if not audit["httponly"] and cookie_name.lower() not in ("csrf", "__csrf", "_csrf"):
                audit["issues"].append("Missing HttpOnly flag")
            if not audit["samesite"]:
                audit["issues"].append("Missing SameSite attribute")
            if "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                audit["issues"].append("SameSite=None without Secure flag")

            results.append(audit)
        return results

    async def _audit_cors(self) -> list[dict[str, str]]:
        """CORS audit — send cross-origin preflight-like requests."""
        results: list[dict[str, str]] = []
        test_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
            for origin in test_origins:
                try:
                    resp = await client.get(
                        self.url,
                        headers={"Origin": origin},
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")

                    if acao:
                        entry: dict[str, str] = {
                            "test_origin": origin,
                            "acao": acao,
                            "acac": acac,
                            "issue": "",
                        }
                        if acao == "*":
                            entry["issue"] = "Wildcard CORS — any origin allowed"
                            await push_finding(
                                self.state.findings_queue,
                                severity="MEDIUM",
                                module="HEADERS",
                                title="Wildcard CORS Policy",
                                detail="Access-Control-Allow-Origin: * allows any origin",
                                evidence=f"Origin: {origin} → ACAO: {acao}",
                            )
                        elif acao == origin:
                            entry["issue"] = f"Origin {origin} reflected in ACAO"
                            severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                            await push_finding(
                                self.state.findings_queue,
                                severity=severity,
                                module="HEADERS",
                                title="CORS Origin Reflection",
                                detail="Server reflects attacker origin in ACAO"
                                + (", with credentials" if acac.lower() == "true" else ""),
                                evidence=f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                            )
                        if acao == "null":
                            entry["issue"] = "CORS allows null origin"
                            await push_finding(
                                self.state.findings_queue,
                                severity="MEDIUM",
                                module="HEADERS",
                                title="CORS Allows Null Origin",
                                detail="Access-Control-Allow-Origin: null — exploitable via sandboxed iframes",
                                evidence=f"Origin: null → ACAO: {acao}",
                            )
                        results.append(entry)
                except Exception as exc:
                    logger.debug("CORS test failed for origin %s: %s", origin, exc)
        return results

    def _compute_score(
        self,
        headers: httpx.Headers,
        security_audit: list[dict],
        info_audit: list[dict],
        cookie_audit: list[dict],
        cors_audit: list[dict],
    ) -> tuple[int, str]:
        """Compute header security score (0–100) and letter grade."""
        score = 0

        # Points for present security headers
        for audit_entry in security_audit:
            if audit_entry["present"] and not audit_entry["issues"]:
                weight = HEADER_WEIGHTS.get(audit_entry["header"], 0)
                score += weight
            elif audit_entry["present"] and audit_entry["issues"]:
                weight = HEADER_WEIGHTS.get(audit_entry["header"], 0)
                score += weight // 2  # Half credit for misconfigured

        # Penalties
        for _ in info_audit:
            score += HEADER_WEIGHTS["info_disclosure_penalty"]
        for cookie in cookie_audit:
            if cookie.get("issues"):
                score += HEADER_WEIGHTS["cookie_penalty"]
        for cors in cors_audit:
            if cors.get("issue"):
                score += HEADER_WEIGHTS["cors_penalty"]

        score = max(0, min(100, score))

        # Grade
        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return score, grade
