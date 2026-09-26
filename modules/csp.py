"""Content Security Policy (CSP) Evaluator & Bypass Engine Module (PD-2).

Parses, grades, and inspects Content-Security-Policy directives for syntax,
wildcards, dangerous execution flags ('unsafe-inline', 'unsafe-eval', 'data:'),
missing barrier directives (base-uri, frame-ancestors, object-src), and
known JSONP/CDN script gadget bypass vectors.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING

from modules.findings import push_finding
from modules.stealth import build_client

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.csp")

# Known CDN/JSONP endpoints that host JSONP endpoints or Angular/Bypass gadgets
GADGET_CDNS: dict[str, str] = {
    "cdnjs.cloudflare.com": "Angular / Vue / JS gadget bypass libraries available",
    "ajax.googleapis.com": "Hosts AngularJS 1.x, Prototype, and Google JSONP endpoints",
    "googleapis.com": "Google JSONP APIs (YouTube, Books, Drive) bypass script restrictions",
    "maps.googleapis.com": "Google Maps JSONP callback endpoints",
    "cdn.jsdelivr.net": "User-controllable script libraries and NPM bypass gadgets",
    "unpkg.com": "NPM package proxy allowing arbitrary script execution",
    "raw.githubusercontent.com": "Direct user content script execution",
    "google-analytics.com": "JSONP callback endpoints (e.g. ga-audiences)",
    "googletagmanager.com": "Google Tag Manager container execution vectors",
    "code.jquery.com": "Legacy jQuery versions with known gadget vectors",
    "stackpath.bootstrapcdn.com": "Legacy Bootstrap/jQuery gadget libraries",
    "cdn.bootcdn.net": "Chinese mirror CDN hosting vulnerable legacy frameworks",
    "connect.facebook.net": "Facebook SDK JSONP callback and DOM gadgets",
    "api.twitter.com": "Twitter JSONP API callback endpoints",
    "api.github.com": "GitHub API JSONP callback endpoints",
    "yandex.ru": "Yandex JSONP callback endpoints",
    "vk.com": "VKontakte JSONP endpoints",
    "vimeo.com": "Vimeo player JSONP callback endpoints",
    "api.flickr.com": "Flickr JSONP callback endpoints",
    "assets.zendesk.com": "Zendesk widget JSONP endpoints",
    "static.cloudflareinsights.com": "Cloudflare Analytics gadget vectors",
}


@dataclass
class CSPFlaw:
    """A detected CSP misconfiguration or bypass opportunity."""

    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    directive: str
    issue: str
    impact: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CSPResult:
    """Structured evaluation of a site's Content Security Policy."""

    raw_csp: str
    report_only: bool
    score: int
    grade: str
    directives: dict[str, list[str]] = field(default_factory=dict)
    flaws: list[CSPFlaw] = field(default_factory=list)
    bypass_vectors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "raw_csp": self.raw_csp,
            "report_only": self.report_only,
            "score": self.score,
            "grade": self.grade,
            "directives": self.directives,
            "flaws": [f.to_dict() for f in self.flaws],
            "bypass_vectors": self.bypass_vectors,
        }


class CSPModule:
    """Evaluates Content-Security-Policy implementation and discovers bypass vectors."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    def _parse_policy(self, raw_header: str) -> dict[str, list[str]]:
        """Parse raw CSP header string into directive map."""
        directives: dict[str, list[str]] = {}
        for part in raw_header.split(";"):
            tokens = part.strip().split()
            if not tokens:
                continue
            name = tokens[0].lower()
            values = tokens[1:]
            directives[name] = values
        return directives

    def _evaluate_csp(self, raw_csp: str, report_only: bool) -> CSPResult:
        """Run deep security heuristic evaluation on CSP directives."""
        directives = self._parse_policy(raw_csp)
        flaws: list[CSPFlaw] = []
        bypass_vectors: list[str] = []
        score = 100

        if report_only:
            score -= 15
            flaws.append(
                CSPFlaw(
                    severity="MEDIUM",
                    directive="Content-Security-Policy-Report-Only",
                    issue="Policy is in Report-Only mode",
                    impact="Violations are logged but malicious payloads are NOT blocked by the browser",
                    recommendation="Enforce the policy using Content-Security-Policy header",
                )
            )

        # Check default-src / script-src existence
        has_default = "default-src" in directives
        has_script = "script-src" in directives or "script-src-elem" in directives

        if not has_default and not has_script:
            score -= 30
            flaws.append(
                CSPFlaw(
                    severity="HIGH",
                    directive="script-src",
                    issue="Missing both default-src and script-src directives",
                    impact="Scripts can be loaded from arbitrary origins, negating XSS protection",
                    recommendation="Define default-src 'none' or explicit script-src origins",
                )
            )

        # Inspect script-src specifically
        script_sources = directives.get(
            "script-src", directives.get("script-src-elem", directives.get("default-src", []))
        )
        " ".join(script_sources).lower()

        # 1. Wildcard script execution
        if "*" in script_sources:
            score -= 30
            flaws.append(
                CSPFlaw(
                    severity="HIGH",
                    directive="script-src",
                    issue="Wildcard (*) origin allowed in script-src",
                    impact="Attacker can load scripts from any public server on the internet",
                    recommendation="Remove wildcard and restrict to specific trusted domains or hashes/nonces",
                )
            )
            bypass_vectors.append("Wildcard origin allows arbitrary external script loading")

        # 2. Scheme-only sources (http:, https:, data:)
        if "data:" in script_sources:
            score -= 25
            flaws.append(
                CSPFlaw(
                    severity="HIGH",
                    directive="script-src",
                    issue="'data:' URI scheme allowed in script-src",
                    impact="Enables trivial XSS injection via data:text/javascript URLs",
                    recommendation="Remove 'data:' from script-src",
                )
            )
            bypass_vectors.append("data: URI scheme enables direct inline payload execution")

        if "http:" in script_sources:
            score -= 15
            flaws.append(
                CSPFlaw(
                    severity="MEDIUM",
                    directive="script-src",
                    issue="Plain 'http:' scheme allowed in script-src",
                    impact="Allows Man-In-The-Middle (MITM) code injection over unencrypted connections",
                    recommendation="Enforce HTTPS-only origins",
                )
            )

        # 3. 'unsafe-inline' without nonce or hash
        has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script_sources)
        if "'unsafe-inline'" in script_sources and not has_nonce_or_hash:
            score -= 25
            flaws.append(
                CSPFlaw(
                    severity="HIGH",
                    directive="script-src",
                    issue="'unsafe-inline' enabled without nonces or hashes",
                    impact="Inline <script> blocks and event handlers (onload, onerror) execute directly, disabling XSS defense",
                    recommendation="Migrate to cryptographic nonces ('nonce-...') or SHA-256 hashes",
                )
            )
            bypass_vectors.append("Direct inline JavaScript execution allowed via 'unsafe-inline'")

        # 4. 'unsafe-eval'
        if "'unsafe-eval'" in script_sources:
            score -= 15
            flaws.append(
                CSPFlaw(
                    severity="MEDIUM",
                    directive="script-src",
                    issue="'unsafe-eval' permitted in script-src",
                    impact="Allows string evaluation functions (eval, Function(), setTimeout(str)) which can be weaponized in DOM XSS",
                    recommendation="Refactor application logic to avoid dynamic string code evaluation",
                )
            )
            bypass_vectors.append("eval() and string execution gadgets allowed")

        # 5. Check Gadget CDNs / JSONP endpoints in script-src
        for domain, desc in GADGET_CDNS.items():
            if any(domain in src.lower() for src in script_sources):
                score -= 10
                flaws.append(
                    CSPFlaw(
                        severity="MEDIUM",
                        directive="script-src",
                        issue=f"Known gadget CDN allowed: {domain}",
                        impact=desc,
                        recommendation=f"Restrict path or host scripts locally instead of trusting {domain}",
                    )
                )
                bypass_vectors.append(f"Gadget / JSONP bypass via {domain} ({desc})")

        # 6. object-src restriction
        obj_sources = directives.get("object-src", directives.get("default-src", []))
        if "'none'" not in obj_sources:
            score -= 15
            flaws.append(
                CSPFlaw(
                    severity="MEDIUM",
                    directive="object-src",
                    issue="object-src is not set to 'none'",
                    impact="Allows malicious Flash, Silverlight, or Java applet execution",
                    recommendation="Explicitly add: object-src 'none'",
                )
            )

        # 7. base-uri restriction
        if "base-uri" not in directives:
            score -= 10
            flaws.append(
                CSPFlaw(
                    severity="LOW",
                    directive="base-uri",
                    issue="Missing base-uri directive",
                    impact="Vulnerable to HTML <base> tag injection, hijacking relative script references",
                    recommendation="Add: base-uri 'self' or 'none'",
                )
            )
            bypass_vectors.append("Base tag injection possible due to missing base-uri")

        # 8. frame-ancestors (clickjacking defense)
        if "frame-ancestors" not in directives:
            score -= 10
            flaws.append(
                CSPFlaw(
                    severity="LOW",
                    directive="frame-ancestors",
                    issue="Missing frame-ancestors directive",
                    impact="Clickjacking defense relies solely on legacy X-Frame-Options",
                    recommendation="Add: frame-ancestors 'self' or 'none'",
                )
            )

        # 9. form-action
        if "form-action" not in directives:
            score -= 5
            flaws.append(
                CSPFlaw(
                    severity="LOW",
                    directive="form-action",
                    issue="Missing form-action directive",
                    impact="Form submissions are not restricted and can be rewritten to external malicious targets",
                    recommendation="Add: form-action 'self'",
                )
            )

        # Calculate grade
        score = max(0, min(100, score))
        if score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 35:
            grade = "D"
        else:
            grade = "F"

        return CSPResult(
            raw_csp=raw_csp,
            report_only=report_only,
            score=score,
            grade=grade,
            directives=directives,
            flaws=flaws,
            bypass_vectors=bypass_vectors,
        )

    async def run(self) -> list[CSPResult]:
        """Fetch and evaluate CSP from the target URL and headers."""
        cfg = self.state.config
        status = self.state.module_statuses.get("CSP")
        if status:
            status.state = "RUNNING"
            status.message = "Analyzing Content Security Policy"
            status.progress = 20

        csp_results: list[CSPResult] = []

        try:
            # Check if headers module already captured CSP in state.header_results
            raw_headers = getattr(self.state, "header_results", {}).get("raw_headers", {})
            csp_val = None
            report_only = False

            for k, v in raw_headers.items():
                if k.lower() == "content-security-policy":
                    csp_val = v
                    report_only = False
                    break
                elif k.lower() == "content-security-policy-report-only":
                    csp_val = v
                    report_only = True
                    break

            # If not found in cache, make a fresh request
            if not csp_val:
                async with build_client(self.state, timeout=cfg.timeout, follow_redirects=True) as client:
                    resp = None
                    try:
                        resp = await client.get(cfg.url)
                    except Exception:
                        if cfg.url.startswith("https://"):
                            with contextlib.suppress(Exception):
                                resp = await client.get(cfg.url.replace("https://", "http://", 1))
                    if resp:
                        for k, v in resp.headers.items():
                            if k.lower() == "content-security-policy":
                                csp_val = v
                                report_only = False
                                break
                            elif k.lower() == "content-security-policy-report-only":
                                csp_val = v
                                report_only = True
                                break

            if status:
                status.progress = 60

            if csp_val:
                evaluated = self._evaluate_csp(csp_val, report_only)
                csp_results.append(evaluated)

                # Push findings based on evaluation
                for flaw in evaluated.flaws:
                    await push_finding(
                        self.state.findings_queue,
                        module="CSP",
                        severity=flaw.severity,
                        title=f"CSP Flaw ({flaw.directive}): {flaw.issue}",
                        detail=f"{flaw.impact}. Recommendation: {flaw.recommendation}",
                        evidence=f"Directive '{flaw.directive}' in CSP: {csp_val[:80]}...",
                    )
            else:
                # No CSP present at all
                no_csp = CSPResult(
                    raw_csp="",
                    report_only=False,
                    score=0,
                    grade="F",
                    directives={},
                    flaws=[
                        CSPFlaw(
                            severity="HIGH",
                            directive="Content-Security-Policy",
                            issue="No Content-Security-Policy header present",
                            impact="The browser has no defense against Cross-Site Scripting (XSS), data exfiltration, or unauthorized script injection",
                            recommendation="Deploy a robust Content-Security-Policy header restricting script-src, default-src, and object-src",
                        )
                    ],
                    bypass_vectors=["Complete absence of CSP allows arbitrary script injection and framing"],
                )
                csp_results.append(no_csp)

                await push_finding(
                    self.state.findings_queue,
                    module="CSP",
                    severity="HIGH",
                    title="Missing Content-Security-Policy (CSP)",
                    detail="Target provides no Content-Security-Policy header, leaving client-side defenses completely unconfigured.",
                    evidence=f"HTTP response from {cfg.url} contains no CSP header",
                )

        except Exception as exc:
            logger.error("CSP evaluation error: %s", exc, exc_info=True)

        self.state.csp_results = csp_results

        if status:
            status.state = "DONE"
            status.progress = 100
            score_str = f"Grade {csp_results[0].grade} ({csp_results[0].score}/100)" if csp_results else "Evaluated"
            status.message = score_str

        return csp_results
