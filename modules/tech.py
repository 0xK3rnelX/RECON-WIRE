"""Technology fingerprinting module — headers + body + Wappalyzer.

Writes TechDetection objects to state.tech_results.
Pushes findings for outdated/EOL versions and HTML comment leaks.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

import httpx
from bs4 import BeautifulSoup

from modules.findings import push_finding

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.tech")


@dataclass
class TechDetection:
    """A single technology detection result."""

    category: str
    name: str
    version: str | None = None
    confidence: str = "MEDIUM"  # HIGH | MEDIUM | LOW
    source: str = "HEADER"  # HEADER | BODY | WAPPALYZER | COOKIE

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── EOL/Outdated version lookup ──
EOL_VERSIONS: dict[str, str] = {
    "php/5": "PHP 5.x is EOL since Jan 2019",
    "php/7.0": "PHP 7.0 is EOL since Dec 2018",
    "php/7.1": "PHP 7.1 is EOL since Dec 2019",
    "php/7.2": "PHP 7.2 is EOL since Nov 2020",
    "php/7.3": "PHP 7.3 is EOL since Dec 2021",
    "php/7.4": "PHP 7.4 is EOL since Nov 2022",
    "php/8.0": "PHP 8.0 is EOL since Nov 2023",
    "apache/2.2": "Apache 2.2 is EOL since Jul 2017",
    "apache/2.0": "Apache 2.0 is EOL",
    "nginx/1.0": "Nginx 1.0.x is ancient and unsupported",
    "nginx/1.2": "Nginx 1.2.x is ancient and unsupported",
    "nginx/1.4": "Nginx 1.4.x is ancient and unsupported",
    "openssl/1.0": "OpenSSL 1.0.x is EOL since Dec 2019",
    "openssl/1.1.0": "OpenSSL 1.1.0 is EOL since Sep 2019",
    "jquery/1": "jQuery 1.x has known XSS vulnerabilities",
    "jquery/2": "jQuery 2.x is unmaintained",
    "angular/1": "AngularJS 1.x is EOL since Jan 2022",
    "bootstrap/3": "Bootstrap 3.x is EOL",
    "bootstrap/2": "Bootstrap 2.x is EOL",
    "python/2": "Python 2.x is EOL since Jan 2020",
    "python/3.5": "Python 3.5 is EOL since Sep 2020",
    "python/3.6": "Python 3.6 is EOL since Dec 2021",
    "node/10": "Node.js 10.x is EOL since Apr 2021",
    "node/12": "Node.js 12.x is EOL since Apr 2022",
    "node/14": "Node.js 14.x is EOL since Apr 2023",
    "wordpress/4": "WordPress 4.x is outdated — upgrade to latest",
    "drupal/7": "Drupal 7 reaches EOL Jan 2025",
    "asp.net/2": "ASP.NET 2.x is legacy",
    "asp.net/3": "ASP.NET 3.x is legacy",
    "iis/6": "IIS 6 runs on Windows Server 2003 — critically outdated",
    "iis/7": "IIS 7 runs on Windows Server 2008 — EOL",
    "iis/7.5": "IIS 7.5 runs on Windows Server 2008 R2 — EOL",
    "tomcat/6": "Apache Tomcat 6 is EOL",
    "tomcat/7": "Apache Tomcat 7 is EOL since Mar 2024",
    "rails/4": "Ruby on Rails 4.x is EOL",
    "rails/5": "Ruby on Rails 5.x is EOL since Jun 2022",
}

# ── Header fingerprint patterns ──
HEADER_SIGNATURES: list[dict[str, Any]] = [
    {"header": "server", "pattern": r"(?i)apache/?(\d[\d.]*)?", "category": "Web Server", "name": "Apache"},
    {"header": "server", "pattern": r"(?i)nginx/?(\d[\d.]*)?", "category": "Web Server", "name": "Nginx"},
    {"header": "server", "pattern": r"(?i)Microsoft-IIS/?(\d[\d.]*)?", "category": "Web Server", "name": "IIS"},
    {"header": "server", "pattern": r"(?i)LiteSpeed/?(\d[\d.]*)?", "category": "Web Server", "name": "LiteSpeed"},
    {"header": "server", "pattern": r"(?i)openresty/?(\d[\d.]*)?", "category": "Web Server", "name": "OpenResty"},
    {"header": "server", "pattern": r"(?i)cloudflare", "category": "CDN", "name": "Cloudflare"},
    {"header": "server", "pattern": r"(?i)AmazonS3", "category": "Cloud", "name": "Amazon S3"},
    {"header": "x-powered-by", "pattern": r"(?i)PHP/?(\d[\d.]*)?", "category": "Language", "name": "PHP"},
    {"header": "x-powered-by", "pattern": r"(?i)ASP\.NET\s*(\d[\d.]*)?", "category": "Framework", "name": "ASP.NET"},
    {"header": "x-powered-by", "pattern": r"(?i)Express", "category": "Framework", "name": "Express"},
    {"header": "x-powered-by", "pattern": r"(?i)Next\.js\s*(\d[\d.]*)?", "category": "Framework", "name": "Next.js"},
    {"header": "x-drupal-cache", "pattern": r".*", "category": "CMS", "name": "Drupal"},
    {"header": "x-generator", "pattern": r"(?i)WordPress\s*(\d[\d.]*)?", "category": "CMS", "name": "WordPress"},
    {"header": "x-generator", "pattern": r"(?i)Drupal\s*(\d[\d.]*)?", "category": "CMS", "name": "Drupal"},
    {"header": "x-generator", "pattern": r"(?i)Joomla\s*(\d[\d.]*)?", "category": "CMS", "name": "Joomla"},
    {"header": "via", "pattern": r"(?i)varnish", "category": "Cache", "name": "Varnish"},
    {"header": "x-varnish", "pattern": r".*", "category": "Cache", "name": "Varnish"},
    {"header": "x-cache", "pattern": r"(?i)HIT|MISS", "category": "Cache", "name": "CDN Cache"},
    {"header": "cf-ray", "pattern": r".*", "category": "CDN", "name": "Cloudflare"},
    {"header": "x-amz-cf-id", "pattern": r".*", "category": "CDN", "name": "CloudFront"},
    {"header": "x-azure-ref", "pattern": r".*", "category": "CDN", "name": "Azure CDN"},
]

# ── Body fingerprint patterns ──
BODY_SIGNATURES: list[dict[str, Any]] = [
    {"pattern": r"jquery[.-]?(\d[\d.]*)?\.(?:min\.)?js", "category": "JS Library", "name": "jQuery"},
    {"pattern": r"angular[.-]?(\d[\d.]*)?\.(?:min\.)?js", "category": "JS Framework", "name": "Angular"},
    {"pattern": r"react[.-]?(\d[\d.]*)?\.(?:min\.)?js", "category": "JS Framework", "name": "React"},
    {"pattern": r"vue[.-]?(\d[\d.]*)?\.(?:min\.)?js", "category": "JS Framework", "name": "Vue.js"},
    {"pattern": r"bootstrap[.-]?(\d[\d.]*)?\.(?:min\.)?(?:js|css)", "category": "CSS Framework", "name": "Bootstrap"},
    {
        "pattern": r"tailwind(?:css)?[.-]?(\d[\d.]*)?\.(?:min\.)?css",
        "category": "CSS Framework",
        "name": "Tailwind CSS",
    },
    {"pattern": r"wp-content/", "category": "CMS", "name": "WordPress"},
    {"pattern": r"wp-includes/", "category": "CMS", "name": "WordPress"},
    {"pattern": r"/sites/default/files/", "category": "CMS", "name": "Drupal"},
    {"pattern": r'content="WordPress\s*(\d[\d.]*)"', "category": "CMS", "name": "WordPress"},
    {"pattern": r'content="Drupal\s*(\d[\d.]*)"', "category": "CMS", "name": "Drupal"},
    {"pattern": r'content="Joomla!\s*(\d[\d.]*)"', "category": "CMS", "name": "Joomla"},
    {"pattern": r'<meta name="generator" content="([^"]+)"', "category": "Generator", "name": ""},
    {"pattern": r"ga\([\'\"]create[\'\"]", "category": "Analytics", "name": "Google Analytics"},
    {"pattern": r"gtag\(", "category": "Analytics", "name": "Google Tag Manager"},
    {"pattern": r"_gaq\.push", "category": "Analytics", "name": "Google Analytics (Legacy)"},
    {"pattern": r"hotjar\.com", "category": "Analytics", "name": "Hotjar"},
    {"pattern": r"fonts\.googleapis\.com", "category": "Font Service", "name": "Google Fonts"},
    {"pattern": r"use\.typekit\.net", "category": "Font Service", "name": "Adobe Fonts"},
    {"pattern": r"cloudflare\.com/ajax", "category": "CDN", "name": "Cloudflare"},
    {"pattern": r"cdn\.jsdelivr\.net", "category": "CDN", "name": "jsDelivr"},
    {"pattern": r"cdnjs\.cloudflare\.com", "category": "CDN", "name": "cdnjs"},
    {"pattern": r"unpkg\.com", "category": "CDN", "name": "unpkg"},
    {"pattern": r"recaptcha/api", "category": "Security", "name": "reCAPTCHA"},
    {"pattern": r"hcaptcha\.com", "category": "Security", "name": "hCaptcha"},
]

# ── Cookie-based fingerprints ──
COOKIE_SIGNATURES: dict[str, tuple[str, str]] = {
    "PHPSESSID": ("Language", "PHP"),
    "JSESSIONID": ("Language", "Java"),
    "ASP.NET_SessionId": ("Framework", "ASP.NET"),
    "ASPSESSIONID": ("Framework", "Classic ASP"),
    "laravel_session": ("Framework", "Laravel"),
    "ci_session": ("Framework", "CodeIgniter"),
    "rack.session": ("Framework", "Ruby (Rack)"),
    "connect.sid": ("Framework", "Express/Connect"),
    "wp-settings": ("CMS", "WordPress"),
    "_csrf": ("Security", "CSRF Token Framework"),
    "csrftoken": ("Security", "Django CSRF"),
}


class TechModule:
    """Technology fingerprinting via headers, body, and Wappalyzer."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.url = state.config.url
        self.timeout = state.config.timeout
        self.seen: set[str] = set()  # dedup by "category:name"

    async def run(self) -> None:
        status = self.state.module_statuses["TECH"]
        status.state = "RUNNING"
        status.message = "Fingerprinting target"
        logger.info("Tech module starting for %s", self.url)

        try:
            # Fetch response (need both headers and body)
            headers_dict, body, cookies = await self._fetch_response()
            status.progress = 20

            # Method A: Header fingerprinting
            status.message = "Analyzing headers"
            self._fingerprint_headers(headers_dict)
            status.progress = 40

            # Method B: Body scan
            status.message = "Scanning page body"
            self._fingerprint_body(body)
            status.progress = 60

            # Cookie fingerprinting
            status.message = "Analyzing cookies"
            self._fingerprint_cookies(cookies)
            status.progress = 70

            # Method C: Wappalyzer
            status.message = "Running Wappalyzer"
            await self._run_wappalyzer()
            status.progress = 85

            # HTML comment extraction
            status.message = "Extracting HTML comments"
            comments = self._extract_comments(body)
            if comments:
                self.state.tech_results.append(
                    TechDetection(
                        category="Leak",
                        name=f"{len(comments)} HTML comments found",
                        version=None,
                        confidence="HIGH",
                        source="BODY",
                    )
                )
                # Store comments in header_results for tech_tab display
                if "html_comments" not in self.state.header_results:
                    self.state.header_results["html_comments"] = comments
                for comment in comments[:5]:  # Limit to first 5
                    if any(
                        kw in comment.lower()
                        for kw in [
                            "todo",
                            "fixme",
                            "hack",
                            "bug",
                            "password",
                            "secret",
                            "api",
                            "key",
                            "token",
                            "credential",
                            "debug",
                            "admin",
                        ]
                    ):
                        await push_finding(
                            self.state.findings_queue,
                            severity="MEDIUM",
                            module="TECH",
                            title="Sensitive HTML Comment",
                            detail="HTML comment may contain sensitive information",
                            evidence=comment[:200],
                        )

            # EOL version checks
            status.message = "Checking for EOL versions"
            await self._check_eol_versions()
            status.progress = 100

            status.state = "DONE"
            status.message = f"Detected {len(self.state.tech_results)} technologies"
            logger.info("Tech module completed — %d detections", len(self.state.tech_results))

        except Exception as exc:
            status.state = "ERROR"
            status.message = f"Tech error: {exc}"
            logger.error("Tech module failed: %s", exc, exc_info=True)

    async def _fetch_response(self) -> tuple[dict[str, str], str, dict[str, str]]:
        """Fetch full HTTP response for analysis."""
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(self.url)
            except Exception:
                if self.url.startswith("https://"):
                    resp = await client.get(self.url.replace("https://", "http://", 1))
                else:
                    raise
            headers = dict(resp.headers)
            body = resp.text[:500000]  # Limit body scan to 500KB
            cookies = dict(resp.cookies.items())
            # Also parse Set-Cookie headers for more cookie names
            for sc in resp.headers.get_list("set-cookie"):
                match = re.match(r"^([^=]+)=", sc)
                if match:
                    cookies[match.group(1)] = ""
            return headers, body, cookies

    def _add_detection(self, detection: TechDetection) -> None:
        """Add a detection, deduplicating by category:name."""
        key = f"{detection.category}:{detection.name}"
        if key not in self.seen:
            self.seen.add(key)
            self.state.tech_results.append(detection)

    def _fingerprint_headers(self, headers: dict[str, str]) -> None:
        """Fingerprint technologies from response headers."""
        for sig in HEADER_SIGNATURES:
            value = headers.get(sig["header"], "")
            if not value:
                # Case-insensitive header lookup
                for k, v in headers.items():
                    if k.lower() == sig["header"].lower():
                        value = v
                        break
            if value:
                match = re.search(sig["pattern"], value)
                if match:
                    version = None
                    if match.lastindex and match.lastindex >= 1:
                        version = match.group(1)
                    self._add_detection(
                        TechDetection(
                            category=sig["category"],
                            name=sig["name"],
                            version=version,
                            confidence="HIGH",
                            source="HEADER",
                        )
                    )

    def _fingerprint_body(self, body: str) -> None:
        """Fingerprint technologies from HTML body."""
        for sig in BODY_SIGNATURES:
            match = re.search(sig["pattern"], body, re.IGNORECASE)
            if match:
                version = None
                if match.lastindex and match.lastindex >= 1:
                    version = match.group(1)
                name = sig["name"]
                if not name and match.lastindex and match.lastindex >= 1:
                    name = match.group(1)  # For generic generator pattern
                if name:
                    self._add_detection(
                        TechDetection(
                            category=sig["category"],
                            name=name,
                            version=version,
                            confidence="MEDIUM",
                            source="BODY",
                        )
                    )

        # BeautifulSoup deep analysis
        try:
            soup = BeautifulSoup(body, "html.parser")

            # Meta generator tags
            for meta in soup.find_all("meta", attrs={"name": re.compile(r"generator", re.I)}):
                content = meta.get("content", "")
                if content:
                    self._add_detection(
                        TechDetection(
                            category="Generator",
                            name=content[:50],
                            version=None,
                            confidence="HIGH",
                            source="BODY",
                        )
                    )

            # Script src analysis
            for script in soup.find_all("script", src=True):
                src = script["src"]
                for sig in BODY_SIGNATURES:
                    match = re.search(sig["pattern"], src, re.IGNORECASE)
                    if match and sig["name"]:
                        version = match.group(1) if match.lastindex else None
                        self._add_detection(
                            TechDetection(
                                category=sig["category"],
                                name=sig["name"],
                                version=version,
                                confidence="HIGH",
                                source="BODY",
                            )
                        )

            # Link href analysis (stylesheets)
            for link in soup.find_all("link", rel="stylesheet", href=True):
                href = link["href"]
                for sig in BODY_SIGNATURES:
                    match = re.search(sig["pattern"], href, re.IGNORECASE)
                    if match and sig["name"]:
                        version = match.group(1) if match.lastindex else None
                        self._add_detection(
                            TechDetection(
                                category=sig["category"],
                                name=sig["name"],
                                version=version,
                                confidence="HIGH",
                                source="BODY",
                            )
                        )

        except Exception as exc:
            logger.debug("BeautifulSoup analysis error: %s", exc)

    def _fingerprint_cookies(self, cookies: dict[str, str]) -> None:
        """Fingerprint technologies from cookie names."""
        for cookie_name in cookies:
            for sig_name, (category, tech) in COOKIE_SIGNATURES.items():
                if sig_name.lower() in cookie_name.lower():
                    self._add_detection(
                        TechDetection(
                            category=category,
                            name=tech,
                            version=None,
                            confidence="MEDIUM",
                            source="COOKIE",
                        )
                    )

    async def _run_wappalyzer(self) -> None:
        """Run python-Wappalyzer analysis."""
        try:
            from Wappalyzer import Wappalyzer, WebPage

            loop = asyncio.get_event_loop()

            def _wap_analyze() -> dict:
                wappalyzer = Wappalyzer.latest()
                webpage = WebPage.new_from_url(self.url)
                return wappalyzer.analyze_with_versions_and_categories(webpage)

            results = await loop.run_in_executor(None, _wap_analyze)

            for tech_name, details in results.items():
                versions = details.get("versions", set())
                categories = details.get("categories", set())
                version = next(iter(versions), None) if versions else None
                category = next(iter(categories), "Unknown") if categories else "Unknown"
                self._add_detection(
                    TechDetection(
                        category=str(category),
                        name=tech_name,
                        version=version,
                        confidence="HIGH",
                        source="WAPPALYZER",
                    )
                )
        except ImportError:
            logger.warning("python-Wappalyzer not available — skipping Wappalyzer analysis")
        except Exception as exc:
            logger.debug("Wappalyzer analysis failed: %s", exc)

    def _extract_comments(self, body: str) -> list[str]:
        """Extract HTML comments from page body."""
        comments: list[str] = []
        try:
            soup = BeautifulSoup(body, "html.parser")
            from bs4 import Comment

            for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                text = comment.strip()
                if text and len(text) > 3:  # Skip trivial empty comments
                    comments.append(text[:500])
        except Exception as exc:
            logger.debug("Comment extraction failed: %s", exc)
        return comments

    async def _check_eol_versions(self) -> None:
        """Check detected technologies against EOL version database."""
        for tech in self.state.tech_results:
            if not tech.version:
                continue
            name_lower = tech.name.lower()
            version = tech.version

            for eol_key, eol_message in EOL_VERSIONS.items():
                key_name, key_version = eol_key.split("/", 1)
                if key_name in name_lower and version.startswith(key_version):
                    await push_finding(
                        self.state.findings_queue,
                        severity="HIGH",
                        module="TECH",
                        title=f"EOL/Outdated: {tech.name} {version}",
                        detail=eol_message,
                        evidence=f"Detected via {tech.source}: {tech.name}/{version}",
                    )
                    break
