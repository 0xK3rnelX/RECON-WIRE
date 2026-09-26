"""DNS Takeover & Dangling CNAME Hunter (PA-3).

Checks CNAME pointers against known cloud service signatures (GitHub Pages, Heroku,
AWS S3, Zendesk, Fastly, Shopify, Pantheon, Readme.io, WordPress, Tumblr, Ghost, etc.).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.resolver

from modules.findings import push_finding
from modules.stealth import apply_stealth_delay, build_client

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.takeover")

# Fingerprints for dangling services: CNAME domain substring -> (service name, response body fingerprint)
TAKEOVER_SIGNATURES: list[dict[str, str]] = [
    # Static Hosting & Git Providers
    {
        "service": "GitHub Pages",
        "cname": "github.io",
        "fingerprint": "There isn't a GitHub Pages site here",
    },
    {
        "service": "GitLab Pages",
        "cname": "gitlab.io",
        "fingerprint": "The page you're looking for could not be found",
    },
    {
        "service": "Bitbucket",
        "cname": "bitbucket.io",
        "fingerprint": "Repository not found",
    },
    {
        "service": "Surge.sh",
        "cname": "surge.sh",
        "fingerprint": "project not found",
    },
    {
        "service": "Vercel",
        "cname": "vercel.app",
        "fingerprint": "404: NOT_FOUND",
    },
    {
        "service": "Vercel (Legacy)",
        "cname": "now.sh",
        "fingerprint": "DEPLOYMENT_NOT_FOUND",
    },
    {
        "service": "Netlify",
        "cname": "netlify.app",
        "fingerprint": "Not Found - Request ID",
    },
    {
        "service": "Cloudflare Pages",
        "cname": "pages.dev",
        "fingerprint": "Deployment not found",
    },
    {
        "service": "Render",
        "cname": "onrender.com",
        "fingerprint": "Render | Page not found",
    },
    {
        "service": "Fly.io",
        "cname": "fly.dev",
        "fingerprint": "404 Not Found",
    },
    # Cloud Infrastructure & Storage
    {
        "service": "AWS S3 Bucket",
        "cname": "s3.amazonaws.com",
        "fingerprint": "The specified bucket does not exist",
    },
    {
        "service": "AWS S3 Bucket",
        "cname": "s3-website",
        "fingerprint": "NoSuchBucket",
    },
    {
        "service": "AWS CloudFront",
        "cname": "cloudfront.net",
        "fingerprint": "Bad Request: ERROR: The request could not be satisfied",
    },
    {
        "service": "AWS Elastic Beanstalk",
        "cname": "elasticbeanstalk.com",
        "fingerprint": "404 Not Found",
    },
    {
        "service": "Azure App Service",
        "cname": "azurewebsites.net",
        "fingerprint": "404 Web Site not found",
    },
    {
        "service": "Azure Traffic Manager",
        "cname": "trafficmanager.net",
        "fingerprint": "404 Web Site not found",
    },
    {
        "service": "Heroku",
        "cname": "herokudns.com",
        "fingerprint": "No such app",
    },
    {
        "service": "Heroku",
        "cname": "herokuapp.com",
        "fingerprint": "No such app",
    },
    {
        "service": "Fastly CDN",
        "cname": "fastly.net",
        "fingerprint": "Fastly error: unknown domain",
    },
    {
        "service": "Pantheon",
        "cname": "pantheonsite.io",
        "fingerprint": "The gods are wise, but do not know of the site which you seek",
    },
    # E-Commerce & CMS Platforms
    {
        "service": "Shopify",
        "cname": "myshopify.com",
        "fingerprint": "Sorry, this shop is currently unavailable",
    },
    {
        "service": "Ghost",
        "cname": "ghost.io",
        "fingerprint": "The thing you were looking for is no longer here",
    },
    {
        "service": "WordPress.com",
        "cname": "wordpress.com",
        "fingerprint": "Do you want to register",
    },
    {
        "service": "Tumblr",
        "cname": "domains.tumblr.com",
        "fingerprint": "Whatever you were looking for doesn't seem to exist",
    },
    {
        "service": "Webflow",
        "cname": "proxy.webflow.com",
        "fingerprint": "The page you are looking for doesn't exist",
    },
    {
        "service": "Strikingly",
        "cname": "strikinglydns.com",
        "fingerprint": "page not found",
    },
    {
        "service": "Cargo Collective",
        "cname": "cargocollective.com",
        "fingerprint": "404 Not Found",
    },
    {
        "service": "Hubspot",
        "cname": "hubspot.net",
        "fingerprint": "Domain not found",
    },
    # Support, Documentation & Analytics
    {
        "service": "Zendesk",
        "cname": "zendesk.com",
        "fingerprint": "Help Center Closed",
    },
    {
        "service": "Readme.io",
        "cname": "readme.io",
        "fingerprint": "Project doesnt exist... yet!",
    },
    {
        "service": "Help Scout",
        "cname": "helpscoutdocs.com",
        "fingerprint": "No settings were found for this company",
    },
    {
        "service": "Freshdesk",
        "cname": "freshdesk.com",
        "fingerprint": "May be this page moved",
    },
    {
        "service": "Statuspage.io",
        "cname": "statuspage.io",
        "fingerprint": "You are being redirected to another page",
    },
    {
        "service": "UserVoice",
        "cname": "uservoice.com",
        "fingerprint": "This UserVoice subdomain is currently available!",
    },
    {
        "service": "Unbounce",
        "cname": "unbouncepages.com",
        "fingerprint": "The requested URL was not found on this server",
    },
    {
        "service": "Campaign Monitor",
        "cname": "createsend.com",
        "fingerprint": "Double check the URL or",
    },
]


@dataclass
class TakeoverResult:
    subdomain: str
    cname: str
    service: str
    status: str  # VULNERABLE | DANGLING | VERIFIED
    fingerprint: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class TakeoverModule:
    """Advanced Subdomain Takeover & Dangling CNAME Detector."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def _resolve_cname(self, resolver: dns.asyncresolver.Resolver, host: str) -> str | None:
        try:
            ans = await resolver.resolve(host, "CNAME")
            for r in ans:
                return str(r.target).rstrip(".")
        except Exception:
            return None
        return None

    async def _verify_takeover(
        self, client, subdomain: str, cname: str, sig: dict, semaphore: asyncio.Semaphore
    ) -> TakeoverResult | None:
        async with semaphore:
            await apply_stealth_delay(self.state.config)
            test_url = f"http://{subdomain}"
            fingerprint = sig["fingerprint"]
            service = sig["service"]
            try:
                resp = await client.get(test_url)
                body = resp.text

                # Check if dangling service fingerprint matches
                if fingerprint.lower() in body.lower():
                    await push_finding(
                        self.state.findings_queue,
                        module="TAKEOVER",
                        severity="CRITICAL",
                        title=f"Subdomain Takeover Vulnerability: {subdomain}",
                        detail=(
                            f"Subdomain '{subdomain}' points via CNAME to '{cname}' ({service}), "
                            f"which appears unclaimed and returned signature: '{fingerprint}'."
                        ),
                        evidence=f"CNAME: {cname} -> Fingerprint '{fingerprint}' verified on {test_url}",
                    )
                    return TakeoverResult(
                        subdomain=subdomain,
                        cname=cname,
                        service=service,
                        status="VULNERABLE",
                        fingerprint=fingerprint,
                    )
                else:
                    return TakeoverResult(
                        subdomain=subdomain,
                        cname=cname,
                        service=service,
                        status="VERIFIED",
                        fingerprint="",
                    )
            except Exception:
                # If connection refused or NXDOMAIN but CNAME matches signature
                return TakeoverResult(
                    subdomain=subdomain,
                    cname=cname,
                    service=service,
                    status="DANGLING",
                    fingerprint="Host unreachable",
                )

    async def run(self) -> list[TakeoverResult]:
        status = self.state.module_statuses.get("TAKEOVER")
        if status:
            status.state = "RUNNING"
            status.message = "Analyzing CNAME pointers for takeover vectors..."

        cfg = self.state.config
        subdomains_to_check = set()
        subdomains_to_check.add(cfg.hostname)

        # Include discovered subdomains
        for s in self.state.subdomain_results:
            sub = getattr(s, "subdomain", str(s))
            if sub:
                subdomains_to_check.add(sub)

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = float(cfg.timeout)
        resolver.lifetime = float(cfg.timeout)

        # 1. Resolve all CNAMEs
        cname_map: dict[str, str] = {}
        for sub in subdomains_to_check:
            cname = await self._resolve_cname(resolver, sub)
            if cname:
                cname_map[sub] = cname

        # Also pull existing CNAME records from DNS module if present
        dns_cnames = self.state.dns_results.get("CNAME", [])
        for rec in dns_cnames:
            val = str(rec.get("value", "")).rstrip(".")
            if val:
                cname_map[cfg.hostname] = val

        # 2. Match CNAME against cloud signatures
        checks = []
        semaphore = asyncio.Semaphore(cfg.max_concurrent)

        results: list[TakeoverResult] = []
        async with build_client(cfg) as client:
            for sub, cname in cname_map.items():
                cname_lower = cname.lower()
                for sig in TAKEOVER_SIGNATURES:
                    if sig["cname"] in cname_lower:
                        checks.append(self._verify_takeover(client, sub, cname, sig, semaphore))
                        break

            if checks:
                raw = await asyncio.gather(*checks, return_exceptions=True)
                results = [r for r in raw if isinstance(r, TakeoverResult)]

        self.state.takeover_results = results

        vuln_count = sum(1 for r in results if r.status == "VULNERABLE")
        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(results)} pointers audited ({vuln_count} vulnerable)"

        return results
