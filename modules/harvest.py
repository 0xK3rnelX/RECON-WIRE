"""Email, credentials, and API secret scraper module (PA-2).

Extracts high-value leaked intelligence from HTML, scripts, and comments:
- Corporate email addresses
- AWS Access Keys & Secrets
- GitHub Personal Access Tokens
- Google API Keys
- Slack Webhooks
- JWT Tokens
- Private Keys
- Internal usernames and employee handles
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from modules.findings import push_finding
from modules.stealth import apply_stealth_delay, build_client

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.harvest")

# Comprehensive high-entropy secret regular expressions
SECRET_PATTERNS: list[dict[str, str]] = [
    {
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
    },
    {
        "name": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "pattern": r"(?i)aws_(?:secret_access_key|secret_key)\s*[:=]\s*['\"]([0-9a-zA-Z/+]{40})['\"]",
    },
    {
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "pattern": r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b",
    },
    {
        "name": "GitHub OAuth / App Token",
        "severity": "CRITICAL",
        "pattern": r"\b(gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})\b",
    },
    {
        "name": "Google Cloud API Key",
        "severity": "HIGH",
        "pattern": r"\b(AIza[0-9A-Za-z\-_]{35})\b",
    },
    {
        "name": "Google OAuth Access Token",
        "severity": "CRITICAL",
        "pattern": r"\b(ya29\.[0-9A-Za-z\-_]{20,})\b",
    },
    {
        "name": "Slack Bot / User Token",
        "severity": "CRITICAL",
        "pattern": r"\b(xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}|xoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24})\b",
    },
    {
        "name": "Slack Webhook URL",
        "severity": "CRITICAL",
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    },
    {
        "name": "Stripe Live Secret Key",
        "severity": "CRITICAL",
        "pattern": r"\b(sk_live_[0-9a-zA-Z]{24,34})\b",
    },
    {
        "name": "Stripe Restricted API Key",
        "severity": "CRITICAL",
        "pattern": r"\b(rk_live_[0-9a-zA-Z]{24,34})\b",
    },
    {
        "name": "Square Access Token",
        "severity": "CRITICAL",
        "pattern": r"\b(sq0atp-[0-9A-Za-z\-_]{22})\b",
    },
    {
        "name": "Twilio Account SID",
        "severity": "MEDIUM",
        "pattern": r"\b(AC[a-f0-9]{32})\b",
    },
    {
        "name": "SendGrid API Key",
        "severity": "HIGH",
        "pattern": r"\b(SG\.[0-9a-zA-Z_\-]{22}\.[0-9a-zA-Z_\-]{43})\b",
    },
    {
        "name": "Mailgun API Key",
        "severity": "HIGH",
        "pattern": r"\b(key-[0-9a-zA-Z]{32})\b",
    },
    {
        "name": "Discord Webhook URL",
        "severity": "HIGH",
        "pattern": r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{68})",
    },
    {
        "name": "Telegram Bot Token",
        "severity": "HIGH",
        "pattern": r"\b([0-9]{9,10}:[a-zA-Z0-9_-]{35})\b",
    },
    {
        "name": "NPM Access Token",
        "severity": "CRITICAL",
        "pattern": r"\b(npm_[a-zA-Z0-9]{36})\b",
    },
    {
        "name": "PyPI API Token",
        "severity": "CRITICAL",
        "pattern": r"\b(pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9\-_]{50,})\b",
    },
    {
        "name": "Cryptographic Private Key",
        "severity": "CRITICAL",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    },
    {
        "name": "JSON Web Token (JWT)",
        "severity": "MEDIUM",
        "pattern": r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b",
    },
    {
        "name": "Generic Hardcoded Password / Secret",
        "severity": "HIGH",
        "pattern": r'(?i)(?:password|passwd|api_key|secret_key|auth_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-!@#$%^&*]{8,32})["\']',
    },
]

EMAIL_PATTERN = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"


class HarvestModule:
    """Deep OSINT scraper for corporate emails and hardcoded secrets."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def run(self) -> dict[str, Any]:
        status = self.state.module_statuses.get("HARVEST")
        if status:
            status.state = "RUNNING"
            status.message = "Scraping web assets for emails & API secrets..."

        cfg = self.state.config
        discovered_emails: set[str] = set()
        discovered_secrets: list[dict[str, str]] = []

        # Target URLs to scrape: main URL + any discovered script files
        urls_to_scrape = [cfg.url]
        for ep in self.state.endpoint_results:
            if getattr(ep, "category", "") == "SCRIPT":
                urls_to_scrape.append(getattr(ep, "url", ""))

        # Limit depth to top 15 scripts to avoid timeouts
        urls_to_scrape = urls_to_scrape[:15]

        try:
            async with build_client(cfg) as client:
                for target_url in urls_to_scrape:
                    await apply_stealth_delay(cfg)
                    try:
                        resp = await client.get(target_url)
                        text = resp.text

                        # 1. Scrape Emails
                        raw_emails = re.findall(EMAIL_PATTERN, text)
                        for em in raw_emails:
                            # Discard file extensions mistaken as emails
                            if not em.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg")):
                                discovered_emails.add(em)

                        # 2. Scrape Secrets
                        for sec in SECRET_PATTERNS:
                            matches = re.findall(sec["pattern"], text)
                            for m in matches:
                                val = m if isinstance(m, str) else m[0]
                                masked = val[:6] + "..." + val[-4:] if len(val) > 10 else "***"
                                item = {
                                    "type": sec["name"],
                                    "severity": sec["severity"],
                                    "masked": masked,
                                    "source": target_url,
                                }
                                if item not in discovered_secrets:
                                    discovered_secrets.append(item)
                                    await push_finding(
                                        self.state.findings_queue,
                                        module="HARVEST",
                                        severity=sec["severity"],
                                        title=f"Leaked Secret: {sec['name']}",
                                        detail=f"Detected pattern for {sec['name']} in {target_url} (Token: {masked})",
                                        evidence=f"Source: {target_url} | Secret signature: {sec['name']}",
                                    )

                    except Exception:
                        pass

        except Exception as exc:
            logger.error("Harvest module error: %s", exc)

        results = {
            "emails": sorted(discovered_emails),
            "secrets": discovered_secrets,
            "total_emails": len(discovered_emails),
            "total_secrets": len(discovered_secrets),
        }
        self.state.harvest_results = results

        # Informational finding for exposed emails
        if discovered_emails:
            domain_emails = [e for e in discovered_emails if cfg.domain in e]
            await push_finding(
                self.state.findings_queue,
                module="HARVEST",
                severity="INFO",
                title=f"Discovered Corporate Emails ({len(domain_emails)})",
                detail=f"Found {len(discovered_emails)} total email addresses ({', '.join(domain_emails[:5])})",
                evidence=f"Emails: {', '.join(list(discovered_emails)[:10])}",
            )

        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(discovered_emails)} emails, {len(discovered_secrets)} secrets uncovered"

        return results
