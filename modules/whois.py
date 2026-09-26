"""WHOIS query module — domain registration, expiry, DNSSEC, contact analysis.

Writes results to state.whois_results.
Pushes findings for expiry, DNSSEC, contact anomalies.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

import whois

from modules.findings import push_finding

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.whois")


class WHOISModule:
    """WHOIS domain registration lookup and analysis."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.domain = state.config.domain

    async def run(self) -> None:
        status = self.state.module_statuses["WHOIS"]
        status.state = "RUNNING"
        status.message = "Querying WHOIS"
        logger.info("WHOIS module starting for %s", self.domain)

        try:
            # python-whois is synchronous — run in executor
            loop = asyncio.get_event_loop()
            raw = await loop.run_in_executor(None, whois.whois, self.domain)
            status.progress = 60
            status.message = "Parsing WHOIS data"

            results = self._parse_whois(raw)
            self.state.whois_results.update(results)
            status.progress = 80

            # Analyze findings
            status.message = "Analyzing WHOIS data"
            await self._analyze_findings(results)

            status.state = "DONE"
            status.progress = 100
            registrar = results.get("registrar", "Unknown")
            status.message = f"Registrar: {registrar}"
            logger.info("WHOIS module completed — Registrar: %s", registrar)

        except Exception as exc:
            status.state = "ERROR"
            status.message = f"WHOIS error: {exc}"
            logger.error("WHOIS module failed: %s", exc, exc_info=True)
            await push_finding(
                self.state.findings_queue,
                severity="INFO",
                module="WHOIS",
                title="WHOIS Lookup Failed",
                detail=str(exc),
                evidence=f"Domain: {self.domain}",
            )

    def _parse_whois(self, raw: Any) -> dict[str, Any]:
        """Parse python-whois result object into a clean dictionary."""
        results: dict[str, Any] = {}

        # Domain name
        domain_name = getattr(raw, "domain_name", None)
        if isinstance(domain_name, list):
            results["domain_name"] = domain_name[0] if domain_name else self.domain
            results["domain_name_variants"] = domain_name
        else:
            results["domain_name"] = domain_name or self.domain

        # Registrar
        results["registrar"] = getattr(raw, "registrar", "Unknown") or "Unknown"

        # WHOIS server
        results["whois_server"] = getattr(raw, "whois_server", "") or ""

        # Dates
        for date_field in ("creation_date", "expiration_date", "updated_date"):
            value = getattr(raw, date_field, None)
            if isinstance(value, list):
                value = value[0] if value else None
            if isinstance(value, datetime):
                results[date_field] = value.isoformat()
                results[f"{date_field}_raw"] = value
            elif value:
                results[date_field] = str(value)
                results[f"{date_field}_raw"] = None
            else:
                results[date_field] = None
                results[f"{date_field}_raw"] = None

        # Status
        status_val = getattr(raw, "status", None)
        if isinstance(status_val, list):
            results["status"] = status_val
        elif status_val:
            results["status"] = [status_val]
        else:
            results["status"] = []

        # Name servers
        ns = getattr(raw, "name_servers", None)
        if isinstance(ns, set):
            results["name_servers"] = sorted(ns)
        elif isinstance(ns, list):
            results["name_servers"] = sorted(set(ns))
        else:
            results["name_servers"] = []

        # Contact info
        for contact_field in ("registrant", "admin", "tech"):
            for sub_field in ("name", "organization", "email", "country"):
                key = f"{contact_field}_{sub_field}"
                results[key] = getattr(raw, key, "") or ""

        # Fallback fields
        results["org"] = getattr(raw, "org", "") or ""
        results["emails"] = getattr(raw, "emails", []) or []
        if isinstance(results["emails"], str):
            results["emails"] = [results["emails"]]
        results["country"] = getattr(raw, "country", "") or ""
        results["state"] = getattr(raw, "state", "") or ""
        results["city"] = getattr(raw, "city", "") or ""
        results["address"] = getattr(raw, "address", "") or ""

        # DNSSEC
        dnssec = getattr(raw, "dnssec", None)
        if isinstance(dnssec, str):
            results["dnssec"] = dnssec.lower()
        elif dnssec:
            results["dnssec"] = str(dnssec).lower()
        else:
            results["dnssec"] = "unknown"

        # Compute domain age
        from datetime import timezone

        now = datetime.now(timezone.utc)
        creation_raw = results.get("creation_date_raw")
        if isinstance(creation_raw, datetime):
            c_date = creation_raw if creation_raw.tzinfo else creation_raw.replace(tzinfo=timezone.utc)
            age = now - c_date
            results["domain_age_days"] = age.days
            years = age.days // 365
            months = (age.days % 365) // 30
            results["domain_age_human"] = f"{years}y {months}m"
        else:
            results["domain_age_days"] = None
            results["domain_age_human"] = "Unknown"

        # Compute days until expiry
        expiry_raw = results.get("expiration_date_raw")
        if isinstance(expiry_raw, datetime):
            e_date = expiry_raw if expiry_raw.tzinfo else expiry_raw.replace(tzinfo=timezone.utc)
            remaining = e_date - now
            results["days_until_expiry"] = remaining.days
        else:
            results["days_until_expiry"] = None

        return results

    async def _analyze_findings(self, results: dict[str, Any]) -> None:
        """Push findings based on WHOIS analysis."""
        q = self.state.findings_queue

        # Expiry checks
        days_until = results.get("days_until_expiry")
        if days_until is not None:
            if days_until < 0:
                await push_finding(
                    q,
                    severity="CRITICAL",
                    module="WHOIS",
                    title="Domain Has Expired",
                    detail=f"Domain expired {abs(days_until)} days ago — vulnerable to takeover",
                    evidence=f"Expiry: {results.get('expiration_date', 'N/A')}",
                )
            elif days_until < 30:
                await push_finding(
                    q,
                    severity="HIGH",
                    module="WHOIS",
                    title="Domain Expiring Within 30 Days",
                    detail=f"Domain expires in {days_until} days — renew immediately",
                    evidence=f"Expiry: {results.get('expiration_date', 'N/A')}",
                )
            elif days_until < 90:
                await push_finding(
                    q,
                    severity="MEDIUM",
                    module="WHOIS",
                    title="Domain Expiring Within 90 Days",
                    detail=f"Domain expires in {days_until} days — plan renewal",
                    evidence=f"Expiry: {results.get('expiration_date', 'N/A')}",
                )

        # DNSSEC check
        dnssec = results.get("dnssec", "unknown")
        if dnssec in ("unsigned", "unknown", ""):
            await push_finding(
                q,
                severity="MEDIUM",
                module="WHOIS",
                title="DNSSEC Not Enabled",
                detail="Domain does not have DNSSEC — vulnerable to DNS spoofing",
                evidence=f"DNSSEC status: {dnssec}",
            )

        # Young domain check
        age_days = results.get("domain_age_days")
        if age_days is not None and age_days < 90:
            await push_finding(
                q,
                severity="MEDIUM",
                module="WHOIS",
                title="Recently Registered Domain",
                detail=f"Domain is only {age_days} days old — may indicate phishing or temporary site",
                evidence=f"Created: {results.get('creation_date', 'N/A')}",
            )

        # Privacy/redacted contact check
        emails = results.get("emails", [])
        org = results.get("org", "")
        all_contact_fields = [
            results.get("registrant_name", ""),
            results.get("registrant_organization", ""),
            results.get("registrant_email", ""),
        ]
        has_privacy = any(
            kw in str(all_contact_fields + emails + [org]).lower()
            for kw in [
                "privacy",
                "redacted",
                "whoisguard",
                "domains by proxy",
                "contact privacy",
                "private",
                "data protected",
            ]
        )
        if has_privacy:
            await push_finding(
                q,
                severity="INFO",
                module="WHOIS",
                title="WHOIS Privacy Protection Enabled",
                detail="Registrant details are behind a privacy service",
                evidence=f"Org: {org}, Emails: {', '.join(emails[:3])}",
            )

        # Status anomalies
        statuses = results.get("status", [])
        hold_statuses = [s for s in statuses if "hold" in s.lower()]
        if hold_statuses:
            await push_finding(
                q,
                severity="HIGH",
                module="WHOIS",
                title="Domain Has Hold Status",
                detail=f"Domain has restrictive status: {', '.join(hold_statuses)}",
                evidence=f"Statuses: {', '.join(statuses)}",
            )
