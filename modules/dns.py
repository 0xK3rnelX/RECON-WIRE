"""DNS reconnaissance module — A/AAAA/MX/TXT/NS/CNAME/SOA/CAA + PTR + GeoIP + AXFR.

Writes results to state.dns_results, pushes findings to state.findings_queue.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

import dns.asyncresolver
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone
import httpx

from modules.findings import push_finding

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.dns")

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]


@dataclass
class GeoInfo:
    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    as_number: str = ""
    lat: float = 0.0
    lon: float = 0.0


@dataclass
class DNSRecord:
    rtype: str
    value: str
    ttl: int = 0
    ptr: str = ""
    geo: GeoInfo | None = None
    flags: list[str] = field(default_factory=list)


class DNSModule:
    """Full DNS reconnaissance module."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.hostname = state.config.hostname
        self.domain = state.config.domain
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = state.config.timeout
        self.resolver.lifetime = state.config.timeout

    async def run(self) -> None:
        """Execute full DNS recon pipeline."""
        status = self.state.module_statuses["DNS"]
        status.state = "RUNNING"
        status.message = "Starting DNS enumeration"
        logger.info("DNS module starting for %s", self.domain)

        try:
            all_records: dict[str, list[dict[str, Any]]] = {}
            total = len(RECORD_TYPES)

            for idx, rtype in enumerate(RECORD_TYPES, 1):
                status.progress = int((idx / (total + 3)) * 100)
                status.message = f"Resolving {rtype} records"
                records = await self._resolve_type(rtype)
                if records:
                    all_records[rtype] = [self._record_to_dict(r) for r in records]
                logger.debug("%s: %d %s records", self.domain, len(records), rtype)

            # PTR lookups on A records
            status.message = "Running PTR reverse lookups"
            a_records = all_records.get("A", [])
            for rec in a_records:
                ptr = await self._reverse_lookup(rec["value"])
                if ptr:
                    rec["ptr"] = ptr

            # GeoIP lookups
            if self.state.config.geoip_enabled and a_records:
                status.message = "Running GeoIP lookups"
                for rec in a_records:
                    geo = await self._geoip_lookup(rec["value"])
                    if geo:
                        rec["geo"] = asdict(geo)

            # AXFR
            if self.state.config.axfr_enabled:
                status.message = "Attempting zone transfers"
                ns_records = all_records.get("NS", [])
                axfr_results = await self._try_axfr(ns_records)
                if axfr_results:
                    all_records["AXFR"] = axfr_results

            # Analyze findings
            await self._analyze_findings(all_records)

            self.state.dns_results.update(all_records)
            status.state = "DONE"
            status.progress = 100
            status.message = f"Resolved {sum(len(v) for v in all_records.values())} records"
            logger.info("DNS module completed — %s", status.message)

        except Exception as exc:
            status.state = "ERROR"
            status.message = f"DNS error: {exc}"
            logger.error("DNS module failed: %s", exc, exc_info=True)
            await push_finding(
                self.state.findings_queue,
                severity="MEDIUM",
                module="DNS",
                title="DNS Module Error",
                detail=str(exc),
                evidence=f"Target: {self.domain}",
            )

    async def _resolve_type(self, rtype: str) -> list[DNSRecord]:
        """Resolve a single record type."""
        records: list[DNSRecord] = []
        try:
            answer = await self.resolver.resolve(self.domain, rtype)
            for rdata in answer:
                value = rdata.to_text().strip('"')
                rec = DNSRecord(rtype=rtype, value=value, ttl=answer.rrset.ttl if answer.rrset else 0)
                # Flag low TTLs (potential fast-flux)
                if rec.ttl > 0 and rec.ttl < 60:
                    rec.flags.append("LOW_TTL")
                # Flag private IPs in A records
                if rtype == "A":
                    try:
                        addr = ipaddress.ip_address(value)
                        if addr.is_private:
                            rec.flags.append("PRIVATE_IP")
                    except ValueError:
                        pass
                records.append(rec)
        except dns.resolver.NoAnswer:
            logger.debug("No %s records for %s", rtype, self.domain)
        except dns.resolver.NXDOMAIN:
            logger.warning("NXDOMAIN for %s/%s", self.domain, rtype)
        except dns.resolver.NoNameservers:
            logger.warning("No nameservers for %s/%s", self.domain, rtype)
        except dns.exception.Timeout:
            logger.warning("Timeout resolving %s/%s", self.domain, rtype)
        except Exception as exc:
            logger.debug("Error resolving %s/%s: %s", self.domain, rtype, exc)
        return records

    async def _reverse_lookup(self, ip: str) -> str:
        """PTR reverse lookup on an IP address."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answer = await self.resolver.resolve(rev_name, "PTR")
            return str(answer[0]).rstrip(".")
        except Exception:
            return ""

    async def _geoip_lookup(self, ip: str) -> GeoInfo | None:
        """GeoIP lookup via ip-api.com (free tier, no key required)."""
        try:
            async with httpx.AsyncClient(timeout=self.state.config.timeout) as client:
                resp = await client.get(f"http://ip-api.com/json/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return GeoInfo(
                            country=data.get("country", ""),
                            region=data.get("regionName", ""),
                            city=data.get("city", ""),
                            isp=data.get("isp", ""),
                            org=data.get("org", ""),
                            as_number=data.get("as", ""),
                            lat=data.get("lat", 0.0),
                            lon=data.get("lon", 0.0),
                        )
        except Exception as exc:
            logger.debug("GeoIP lookup failed for %s: %s", ip, exc)
        return None

    async def _try_axfr(self, ns_records: list[dict[str, Any]]) -> list[dict[str, str]]:
        """Attempt AXFR zone transfer on each nameserver."""
        axfr_results: list[dict[str, str]] = []
        loop = asyncio.get_event_loop()
        for ns_rec in ns_records:
            ns_host = ns_rec.get("value", "").rstrip(".")
            if not ns_host:
                continue
            try:
                result = await loop.run_in_executor(None, self._sync_axfr, ns_host)
                if result:
                    axfr_results.extend(result)
                    await push_finding(
                        self.state.findings_queue,
                        severity="CRITICAL",
                        module="DNS",
                        title="Zone Transfer (AXFR) Successful",
                        detail=f"Nameserver {ns_host} allows unrestricted zone transfers",
                        evidence=f"Retrieved {len(result)} records via AXFR from {ns_host}",
                    )
            except Exception as exc:
                logger.debug("AXFR failed on %s: %s", ns_host, exc)
        return axfr_results

    def _sync_axfr(self, ns_host: str) -> list[dict[str, str]]:
        """Synchronous AXFR attempt (runs in executor)."""
        records: list[dict[str, str]] = []
        try:
            # Resolve NS hostname to IP first
            ns_ip = socket.gethostbyname(ns_host)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=self.state.config.timeout))
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(
                            {
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "value": rdata.to_text(),
                                "ns": ns_host,
                            }
                        )
        except Exception:
            pass  # Expected — most servers deny AXFR
        return records

    async def _analyze_findings(self, results: dict[str, list]) -> None:
        """Push findings based on DNS analysis."""
        q = self.state.findings_queue

        # Check for missing SPF
        txt_records = results.get("TXT", [])
        has_spf = any("v=spf1" in r.get("value", "").lower() for r in txt_records)
        if not has_spf:
            await push_finding(
                q,
                severity="MEDIUM",
                module="DNS",
                title="Missing SPF Record",
                detail="No SPF TXT record found — domain may be vulnerable to email spoofing",
                evidence=f"Domain: {self.domain}",
            )

        # Check for missing DMARC
        try:
            await self.resolver.resolve(f"_dmarc.{self.domain}", "TXT")
        except Exception:
            await push_finding(
                q,
                severity="MEDIUM",
                module="DNS",
                title="Missing DMARC Record",
                detail="No _dmarc TXT record found — email authentication incomplete",
                evidence=f"Checked: _dmarc.{self.domain}",
            )

        # Check for missing CAA
        if not results.get("CAA"):
            await push_finding(
                q,
                severity="LOW",
                module="DNS",
                title="Missing CAA Records",
                detail="No CAA records restrict which CAs can issue certificates for this domain",
                evidence=f"Domain: {self.domain}",
            )

        # Check for private IP exposure
        for rec in results.get("A", []):
            if "PRIVATE_IP" in rec.get("flags", []):
                await push_finding(
                    q,
                    severity="HIGH",
                    module="DNS",
                    title="Private IP Address in DNS",
                    detail="A record resolves to a private/internal IP address",
                    evidence=f"{self.domain} → {rec['value']}",
                )

        # Check for wildcard DNS
        try:
            import secrets

            wild_test = f"{secrets.token_hex(12)}.{self.domain}"
            await self.resolver.resolve(wild_test, "A")
            await push_finding(
                q,
                severity="INFO",
                module="DNS",
                title="Wildcard DNS Detected",
                detail="Domain resolves arbitrary subdomains — may mask subdomain enumeration",
                evidence=f"Tested: {wild_test}",
            )
        except Exception:
            pass  # Expected — no wildcard

        # Low TTL warning
        for rtype, recs in results.items():
            if rtype == "AXFR":
                continue
            for rec in recs:
                if "LOW_TTL" in rec.get("flags", []):
                    await push_finding(
                        q,
                        severity="INFO",
                        module="DNS",
                        title="Suspiciously Low TTL",
                        detail=f"{rtype} record has TTL < 60s — possible fast-flux or CDN",
                        evidence=f"{rec['value']} TTL={rec.get('ttl', 'N/A')}",
                    )
                    break  # One finding per type is enough

    @staticmethod
    def _record_to_dict(rec: DNSRecord) -> dict[str, Any]:
        return asdict(rec)
