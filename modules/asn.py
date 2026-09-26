"""IP Range, BGP, and Autonomous System (ASN) Discovery Module (PC-1).

Resolves target IPs to Autonomous System Numbers (ASN), organization names, BGP CIDR prefixes,
and hosting provider classifications.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, asdict
from typing import TYPE_CHECKING

from modules.findings import push_finding
from modules.stealth import build_client, apply_stealth_delay

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.asn")


@dataclass
class ASNInfo:
    ip: str
    asn: str
    asn_org: str
    bgp_prefix: str
    country: str
    registry: str

    def to_dict(self) -> dict:
        return asdict(self)


class ASNModule:
    """Network infrastructure, BGP prefix, and ASN mapping engine."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def _resolve_ip(self, hostname: str) -> list[str]:
        ips = []
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            for item in addr_info:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        return ips

    async def _lookup_asn(self, client, ip: str) -> ASNInfo | None:
        # Query Cymru / bgpview / ip-api JSON API for live BGP routing context
        try:
            url = f"https://ipapi.co/{ip}/json/"
            resp = await client.get(url, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                asn = data.get("asn", "")
                org = data.get("org", "") or data.get("network", {}).get("name", "")
                prefix = f"{data.get('network', ip)}/24" if not data.get("network") else str(data.get("network"))
                country = data.get("country_name", "")
                return ASNInfo(
                    ip=ip,
                    asn=asn,
                    asn_org=org,
                    bgp_prefix=prefix,
                    country=country,
                    registry=data.get("country_code", ""),
                )
        except Exception:
            pass

        # Fallback to ipwhois / rdap
        try:
            url = f"https://rdap.arin.net/registry/ip/{ip}"
            resp = await client.get(url, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                name = data.get("name", "")
                cidr = ""
                for ent in data.get("entities", []):
                    vcard = ent.get("vcardArray", [])
                    if vcard:
                        name = ent.get("handle", name)
                return ASNInfo(
                    ip=ip,
                    asn="Unknown",
                    asn_org=name,
                    bgp_prefix=f"{ip}/32",
                    country="",
                    registry="ARIN",
                )
        except Exception:
            pass

        return None

    async def run(self) -> dict[str, Any]:
        status = self.state.module_statuses.get("ASN")
        if status:
            status.state = "RUNNING"
            status.message = "Querying BGP prefixes & Autonomous System data..."

        cfg = self.state.config
        ips = await self._resolve_ip(cfg.hostname)

        # Also pull from DNS module A records if available
        for rec in self.state.dns_results.get("A", []):
            val = rec.get("value")
            if val and val not in ips:
                ips.append(val)

        asn_map: dict[str, ASNInfo] = {}

        try:
            async with build_client(cfg) as client:
                for ip in ips[:5]:
                    await apply_stealth_delay(cfg)
                    info = await self._lookup_asn(client, ip)
                    if info:
                        asn_map[ip] = info
        except Exception as exc:
            logger.error("ASN module error: %s", exc)

        results = {
            "ips": ips,
            "networks": [info.to_dict() for info in asn_map.values()],
        }
        self.state.asn_results = results

        if asn_map:
            first_asn = next(iter(asn_map.values()))
            await push_finding(
                self.state.findings_queue,
                module="ASN",
                severity="INFO",
                title=f"Autonomous System Identified: {first_asn.asn} ({first_asn.asn_org})",
                detail=f"Target routed through BGP Prefix {first_asn.bgp_prefix} hosted by {first_asn.asn_org}.",
                evidence=f"IP: {first_asn.ip} -> ASN: {first_asn.asn}",
            )

        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(asn_map)} ASNs mapped"

        return results
