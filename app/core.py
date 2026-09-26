"""ReconWireApp — Retro cyberpunk terminal reconnaissance interface.

No CSS files. Pure terminal rendering matching the httpcrabber aesthetic.
Renders live intercept stream, metadata, status indicators, and outputs full formatted results to terminal.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.box import ROUNDED
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.export import export_json, export_markdown, export_sarif, export_text
from app.state import AppState, ScanConfig
from modules.asn import ASNModule
from modules.cloud import CloudModule
from modules.csp import CSPModule
from modules.dns import DNSModule
from modules.endpoints import EndpointModule
from modules.findings import FindingsAggregator
from modules.fuzz import FuzzModule
from modules.harvest import HarvestModule
from modules.header import HeaderModule
from modules.params import ParamModule
from modules.ports import PortModule
from modules.subdomain import SubdomainModule
from modules.takeover import TakeoverModule
from modules.tech import TechModule
from modules.tls import TLSModule
from modules.vhost import VHostModule
from modules.waf import WAFModule
from modules.whois import WHOISModule
from ui.banner import get_banner_renderable

logger = logging.getLogger("recon_wire")

# Configure file logging
_log_handler = logging.FileHandler("recon_wire.log", mode="w", encoding="utf-8")
_log_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s  %(name)-30s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
logging.getLogger("recon_wire").addHandler(_log_handler)
logging.getLogger("recon_wire").setLevel(logging.DEBUG)


class ReconWireApp:
    """Cyberpunk live terminal UI for RECON-WIRE. No CSS or bloated widgets."""

    def __init__(self, config: ScanConfig) -> None:
        self.scan_config = config
        if sys.platform == "win32":
            try:
                import ctypes

                ctypes.windll.kernel32.SetConsoleOutputCP(65001)
                ctypes.windll.kernel32.SetConsoleCP(65001)
            except Exception:
                pass
        if hasattr(sys.stdout, "reconfigure"):
            with contextlib.suppress(Exception):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            with contextlib.suppress(Exception):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")

        self.state = AppState(config=config)
        self.console = Console(force_terminal=True, highlight=False)
        self.events: list[dict[str, str]] = []
        self._seen_event_keys: set[str] = set()
        self._sparkline_frames = [" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        self._sparkline_history: list[int] = [1, 2, 4, 3, 5, 2, 6, 7, 4, 6, 8, 9]
        self._stop_requested = False
        self._req_count = 0
        self._resp_count = 0

        # Seed initial connection event
        self._add_event(
            method="PROBE",
            code="INIT",
            detail=f"Target: {self.scan_config.url}",
        )

    def _add_event(self, method: str, code: str, detail: str) -> None:
        """Add an intercept event to the live display stream."""
        now_str = datetime.now().strftime("%H:%M:%S")
        event = {
            "time": now_str,
            "method": method,
            "code": str(code),
            "detail": detail,
        }
        self.events.append(event)
        # Keep recent 12 events
        if len(self.events) > 12:
            self.events = self.events[-12:]
        self._sparkline_history.append(min(7, len(self.events) % 8 + 1))
        if len(self._sparkline_history) > 12:
            self._sparkline_history = self._sparkline_history[-12:]

    def _format_method(self, method: str) -> str:
        """Format method badge with retro hacker colors."""
        m = method.upper()
        if m in ("GET", "DNS"):
            return f"[bold #00e5ff]{m:<7}[/bold #00e5ff]"
        elif m in ("POST", "FIND", "FINDING"):
            return f"[bold #ff007f]{m:<7}[/bold #ff007f]"
        elif m in ("OPTIONS", "SUB", "SUBDOMAIN"):
            return f"[bold #ffff00]{m:<7}[/bold #ffff00]"
        elif m in ("TECH", "TLS", "PORT", "PORTS"):
            return f"[bold #bc8cff]{m:<7}[/bold #bc8cff]"
        elif m in ("WHOIS", "PROBE", "CLOUD", "ASN"):
            return f"[bold #39d353]{m:<7}[/bold #39d353]"
        elif m in ("FUZZ", "EP", "CRAWL", "WAF"):
            return f"[bold #ff9f43]{m:<7}[/bold #ff9f43]"
        elif m in ("TAKEOVER", "HARVEST", "SECRET"):
            return f"[bold #ff0055]{m:<7}[/bold #ff0055]"
        elif m in ("PARAM", "PARAMS", "CSP", "VHOST"):
            return f"[bold #00e5ff]{m:<7}[/bold #00e5ff]"
        return f"[bold #e6edf3]{m:<7}[/bold #e6edf3]"

    def _format_code(self, code: str) -> str:
        """Format status or response code with authentic terminal colors."""
        c = code.upper()
        if c in ("200", "204", "OK", "FOUND"):
            return f"[bold #00ff66]{c:<4}[/bold #00ff66]"
        elif c in ("301", "302", "307", "308"):
            return f"[bold #ffff00]{c:<4}[/bold #ffff00]"
        elif c in ("400", "401", "403"):
            return f"[bold #ffb703]{c:<4}[/bold #ffb703]"
        elif c in ("404", "NONE"):
            return f"[dim #8b949e]{c:<4}[/dim #8b949e]"
        elif c in ("500", "502", "503", "CRIT", "HIGH", "ERR"):
            return f"[bold #ff4444]{c:<4}[/bold #ff4444]"
        elif c in ("A", "AAAA", "MX", "TXT", "NS", "SOA"):
            return f"[bold #00e5ff]{c:<4}[/bold #00e5ff]"
        return f"[bold #e6edf3]{c:<4}[/bold #e6edf3]"

    def render(self) -> Panel:
        """Build a distinctive RECON-WIRE cyber-reconnaissance operations dashboard."""
        cfg = self.scan_config
        elapsed = int(self.state.elapsed)
        mins, secs = divmod(elapsed, 60)
        elapsed_str = f"{mins:02d}:{secs:02d}"

        # ── Header bar with pulse indicator ──
        pulse = "◈" if (int(time.time() * 2) % 2 == 0) else "◇"
        status_text = (
            "[bold #00ffcc]SYSTEM SCANNING[/bold #00ffcc]"
            if not self.state.scan_complete
            else "[bold #39d353]ALL VECTORS COMPLETE[/bold #39d353]"
        )
        header_text = Text.from_markup(
            f"[bold #00e5ff]RECON-WIRE[/bold #00e5ff] [bold #ff79c6]v1.0[/bold #ff79c6] │ {status_text} [bold #00ffcc]{pulse}[/bold #00ffcc] │ [bold #ffffff]{elapsed_str}[/bold #ffffff]"
        )

        # ── Target Overview & Recon HUD ──
        dns_count = sum(len(v) for v in self.state.dns_results.values() if isinstance(v, list))
        subs_count = len(self.state.subdomain_results)
        findings_count = len(self.state.findings)
        len(self.state.tech_results)
        ports_count = len(self.state.port_results)
        ep_count = len(self.state.endpoint_results)
        len(self.state.fuzz_results)
        req_count = max(self._req_count, subs_count * 2 + ports_count + ep_count + 10)

        overview = Table.grid(expand=True)
        overview.add_column(width=14)
        overview.add_column(ratio=2)
        overview.add_column(width=14)
        overview.add_column(ratio=1)

        stealth_info = f"{cfg.delay}s (+{cfg.jitter}s)" if (cfg.delay > 0 or cfg.jitter > 0) else "None (Max Speed)"

        overview.add_row(
            "[#8b949e]Target URL:[/#8b949e]",
            f"[bold #00e5ff]{cfg.url}[/bold #00e5ff]",
            "[#8b949e]Concurrency:[/#8b949e]",
            f"[bold #ff79c6]{cfg.max_concurrent} workers[/bold #ff79c6]",
        )
        overview.add_row(
            "[#8b949e]Apex Domain:[/#8b949e]",
            f"[bold #39d353]{cfg.domain}[/bold #39d353] [#8b949e]({cfg.scheme}://:{cfg.port})[/#8b949e]",
            "[#8b949e]Stealth Delay:[/#8b949e]",
            f"[#e6edf3]{stealth_info}[/#e6edf3]",
        )

        overview_panel = Panel(
            overview,
            title="[bold #58a6ff]▣ MISSION PARAMETERS[/bold #58a6ff]",
            title_align="left",
            border_style="#30363d",
            box=ROUNDED,
        )

        # ── Live Telemetry Feed (distinctive cyber table) ──
        stream = Table(expand=True, box=ROUNDED, border_style="#30363d", show_header=True, header_style="bold #58a6ff")
        stream.add_column("MARK", width=4, justify="center")
        stream.add_column("TIME", width=10, style="#8b949e")
        stream.add_column("VECTOR", width=10)
        stream.add_column("CODE", width=8)
        stream.add_column("SIGNAL / DISCOVERY", ratio=1)

        total_ev = len(self.events)
        for i, ev in enumerate(self.events):
            is_latest = (i == total_ev - 1) and not self.state.scan_complete
            marker = "[bold #00ffcc]▶[/bold #00ffcc]" if is_latest else "[#484f58]·[/#484f58]"
            method_badge = self._format_method(ev["method"])
            code_badge = self._format_code(ev["code"])
            detail_str = escape(ev["detail"])
            stream.add_row(marker, ev["time"], method_badge, code_badge, detail_str)

        for _ in range(max(0, 8 - len(self.events))):
            stream.add_row("", "", "", "", "")

        # ── Signal Metrics & Telemetry Bar ──
        sparkline = "".join(
            self._sparkline_frames[val % len(self._sparkline_frames)] for val in self._sparkline_history
        )

        metrics_grid = Table.grid(expand=True)
        metrics_grid.add_column(ratio=1)
        metrics_grid.add_column(width=28, justify="right")

        metrics_left = (
            f"[bold #00e5ff]◈ REQ[/bold #00e5ff] [#e6edf3]{req_count:<4}[/#e6edf3] "
            f"[bold #39d353]◈ DNS[/bold #39d353] [#e6edf3]{dns_count:<4}[/#e6edf3] "
            f"[bold #ffff00]◈ SUBS[/bold #ffff00] [#e6edf3]{subs_count:<4}[/#e6edf3] "
            f"[bold #bc8cff]◈ PORTS[/bold #bc8cff] [#e6edf3]{ports_count:<3}[/#e6edf3] "
            f"[bold #ff9f43]◈ ENDP[/bold #ff9f43] [#e6edf3]{ep_count:<4}[/#e6edf3] "
            f"[bold #ff4444]◈ VULNS[/bold #ff4444] [#ff4444]{findings_count:<3}[/#ff4444]"
        )
        metrics_right = f"[#8b949e]ACTIVITY:[/#8b949e] [bold #00ffcc]{sparkline}[/bold #00ffcc]"
        metrics_grid.add_row(metrics_left, metrics_right)

        metrics_panel = Panel(
            metrics_grid,
            border_style="#30363d",
            box=ROUNDED,
            style="on #0d1117",
        )

        footer_text = Text(
            "Press 'q' or Ctrl+C to halt stream & display detailed report in terminal",
            style="#8b949e",
            justify="center",
        )

        content = Group(
            overview_panel,
            stream,
            metrics_panel,
            footer_text,
        )

        return Panel(
            content,
            title=header_text,
            title_align="center",
            border_style="#58a6ff",
            box=ROUNDED,
        )

    async def _event_collector(self) -> None:
        """Poll AppState to generate live intercept stream events in real time."""
        processed_subs = 0
        processed_findings = 0
        processed_tech = 0
        processed_ports = 0
        processed_ep = 0
        processed_fuzz = 0
        processed_cloud = 0
        processed_takeover = 0
        processed_waf = 0
        processed_harvest_secrets = 0
        processed_params = 0
        processed_vhost = 0
        processed_dns: set[str] = set()
        seen_asn = False
        seen_csp = False

        while not self._stop_requested:
            # Check DNS
            for rtype, records in list(self.state.dns_results.items()):
                if isinstance(records, list):
                    for rec in records:
                        val = str(rec.get("value", ""))[:70]
                        key = f"dns_{rtype}_{val}"
                        if key not in processed_dns:
                            processed_dns.add(key)
                            self._add_event(method="DNS", code=rtype, detail=f"{self.scan_config.hostname} -> {val}")
                            self._resp_count += 1

            # Check Subdomains
            sub_results = self.state.subdomain_results
            while processed_subs < len(sub_results):
                sub = sub_results[processed_subs]
                processed_subs += 1
                status = str(sub.status_code) if sub.status_code else ("200" if sub.is_live else "404")
                self._add_event(
                    method="GET", code=status, detail=f"{sub.subdomain} [{'live' if sub.is_live else 'down'}]"
                )
                self._req_count += 1
                self._resp_count += 1

            # Check Tech detections
            tech_results = self.state.tech_results
            while processed_tech < len(tech_results):
                t = tech_results[processed_tech]
                processed_tech += 1
                name = getattr(t, "name", t.get("name") if isinstance(t, dict) else str(t))
                ver = (
                    getattr(t, "version", t.get("version", "")) if isinstance(t, dict) or hasattr(t, "version") else ""
                )
                self._add_event(method="TECH", code="FOUND", detail=f"{name} {ver}".strip())
                self._resp_count += 1

            # Check Findings
            findings = self.state.findings
            while processed_findings < len(findings):
                f = findings[processed_findings]
                processed_findings += 1
                sev = getattr(f, "severity", "INFO")
                title = getattr(f, "title", str(f))[:75]
                self._add_event(method="FINDING", code=sev[:4], detail=title)

            # Check Header final status
            hdr_status = self.state.header_results.get("final_status")
            if hdr_status and "hdr_reported" not in self._seen_event_keys:
                self._seen_event_keys.add("hdr_reported")
                self._add_event(method="GET", code=str(hdr_status), detail=f"{self.scan_config.hostname}/")
                self._req_count += 1
                self._resp_count += 1

            # Check TLS
            tls_res = self.state.tls_results.get("leaf_cert")
            if tls_res and "tls_reported" not in self._seen_event_keys:
                self._seen_event_keys.add("tls_reported")
                cn = tls_res.get("subject_cn", "unknown")
                self._add_event(method="TLS", code="200", detail=f"CN: {cn}")

            # Check Ports
            while processed_ports < len(self.state.port_results):
                p = self.state.port_results[processed_ports]
                processed_ports += 1
                self._add_event(
                    method="PORT", code=str(p.port), detail=f"{p.service} open on {self.scan_config.hostname}"
                )
                self._req_count += 1
                self._resp_count += 1

            # Check Endpoints
            while processed_ep < len(self.state.endpoint_results):
                ep = self.state.endpoint_results[processed_ep]
                processed_ep += 1
                self._add_event(method="EP", code=ep.category[:4], detail=ep.path)
                self._resp_count += 1

            # Check Fuzzing hits
            while processed_fuzz < len(self.state.fuzz_results):
                fz = self.state.fuzz_results[processed_fuzz]
                processed_fuzz += 1
                self._add_event(method="FUZZ", code=str(fz.status_code), detail=f"{fz.path} ({fz.content_length}B)")
                self._req_count += 1
                self._resp_count += 1

            # Check Cloud buckets
            while processed_cloud < len(self.state.cloud_results):
                cb = self.state.cloud_results[processed_cloud]
                processed_cloud += 1
                self._add_event(method="CLOUD", code=cb.status[:4], detail=f"[{cb.provider}] {cb.bucket_name}")
                self._resp_count += 1

            # Check Subdomain Takeover vectors
            while processed_takeover < len(self.state.takeover_results):
                tk = self.state.takeover_results[processed_takeover]
                processed_takeover += 1
                self._add_event(method="TAKEOVER", code=tk.status[:4], detail=f"{tk.subdomain} -> {tk.service}")
                self._resp_count += 1

            # Check WAF detections
            while processed_waf < len(self.state.waf_results):
                w = self.state.waf_results[processed_waf]
                processed_waf += 1
                self._add_event(
                    method="WAF",
                    code="BLOCK" if "Probe" in w.matched_vector else "DETECT",
                    detail=f"{w.name} ({w.confidence})",
                )
                self._resp_count += 1

            # Check Harvested Secrets
            secrets_list = self.state.harvest_results.get("secrets", [])
            while processed_harvest_secrets < len(secrets_list):
                sec = secrets_list[processed_harvest_secrets]
                processed_harvest_secrets += 1
                self._add_event(method="HARVEST", code="LEAK", detail=f"{sec.get('type')}: {sec.get('masked')}")
                self._resp_count += 1

            # Check ASN
            if not seen_asn and self.state.asn_results.get("networks"):
                seen_asn = True
                first_net = self.state.asn_results["networks"][0]
                self._add_event(
                    method="ASN",
                    code=str(first_net.get("asn", "BGP"))[:4],
                    detail=f"{first_net.get('asn_org', '')} [{first_net.get('bgp_prefix', '')}]",
                )
                self._resp_count += 1

            # Check Parameters (PD-1)
            while processed_params < len(self.state.param_results):
                pr = self.state.param_results[processed_params]
                processed_params += 1
                self._add_event(method="PARAM", code=pr.anomaly_type[:4], detail=f"{pr.param} ({pr.anomaly_type})")
                self._resp_count += 1

            # Check CSP (PD-2)
            if not seen_csp and self.state.csp_results:
                seen_csp = True
                csp_item = self.state.csp_results[0]
                self._add_event(
                    method="CSP",
                    code=f"GRD_{csp_item.grade}",
                    detail=f"Score: {csp_item.score}/100 | Flaws: {len(csp_item.flaws)}",
                )
                self._resp_count += 1

            # Check Virtual Hosts (PC-2)
            while processed_vhost < len(self.state.vhost_results):
                vh = self.state.vhost_results[processed_vhost]
                processed_vhost += 1
                self._add_event(method="VHOST", code=str(vh.status_code), detail=f"{vh.host} ({vh.diff_type})")
                self._resp_count += 1

            await asyncio.sleep(0.1)

    async def _run_modules_async(self) -> None:
        """Run all active recon modules concurrently with task management."""
        cfg = self.state.config
        tasks = []
        names = []

        # Core baseline reconnaissance
        tasks.append(DNSModule(self.state).run())
        names.append("DNS")

        tasks.append(SubdomainModule(self.state).run())
        names.append("SUBDOMAINS")

        tasks.append(HeaderModule(self.state).run())
        names.append("HEADERS")

        tasks.append(TechModule(self.state).run())
        names.append("TECH")

        tasks.append(WHOISModule(self.state).run())
        names.append("WHOIS")

        tasks.append(TLSModule(self.state).run())
        names.append("TLS")

        # New Vector Modules
        if cfg.scan_ports:
            tasks.append(PortModule(self.state).run())
            names.append("PORTS")

        if cfg.scan_endpoints:
            tasks.append(EndpointModule(self.state).run())
            names.append("ENDPOINTS")

        if cfg.scan_fuzz:
            tasks.append(FuzzModule(self.state).run())
            names.append("FUZZ")

        if cfg.scan_cloud:
            tasks.append(CloudModule(self.state).run())
            names.append("CLOUD")

        if cfg.scan_takeover:
            tasks.append(TakeoverModule(self.state).run())
            names.append("TAKEOVER")

        if cfg.scan_harvest:
            tasks.append(HarvestModule(self.state).run())
            names.append("HARVEST")

        if cfg.scan_waf:
            tasks.append(WAFModule(self.state).run())
            names.append("WAF")

        if cfg.scan_asn:
            tasks.append(ASNModule(self.state).run())
            names.append("ASN")

        if cfg.scan_params:
            tasks.append(ParamModule(self.state).run())
            names.append("PARAMS")

        if cfg.scan_csp:
            tasks.append(CSPModule(self.state).run())
            names.append("CSP")

        if cfg.scan_vhost:
            tasks.append(VHostModule(self.state).run())
            names.append("VHOST")

        aggregator = FindingsAggregator(self.state)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for name, res in zip(names, results, strict=False):
            if isinstance(res, Exception):
                logger.error("Module %s raised: %s", name, res, exc_info=res)

        self.state.scan_complete = True
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(aggregator.consume(), timeout=3.0)

    async def _keyboard_listener(self) -> None:
        """Non-blocking keyboard listener for 'q' or Ctrl+C on Windows."""
        if sys.platform == "win32":
            try:
                import msvcrt

                while not self._stop_requested:
                    if msvcrt.kbhit():
                        char = msvcrt.getch()
                        # Consume extended key follow-up byte (arrows, function keys)
                        if char in (b"\x00", b"\xe0") and msvcrt.kbhit():
                            msvcrt.getch()
                        elif char in (b"q", b"Q", b"\x03", b"\x1b"):
                            self._stop_requested = True
                            break
                    await asyncio.sleep(0.1)
            except Exception:
                pass

    async def _main_loop(self) -> None:
        """Main async loop running Live UI and modules."""
        collector_task = asyncio.create_task(self._event_collector())
        modules_task = asyncio.create_task(self._run_modules_async())
        keyboard_task = asyncio.create_task(self._keyboard_listener())

        with Live(self.render(), console=self.console, refresh_per_second=8, screen=False) as live:
            while not self._stop_requested:
                live.update(self.render())
                if self.state.scan_complete:
                    await asyncio.sleep(0.5)
                    break
                await asyncio.sleep(0.125)

        self._stop_requested = True
        collector_task.cancel()
        keyboard_task.cancel()
        if not modules_task.done():
            modules_task.cancel()

        # Display full detailed reconnaissance output directly in terminal
        self._print_terminal_report()

        # Save session exports
        self._export_results()

    def _print_terminal_report(self) -> None:
        """Print full, comprehensive reconnaissance results directly into the terminal."""
        c = self.console
        cfg = self.scan_config
        c.print(f"\n[bold #00ff66]RECONNAISSANCE SCAN RESULTS — {cfg.hostname}[/bold #00ff66]\n")

        # ── 1. Target Summary ──
        a_records = self.state.dns_results.get("A", [])
        ips = [r.get("value", "") for r in a_records[:3] if r.get("value")]
        ip_str = ", ".join(ips) if ips else "Unknown"
        final_status = self.state.header_results.get("final_status", 200)

        summary_table = Table(show_header=False, box=ROUNDED, border_style="#30363d", expand=True)
        summary_table.add_column("Field", style="bold #8b949e", width=16)
        summary_table.add_column("Value", style="bold #e6edf3")
        summary_table.add_row("Target URL", f"[bold #00e5ff]{cfg.url}[/bold #00e5ff]")
        summary_table.add_row("Apex Domain", f"[#58a6ff]{cfg.domain}[/#58a6ff]")
        summary_table.add_row("Resolved IP(s)", f"[#3fb950]{ip_str}[/#3fb950]")
        summary_table.add_row("HTTP Status", f"[bold #00ff66]{final_status}[/bold #00ff66]")
        summary_table.add_row("Duration", f"[bold #ffffff]{self.state.elapsed:.2f}s[/bold #ffffff]")
        c.print(summary_table)

        # ── 2. DNS Enumeration ──
        dns_res = self.state.dns_results
        if dns_res:
            c.print("\n[bold #00e5ff]DNS RECORDS[/bold #00e5ff]")
            dns_table = Table(show_header=True, header_style="bold #00e5ff", border_style="#30363d", expand=True)
            dns_table.add_column("TYPE", width=8, style="bold #e6edf3")
            dns_table.add_column("VALUE", ratio=3)
            dns_table.add_column("TTL", width=8, justify="right", style="#8b949e")
            dns_table.add_column("GEO / ISP", ratio=2, style="#8b949e")

            for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
                records = dns_res.get(rtype, [])
                for r in records:
                    val = str(r.get("value", ""))[:75]
                    ttl = str(r.get("ttl", ""))
                    geo = r.get("geo")
                    geo_str = f"{geo.get('city', '')}, {geo.get('country', '')}" if isinstance(geo, dict) else ""
                    dns_table.add_row(rtype, escape(val), ttl, escape(geo_str))
            c.print(dns_table)

        # ── 3. Subdomains ──
        subs = self.state.subdomain_results
        if subs:
            c.print(f"\n[bold #58a6ff]DISCOVERED SUBDOMAINS ({len(subs)})[/bold #58a6ff]")
            sub_table = Table(show_header=True, header_style="bold #58a6ff", border_style="#30363d", expand=True)
            sub_table.add_column("SUBDOMAIN", ratio=2, style="bold #e6edf3")
            sub_table.add_column("IP", width=16, style="#3fb950")
            sub_table.add_column("STATUS", width=8, justify="center")
            sub_table.add_column("SERVER", width=18, style="#8b949e")
            sub_table.add_column("TITLE", ratio=2, style="#8b949e")

            for s in subs[:30]:
                code = str(s.status_code) if s.status_code else ("200" if s.is_live else "—")
                code_colored = f"[bold #00ff66]{code}[/bold #00ff66]" if code == "200" else f"[#ffb703]{code}[/#ffb703]"
                sub_table.add_row(
                    escape(s.subdomain),
                    escape(s.ip or "—"),
                    code_colored,
                    escape(s.server or "—")[:18],
                    escape(s.title or "—")[:40],
                )
            c.print(sub_table)
            if len(subs) > 30:
                c.print(f"  [dim]... and {len(subs) - 30} more subdomains[/dim]")

        # ── 4. Tech Stack ──
        techs = self.state.tech_results
        if techs:
            c.print(f"\n[bold #bc8cff]DETECTED TECHNOLOGIES ({len(techs)})[/bold #bc8cff]")
            tech_table = Table(show_header=True, header_style="bold #bc8cff", border_style="#30363d", expand=True)
            tech_table.add_column("TECHNOLOGY", ratio=2, style="bold #e6edf3")
            tech_table.add_column("VERSION", width=15, style="#3fb950")
            tech_table.add_column("CONFIDENCE", width=12, justify="center")
            tech_table.add_column("CATEGORY", ratio=2, style="#8b949e")

            for t in techs:
                if isinstance(t, dict):
                    name = t.get("name", str(t))
                    ver = t.get("version") or "—"
                    conf = t.get("confidence", "HIGH")
                    cat = t.get("category", "General")
                else:
                    name = getattr(t, "name", str(t))
                    ver = getattr(t, "version", None) or "—"
                    conf = getattr(t, "confidence", "HIGH")
                    cat = getattr(t, "category", "General")
                conf_color = "green" if conf == "HIGH" else "yellow"
                tech_table.add_row(
                    escape(str(name)), escape(str(ver)), f"[{conf_color}]{conf}[/{conf_color}]", escape(str(cat))
                )
            c.print(tech_table)

        # ── 5. Security Headers ──
        hdr_res = self.state.header_results
        if hdr_res:
            score = hdr_res.get("score")
            grade = hdr_res.get("grade")
            if score is not None:
                grade_color = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}.get(
                    grade, "white"
                )
                bar_filled = int(score / 100 * 30)
                score_bar = "█" * bar_filled + "░" * (30 - bar_filled)
                c.print("\n[bold #00ff66]HTTP SECURITY HEADERS[/bold #00ff66]")
                c.print(f"  Score: [{grade_color}][{score_bar}] {score}/100  Grade: {grade}[/{grade_color}]")

            audit = hdr_res.get("security_audit", [])
            if audit:
                audit_table = Table(show_header=True, header_style="bold #00ff66", border_style="#30363d", expand=True)
                audit_table.add_column("STATUS", width=8, justify="center")
                audit_table.add_column("HEADER", width=30, style="bold #e6edf3")
                audit_table.add_column("VALUE / ISSUES", ratio=2, style="#8b949e")

                for entry in audit:
                    status_badge = (
                        "[bold #00ff66]✓ PASS[/bold #00ff66]"
                        if entry["present"] and not entry["issues"]
                        else "[bold #ff4444]✗ MISSING[/bold #ff4444]"
                    )
                    issues = "; ".join(entry.get("issues", [])) or (entry.get("value") or "—")
                    audit_table.add_row(status_badge, escape(entry["header"]), escape(issues[:80]))
                c.print(audit_table)

        # ── 6. TLS Certificate ──
        tls_res = self.state.tls_results.get("leaf_cert")
        if tls_res and not tls_res.get("error"):
            c.print("\n[bold #39d353]TLS / SSL CERTIFICATE[/bold #39d353]")
            tls_table = Table(show_header=False, box=ROUNDED, border_style="#30363d", expand=True)
            tls_table.add_column("Property", style="bold #8b949e", width=18)
            tls_table.add_column("Value", style="#e6edf3")
            tls_table.add_row("Subject CN", escape(str(tls_res.get("subject_cn", "N/A"))))
            tls_table.add_row("Issuer CN", escape(str(tls_res.get("issuer_cn", "N/A"))))
            tls_table.add_row(
                "Days Remaining", f"[bold #00ff66]{tls_res.get('days_remaining', 'N/A')} days[/bold #00ff66]"
            )
            tls_table.add_row("Key Type & Size", f"{tls_res.get('key_type', '')} {tls_res.get('key_size', '')} bits")
            c.print(tls_table)

        # ── 7. Open Ports & Services ──
        if self.state.port_results:
            c.print(f"\n[bold #bc8cff]OPEN PORTS & SERVICES ({len(self.state.port_results)})[/bold #bc8cff]")
            port_table = Table(show_header=True, header_style="bold #bc8cff", border_style="#30363d", expand=True)
            port_table.add_column("PORT", width=8, style="bold #e6edf3")
            port_table.add_column("SERVICE", width=16, style="#3fb950")
            port_table.add_column("BANNER / DETECTED SERVICE", ratio=2, style="#8b949e")
            for p in self.state.port_results:
                port_table.add_row(str(p.port), p.service, escape(p.banner or "—"))
            c.print(port_table)

        # ── 8. Discovered Endpoints ──
        if self.state.endpoint_results:
            c.print(f"\n[bold #ff9f43]DISCOVERED ENDPOINTS ({len(self.state.endpoint_results)})[/bold #ff9f43]")
            ep_table = Table(show_header=True, header_style="bold #ff9f43", border_style="#30363d", expand=True)
            ep_table.add_column("CATEGORY", width=12, style="bold #e6edf3")
            ep_table.add_column("METHOD", width=8, justify="center")
            ep_table.add_column("PATH / URL", ratio=3, style="#58a6ff")
            for ep in self.state.endpoint_results[:25]:
                ep_table.add_row(ep.category, ep.method, escape(ep.path))
            c.print(ep_table)
            if len(self.state.endpoint_results) > 25:
                c.print(f"  [dim]... and {len(self.state.endpoint_results) - 25} more endpoints[/dim]")

        # ── 9. Sensitive Files & Fuzzing Hits ──
        if self.state.fuzz_results:
            c.print(f"\n[bold #ff6b6b]EXPOSED FILES & DIRECTORIES ({len(self.state.fuzz_results)})[/bold #ff6b6b]")
            fuzz_table = Table(show_header=True, header_style="bold #ff6b6b", border_style="#30363d", expand=True)
            fuzz_table.add_column("STATUS", width=8, justify="center")
            fuzz_table.add_column("PATH", ratio=2, style="bold #e6edf3")
            fuzz_table.add_column("SIZE", width=14, justify="right", style="#8b949e")
            fuzz_table.add_column("CONTENT TYPE", width=20, style="#8b949e")
            for f in self.state.fuzz_results:
                color = "green" if f.status_code == 200 else "yellow"
                fuzz_table.add_row(
                    f"[{color}]{f.status_code}[/{color}]",
                    escape(f.path),
                    f"{f.content_length} B",
                    escape(f.content_type[:20]),
                )
            c.print(fuzz_table)

        # ── 10. Cloud Buckets ──
        if self.state.cloud_results:
            c.print(f"\n[bold #39d353]PUBLIC CLOUD BUCKETS ({len(self.state.cloud_results)})[/bold #39d353]")
            cloud_table = Table(show_header=True, header_style="bold #39d353", border_style="#30363d", expand=True)
            cloud_table.add_column("PROVIDER", width=12, style="bold #e6edf3")
            cloud_table.add_column("BUCKET NAME", ratio=2, style="#58a6ff")
            cloud_table.add_column("STATUS", width=14, justify="center")
            cloud_table.add_column("URL", ratio=2, style="#8b949e")
            for cb in self.state.cloud_results:
                stat_badge = (
                    "[bold #ff4444]OPEN[/bold #ff4444]" if cb.status == "OPEN" else "[#8b949e]PROTECTED[/#8b949e]"
                )
                cloud_table.add_row(cb.provider, escape(cb.bucket_name), stat_badge, escape(cb.url))
            c.print(cloud_table)

        # ── 11. WAF Fingerprint ──
        if self.state.waf_results:
            c.print(f"\n[bold #00e5ff]WEB APPLICATION FIREWALL (WAF) ({len(self.state.waf_results)})[/bold #00e5ff]")
            waf_table = Table(show_header=True, header_style="bold #00e5ff", border_style="#30363d", expand=True)
            waf_table.add_column("FIREWALL / VENDOR", width=22, style="bold #e6edf3")
            waf_table.add_column("CONFIDENCE", width=12, justify="center")
            waf_table.add_column("VECTOR", width=18, style="#58a6ff")
            waf_table.add_column("DETAILS / SIGNATURE", ratio=2, style="#8b949e")
            for w in self.state.waf_results:
                conf_color = (
                    "bold #ff4444"
                    if w.confidence == "DEFINITIVE"
                    else ("#ffb703" if w.confidence == "HIGH" else "#00e5ff")
                )
                waf_table.add_row(
                    f"{w.name} ({w.vendor})",
                    f"[{conf_color}]{w.confidence}[/{conf_color}]",
                    escape(w.matched_vector),
                    escape(w.details[:75]),
                )
            c.print(waf_table)

        # ── 12. Autonomous System & BGP (ASN) ──
        asn_nets = self.state.asn_results.get("networks", [])
        if asn_nets:
            c.print(f"\n[bold #58a6ff]AUTONOMOUS SYSTEM & IP ROUTING ({len(asn_nets)})[/bold #58a6ff]")
            asn_table = Table(show_header=True, header_style="bold #58a6ff", border_style="#30363d", expand=True)
            asn_table.add_column("IP ADDRESS", width=16, style="bold #3fb950")
            asn_table.add_column("ASN", width=10, style="bold #00e5ff")
            asn_table.add_column("ORGANIZATION", ratio=2, style="#e6edf3")
            asn_table.add_column("BGP PREFIX", width=18, style="#8b949e")
            asn_table.add_column("COUNTRY", width=8, justify="center", style="#8b949e")
            for net in asn_nets:
                raw_asn = str(net.get("asn", "")).removeprefix("AS")
                asn_val = f"AS{raw_asn}" if raw_asn else "—"
                asn_table.add_row(
                    escape(net.get("ip", "—")),
                    asn_val,
                    escape(net.get("asn_org", "—")[:40]),
                    escape(net.get("bgp_prefix", "—")),
                    escape(net.get("country", "—")),
                )
            c.print(asn_table)

        # ── 13. Subdomain Takeover Vectors ──
        if self.state.takeover_results:
            c.print(f"\n[bold #ff4444]SUBDOMAIN TAKEOVER HUNTING ({len(self.state.takeover_results)})[/bold #ff4444]")
            tko_table = Table(show_header=True, header_style="bold #ff4444", border_style="#30363d", expand=True)
            tko_table.add_column("STATUS", width=12, justify="center")
            tko_table.add_column("SUBDOMAIN", ratio=2, style="bold #e6edf3")
            tko_table.add_column("PROVIDER", width=16, style="#ffb703")
            tko_table.add_column("DANGLING CNAME", ratio=2, style="#58a6ff")
            tko_table.add_column("EVIDENCE", ratio=2, style="#8b949e")
            for t in self.state.takeover_results:
                badge = "[bold red on #3a0000] VULNERABLE [/bold red on #3a0000]" if t.vulnerable else "[dim]SAFE[/dim]"
                tko_table.add_row(
                    badge,
                    escape(t.subdomain),
                    escape(t.provider),
                    escape(t.cname),
                    escape(t.verification_evidence[:60]),
                )
            c.print(tko_table)

        # ── 14. Harvested Secrets & Emails ──
        emails = self.state.harvest_results.get("emails", [])
        secrets = self.state.harvest_results.get("secrets", [])
        if emails or secrets:
            c.print("\n[bold #ffb703]HARVESTED CREDENTIALS & EMAILS[/bold #ffb703]")
            if emails:
                c.print(
                    f"  [bold #3fb950]Emails Found ({len(emails)}):[/bold #3fb950] "
                    + ", ".join(f"[bold #e6edf3]{escape(e)}[/bold #e6edf3]" for e in emails[:15])
                )
                if len(emails) > 15:
                    c.print(f"  [dim]... and {len(emails) - 15} more emails[/dim]")
            if secrets:
                sec_table = Table(show_header=True, header_style="bold #ffb703", border_style="#30363d", expand=True)
                sec_table.add_column("SECRET TYPE", width=22, style="bold #ff4444")
                sec_table.add_column("MASKED VALUE", ratio=2, style="#e6edf3")
                sec_table.add_column("ENTROPY", width=10, justify="right", style="#3fb950")
                sec_table.add_column("SOURCE LOCATION", ratio=2, style="#8b949e")
                for s in secrets:
                    sec_table.add_row(
                        escape(s.get("type", "Secret")),
                        escape(s.get("masked", "—")),
                        f"{s.get('entropy', 0.0):.2f}",
                        escape(s.get("url", "—")[:45]),
                    )
                c.print(sec_table)

        # ── 15. Content Security Policy (CSP) ──
        if self.state.csp_results:
            c.print("\n[bold #00ff66]CONTENT SECURITY POLICY (CSP)[/bold #00ff66]")
            for csp_eval in self.state.csp_results:
                grade_col = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}.get(
                    csp_eval.grade, "white"
                )
                c.print(
                    f"  Score: [{grade_col}]{csp_eval.score}/100 (Grade {csp_eval.grade})[/{grade_col}]  Report-Only: {'Yes' if csp_eval.report_only else 'No'}"
                )
                if csp_eval.bypass_vectors:
                    c.print(
                        "  [bold #ff4444]Potential Bypass Vectors:[/bold #ff4444] "
                        + "; ".join(csp_eval.bypass_vectors[:3])
                    )

                if csp_eval.flaws:
                    csp_table = Table(
                        show_header=True, header_style="bold #00ff66", border_style="#30363d", expand=True
                    )
                    csp_table.add_column("SEV", width=10)
                    csp_table.add_column("DIRECTIVE", width=20, style="bold #e6edf3")
                    csp_table.add_column("ISSUE", ratio=2, style="#ffb703")
                    csp_table.add_column("IMPACT / REMEDIATION", ratio=3, style="#8b949e")
                    for fl in csp_eval.flaws:
                        fl_col = (
                            "bold #ff4444"
                            if fl.severity in ("CRITICAL", "HIGH")
                            else ("#ffb703" if fl.severity == "MEDIUM" else "#00e5ff")
                        )
                        csp_table.add_row(
                            f"[{fl_col}]{fl.severity}[/{fl_col}]",
                            escape(fl.directive),
                            escape(fl.issue),
                            escape(f"{fl.impact} — {fl.recommendation}"[:100]),
                        )
                    c.print(csp_table)

        # ── 16. Discovered Parameters (PD-1) ──
        if self.state.param_results:
            c.print(f"\n[bold #ff9f43]DISCOVERED QUERY PARAMETERS ({len(self.state.param_results)})[/bold #ff9f43]")
            p_table = Table(show_header=True, header_style="bold #ff9f43", border_style="#30363d", expand=True)
            p_table.add_column("PARAMETER", width=18, style="bold #00e5ff")
            p_table.add_column("BEHAVIOR", width=16, justify="center")
            p_table.add_column("ENDPOINT", ratio=2, style="#58a6ff")
            p_table.add_column("EVIDENCE", ratio=2, style="#8b949e")
            for pr in self.state.param_results:
                b_color = "bold #ff4444" if pr.anomaly_type == "REFLECTION" else "#ffb703"
                p_table.add_row(
                    escape(pr.param),
                    f"[{b_color}]{pr.anomaly_type}[/{b_color}]",
                    escape(pr.endpoint[:45]),
                    escape(pr.evidence[:70]),
                )
            c.print(p_table)

        # ── 17. Virtual Hosts (PC-2) ──
        if self.state.vhost_results:
            c.print(f"\n[bold #bc8cff]DISCOVERED VIRTUAL HOSTS ({len(self.state.vhost_results)})[/bold #bc8cff]")
            vh_table = Table(show_header=True, header_style="bold #bc8cff", border_style="#30363d", expand=True)
            vh_table.add_column("VIRTUAL HOST", ratio=2, style="bold #e6edf3")
            vh_table.add_column("IP", width=16, style="#3fb950")
            vh_table.add_column("STATUS", width=8, justify="center")
            vh_table.add_column("TITLE", ratio=2, style="#8b949e")
            vh_table.add_column("DIFFERENCE", width=16, style="#ffb703")
            for vh in self.state.vhost_results:
                sc_col = "bold #00ff66" if vh.status_code == 200 else "#ffb703"
                vh_table.add_row(
                    escape(vh.host),
                    escape(vh.ip),
                    f"[{sc_col}]{vh.status_code}[/{sc_col}]",
                    escape(vh.title[:35]),
                    vh.diff_type,
                )
            c.print(vh_table)

        # ── 18. Security Findings ──
        findings = self.state.findings
        c.print(f"\n[bold #ff4444]SECURITY FINDINGS ({len(findings)})[/bold #ff4444]")
        if findings:
            find_table = Table(show_header=True, header_style="bold #ff4444", border_style="#30363d", expand=True)
            find_table.add_column("#", width=4, justify="right", style="#8b949e")
            find_table.add_column("SEV", width=10)
            find_table.add_column("MODULE", width=12, style="#58a6ff")
            find_table.add_column("TITLE", ratio=2, style="bold #e6edf3")
            find_table.add_column("DETAIL", ratio=3, style="#8b949e")

            sev_colors = {
                "CRITICAL": "bold #ff4444",
                "HIGH": "#ff4444",
                "MEDIUM": "#ffb703",
                "LOW": "#00e5ff",
                "INFO": "#8b949e",
            }
            for i, f in enumerate(findings, 1):
                sev = getattr(f, "severity", "INFO")
                color = sev_colors.get(sev, "white")
                title = getattr(f, "title", str(f))
                detail = getattr(f, "detail", "")
                mod = getattr(f, "module", "RECON")
                find_table.add_row(str(i), f"[{color}]{sev}[/{color}]", mod, escape(title[:60]), escape(detail[:90]))
            c.print(find_table)
        else:
            c.print("  [bold #00ff66]Clean scan — no immediate security findings detected.[/bold #00ff66]")

    def _export_results(self) -> None:
        """Export session findings only if file export options were requested."""
        cfg = self.scan_config
        saved_files: list[tuple[str, Path]] = []

        try:
            if cfg.output_json:
                p = export_json(self.state, filepath=cfg.output_json)
                saved_files.append(("JSON report", p))

            if cfg.output_markdown:
                p = export_markdown(self.state, filepath=cfg.output_markdown)
                saved_files.append(("Markdown report", p))

            if cfg.output_text:
                p = export_text(self.state, filepath=cfg.output_text)
                saved_files.append(("Text report", p))

            if cfg.output_sarif:
                p = export_sarif(self.state, filepath=cfg.output_sarif)
                saved_files.append(("SARIF v2.1.0", p))

            if saved_files:
                self.console.print("\n[bold #00ff66]SESSION EXPORT SAVED[/bold #00ff66]")
                for label, p in saved_files:
                    self.console.print(f"  [#8b949e]{label:<16}:[/#8b949e] [bold #00e5ff]{p}[/bold #00e5ff]")
                self.console.print("")
        except Exception as exc:
            self.console.print(f"[bold #ff4444]Export notice: {exc}[/bold #ff4444]")

    def run(self) -> None:
        """Entry point called by main.py."""
        # Clear old terminal output and scrollback for a fresh screen
        self.console.clear()

        # 1. Print the purple-blue gradient ASCII art banner centered in terminal
        self.console.print(get_banner_renderable())
        self.console.print("")

        # 2. Run the main reconnaissance scan and live TUI
        try:
            asyncio.run(self._main_loop())
        except KeyboardInterrupt:
            self.console.print("\n[bold #ffb703]Session interrupted by user.[/bold #ffb703]")
            self._print_terminal_report()
            self._export_results()
