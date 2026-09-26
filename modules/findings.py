"""Finding dataclass and FindingsAggregator — the single source of truth.

All modules push Finding objects into AppState.findings_queue via push_finding().
FindingsAggregator drains the queue and maintains the sorted findings list.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.findings")

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass
class Finding:
    """A single security finding produced by any module."""
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    module: str
    title: str
    detail: str
    evidence: str
    timestamp: datetime

    def to_dict(self) -> dict:
        """JSON-safe dictionary representation."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)


async def push_finding(queue: asyncio.Queue, **kwargs) -> None:
    """Helper for modules to push a Finding without boilerplate."""
    finding = Finding(timestamp=datetime.utcnow(), **kwargs)
    await queue.put(finding)
    logger.info("Finding pushed: [%s] %s — %s", finding.severity, finding.module, finding.title)


class FindingsAggregator:
    """Drains the findings queue and maintains the sorted master list.

    Runs as a concurrent task alongside modules in core.py.
    """

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def consume(self) -> None:
        """Drain findings_queue indefinitely until scan completes."""
        logger.info("FindingsAggregator started — waiting for findings")
        while True:
            try:
                finding: Finding = await asyncio.wait_for(
                    self.state.findings_queue.get(), timeout=1.0
                )
                self.state.findings.append(finding)
                # Re-sort by severity (stable sort preserves order within rank)
                self.state.findings.sort(key=lambda f: f.severity_rank)
                self.state.findings_queue.task_done()
                logger.debug(
                    "Findings total: %d  (latest: %s/%s)",
                    len(self.state.findings), finding.severity, finding.title,
                )
            except asyncio.TimeoutError:
                if self.state.scan_complete:
                    # Drain any remaining items
                    while not self.state.findings_queue.empty():
                        try:
                            finding = self.state.findings_queue.get_nowait()
                            self.state.findings.append(finding)
                            self.state.findings.sort(key=lambda f: f.severity_rank)
                            self.state.findings_queue.task_done()
                        except asyncio.QueueEmpty:
                            break
                    logger.info(
                        "FindingsAggregator finished — %d total findings",
                        len(self.state.findings),
                    )
                    return
            except Exception as exc:
                logger.error("FindingsAggregator error: %s", exc, exc_info=True)
