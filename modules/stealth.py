"""HTTP Client factory with adaptive stealth, rate limiting, and jitter (P2-2)."""

from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from app.state import ScanConfig

USER_AGENT_POOL: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]


def get_user_agent(config: ScanConfig) -> str:
    """Return configured, randomized, or default User-Agent string."""
    if config.user_agent:
        if config.user_agent.lower() == "random":
            return random.choice(USER_AGENT_POOL)
        return config.user_agent
    return "RECON-WIRE/1.0 (Security Reconnaissance Suite)"


async def apply_stealth_delay(target: Any) -> None:
    """Apply adaptive delay and jitter between requests if configured (P2-2)."""
    cfg = getattr(target, "config", target)
    delay = getattr(cfg, "delay", 0.0)
    jitter = getattr(cfg, "jitter", 0.0)
    if jitter > 0:
        delay += random.uniform(0.0, jitter)
    if delay > 0:
        await asyncio.sleep(delay)


def build_client(
    target: Any,
    verify: bool = False,
    follow_redirects: bool = True,
    timeout: int | float | None = None,
) -> httpx.AsyncClient:
    """Construct an AsyncClient honoring timeouts, redirects, and User-Agent."""
    cfg = getattr(target, "config", target)
    t_val = timeout if timeout is not None else getattr(cfg, "timeout", 10)
    headers = {
        "User-Agent": get_user_agent(cfg),
        "Accept": "*/*",
    }
    max_conn = getattr(cfg, "max_concurrent", 20)
    return httpx.AsyncClient(
        headers=headers,
        timeout=httpx.Timeout(t_val),
        verify=verify,
        follow_redirects=follow_redirects,
        limits=httpx.Limits(max_connections=max_conn, max_keepalive_connections=20),
    )
