"""Public cloud bucket hunting module (P1-4).

Probes AWS S3, Google Cloud Storage, and Azure Blob storage containers matching the organization domain.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from modules.findings import push_finding
from modules.stealth import apply_stealth_delay, build_client

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.cloud")


@dataclass
class CloudResult:
    provider: str  # AWS | GCP | AZURE
    bucket_name: str
    url: str
    status: str  # OPEN | PROTECTED | NOT_FOUND

    def to_dict(self) -> dict:
        return asdict(self)


class CloudModule:
    """Async hunter for exposed public cloud storage buckets."""

    def __init__(self, state: AppState) -> None:
        self.state = state

    async def _check_bucket(
        self, client, provider: str, bucket: str, url: str, semaphore: asyncio.Semaphore
    ) -> CloudResult | None:
        async with semaphore:
            await apply_stealth_delay(self.state.config)
            try:
                resp = await client.get(url)
                status_code = resp.status_code
                text = resp.text[:500].lower()

                # AWS S3: 200 = ListBucketResult (Public open), 403 = AccessDenied (Bucket exists)
                if provider == "AWS":
                    if status_code == 200 and ("listbucketresult" in text or "<contents>" in text):
                        await push_finding(
                            self.state.findings_queue,
                            module="CLOUD",
                            severity="CRITICAL",
                            title=f"Open AWS S3 Bucket: {bucket}",
                            detail=f"AWS S3 Bucket '{bucket}' is publicly open and listable.",
                            evidence=f"URL: {url} (HTTP 200)",
                        )
                        return CloudResult(provider="AWS", bucket_name=bucket, url=url, status="OPEN")
                    elif status_code == 403:
                        await push_finding(
                            self.state.findings_queue,
                            module="CLOUD",
                            severity="INFO",
                            title=f"Protected AWS S3 Bucket Found: {bucket}",
                            detail=f"AWS S3 Bucket '{bucket}' exists but public listing is denied.",
                            evidence=f"URL: {url} (HTTP 403)",
                        )
                        return CloudResult(provider="AWS", bucket_name=bucket, url=url, status="PROTECTED")

                # GCP Storage
                elif provider == "GCP":
                    if status_code == 200 and ("<listbucketresult>" in text or "items" in text):
                        await push_finding(
                            self.state.findings_queue,
                            module="CLOUD",
                            severity="CRITICAL",
                            title=f"Open Google Cloud Bucket: {bucket}",
                            detail=f"GCP Storage bucket '{bucket}' is publicly accessible.",
                            evidence=f"URL: {url} (HTTP 200)",
                        )
                        return CloudResult(provider="GCP", bucket_name=bucket, url=url, status="OPEN")
                    elif status_code == 403:
                        return CloudResult(provider="GCP", bucket_name=bucket, url=url, status="PROTECTED")

                # Azure Blob
                elif provider == "AZURE":
                    if status_code == 200 and "enumerationresults" in text:
                        await push_finding(
                            self.state.findings_queue,
                            module="CLOUD",
                            severity="CRITICAL",
                            title=f"Open Azure Blob Container: {bucket}",
                            detail=f"Azure Blob container '{bucket}' is publicly open.",
                            evidence=f"URL: {url} (HTTP 200)",
                        )
                        return CloudResult(provider="AZURE", bucket_name=bucket, url=url, status="OPEN")
                    elif status_code == 400 or status_code == 403:
                        return CloudResult(provider="AZURE", bucket_name=bucket, url=url, status="PROTECTED")

            except Exception:
                pass
            return None

    async def run(self) -> list[CloudResult]:
        status = self.state.module_statuses.get("CLOUD")
        if status:
            status.state = "RUNNING"
            status.message = "Hunting for public cloud buckets..."

        cfg = self.state.config
        clean_name = cfg.domain.split(".")[0].lower()
        full_domain_clean = cfg.domain.replace(".", "-").lower()

        # Word variations
        candidates = [
            clean_name,
            f"{clean_name}-backup",
            f"{clean_name}-data",
            f"{clean_name}-assets",
            f"{clean_name}-prod",
            f"{clean_name}-staging",
            full_domain_clean,
        ]

        targets: list[tuple[str, str, str]] = []
        for c in candidates:
            targets.append(("AWS", c, f"https://{c}.s3.amazonaws.com"))
            targets.append(("GCP", c, f"https://storage.googleapis.com/{c}"))
            targets.append(("AZURE", c, f"https://{c}.blob.core.windows.net/$root?restype=container&comp=list"))

        semaphore = asyncio.Semaphore(cfg.max_concurrent)
        results: list[CloudResult] = []

        try:
            async with build_client(cfg) as client:
                tasks = [self._check_bucket(client, prov, b_name, url, semaphore) for prov, b_name, url in targets]
                raw = await asyncio.gather(*tasks, return_exceptions=True)
                results = [r for r in raw if isinstance(r, CloudResult)]
        except Exception as exc:
            logger.error("Cloud hunter raised error: %s", exc)

        self.state.cloud_results = results

        if status:
            status.state = "DONE"
            status.progress = 100
            status.message = f"{len(results)} cloud buckets discovered"

        return results
