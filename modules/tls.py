"""TLS/SSL certificate and cipher analysis module.

Writes structured results to state.tls_results.
Pushes findings for vulnerable TLS versions, weak ciphers, cert issues.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
from datetime import datetime
from typing import Any, TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import NameOID, ExtensionOID

from modules.findings import push_finding

if TYPE_CHECKING:
    from app.state import AppState

logger = logging.getLogger("recon_wire.tls")

# ── TLS versions to probe (label → ssl constant) ──
TLS_VERSIONS: list[dict[str, Any]] = [
    {"name": "TLS 1.3", "protocol": ssl.PROTOCOL_TLS_CLIENT, "min": getattr(ssl.TLSVersion, "TLSv1_3", None), "max": getattr(ssl.TLSVersion, "TLSv1_3", None), "secure": True},
    {"name": "TLS 1.2", "protocol": ssl.PROTOCOL_TLS_CLIENT, "min": ssl.TLSVersion.TLSv1_2, "max": ssl.TLSVersion.TLSv1_2, "secure": True},
    {"name": "TLS 1.1", "protocol": ssl.PROTOCOL_TLS_CLIENT, "min": getattr(ssl.TLSVersion, "TLSv1_1", None), "max": getattr(ssl.TLSVersion, "TLSv1_1", None), "secure": False},
    {"name": "TLS 1.0", "protocol": ssl.PROTOCOL_TLS_CLIENT, "min": getattr(ssl.TLSVersion, "TLSv1", None), "max": getattr(ssl.TLSVersion, "TLSv1", None), "secure": False},
]

# ── Weak cipher substrings ──
WEAK_CIPHERS = [
    "RC4", "DES", "MD5", "NULL", "EXPORT", "anon", "RC2",
    "SEED", "IDEA", "CAMELLIA",
]


class TLSModule:
    """TLS/SSL analysis — version probing, cert chain, cipher audit, vuln checks."""

    def __init__(self, state: AppState) -> None:
        self.state = state
        self.hostname = state.config.hostname
        self.port = state.config.port
        self.timeout = state.config.timeout

    async def run(self) -> None:
        status = self.state.module_statuses["TLS"]
        status.state = "RUNNING"
        status.message = "Probing TLS versions"
        logger.info("TLS module starting for %s:%d", self.hostname, self.port)

        try:
            loop = asyncio.get_event_loop()

            # Skip TLS analysis for plain HTTP targets
            if self.state.config.scheme != "https":
                await push_finding(
                    self.state.findings_queue,
                    severity="HIGH", module="TLS",
                    title="No TLS — Plain HTTP",
                    detail="Target uses plain HTTP without encryption",
                    evidence=f"Scheme: {self.state.config.scheme}",
                )
                self.state.tls_results = {
                    "tls_versions": {},
                    "negotiated_cipher": "N/A — plain HTTP",
                    "cert_chain": [],
                    "leaf_cert": {},
                    "vulnerabilities": [{"name": "No TLS", "detail": "Plain HTTP target"}],
                    "ocsp_urls": [],
                    "crl_urls": [],
                    "ct_present": False,
                }
                status.state = "DONE"
                status.progress = 100
                status.message = "Plain HTTP — no TLS"
                return

            # ── TLS version probing ──
            tls_versions: dict[str, bool] = {}
            for ver_spec in TLS_VERSIONS:
                supported = await loop.run_in_executor(
                    None, self._probe_tls_version, ver_spec
                )
                tls_versions[ver_spec["name"]] = supported
                if supported and not ver_spec["secure"]:
                    await push_finding(
                        self.state.findings_queue,
                        severity="HIGH" if ver_spec["name"] in ("TLS 1.0",) else "MEDIUM",
                        module="TLS",
                        title=f"Insecure {ver_spec['name']} Supported",
                        detail=f"Server supports deprecated {ver_spec['name']}",
                        evidence=f"{self.hostname}:{self.port}",
                    )
            status.progress = 30

            # ── Get negotiated cipher and cert chain ──
            status.message = "Extracting certificate chain"
            chain_data = await loop.run_in_executor(None, self._get_cert_chain)
            status.progress = 60

            negotiated_cipher = chain_data.get("cipher", "Unknown")
            cert_chain = chain_data.get("chain", [])
            leaf_cert = chain_data.get("leaf", {})

            # ── Check cipher strength ──
            if negotiated_cipher and negotiated_cipher != "Unknown":
                for weak in WEAK_CIPHERS:
                    if weak.lower() in negotiated_cipher.lower():
                        await push_finding(
                            self.state.findings_queue,
                            severity="HIGH", module="TLS",
                            title=f"Weak Cipher: {negotiated_cipher}",
                            detail=f"Negotiated cipher contains weak algorithm: {weak}",
                            evidence=f"Cipher: {negotiated_cipher}",
                        )
                        break

            # ── Cert vulnerability checks ──
            status.message = "Running vulnerability checks"
            vulnerabilities = await self._check_vulnerabilities(leaf_cert, cert_chain)
            status.progress = 85

            # ── OCSP/CRL/CT extraction ──
            ocsp_urls = leaf_cert.get("ocsp_urls", [])
            crl_urls = leaf_cert.get("crl_urls", [])
            ct_present = leaf_cert.get("ct_present", False)

            self.state.tls_results = {
                "tls_versions": tls_versions,
                "negotiated_cipher": negotiated_cipher,
                "cert_chain": cert_chain,
                "leaf_cert": leaf_cert,
                "vulnerabilities": vulnerabilities,
                "ocsp_urls": ocsp_urls,
                "crl_urls": crl_urls,
                "ct_present": ct_present,
            }

            status.state = "DONE"
            status.progress = 100
            vuln_count = len(vulnerabilities)
            status.message = f"Cipher: {negotiated_cipher[:30]}, {vuln_count} issue(s)"
            logger.info("TLS module completed — %d vulnerabilities", vuln_count)

        except Exception as exc:
            status.state = "ERROR"
            status.message = f"TLS error: {exc}"
            logger.error("TLS module failed: %s", exc, exc_info=True)
            await push_finding(
                self.state.findings_queue,
                severity="MEDIUM", module="TLS",
                title="TLS Module Error",
                detail=str(exc),
                evidence=f"{self.hostname}:{self.port}",
            )

    def _probe_tls_version(self, ver_spec: dict[str, Any]) -> bool:
        """Probe whether a specific TLS version is supported (runs in executor)."""
        try:
            ctx = ssl.SSLContext(ver_spec["protocol"])
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            if ver_spec.get("min") is not None:
                ctx.minimum_version = ver_spec["min"]
            if ver_spec.get("max") is not None:
                ctx.maximum_version = ver_spec["max"]

            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    ssock.do_handshake()
                    return True
        except (ssl.SSLError, OSError, ConnectionError, socket.timeout):
            return False
        except Exception as exc:
            logger.debug("TLS probe error for %s: %s", ver_spec["name"], exc)
            return False

    def _get_cert_chain(self) -> dict[str, Any]:
        """Extract certificate chain, negotiated cipher, and leaf cert details."""
        result: dict[str, Any] = {
            "cipher": "Unknown",
            "chain": [],
            "leaf": {},
        }
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    ssock.do_handshake()

                    # Negotiated cipher
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result["cipher"] = f"{cipher_info[0]} ({cipher_info[1]}, {cipher_info[2]}-bit)"

                    # Get binary cert chain
                    der_certs = ssock.getpeercert(binary_form=True)
                    peer_cert = ssock.getpeercert()

                    # Parse binary certs
                    if der_certs:
                        chain_parsed = self._parse_cert(der_certs, is_leaf=True)
                        result["chain"].append(chain_parsed)
                        result["leaf"] = chain_parsed

                    # Parse peer cert dict for additional info
                    if peer_cert:
                        result["leaf"].update(self._parse_peer_cert(peer_cert))

        except Exception as exc:
            logger.warning("Cert chain extraction failed: %s", exc)
            result["cipher"] = f"Error: {exc}"

        # Try to get full chain via different method
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Some Python versions support get_unverified_chain
                    if hasattr(ssock, "get_unverified_chain"):
                        chain_certs = ssock.get_unverified_chain()
                        result["chain"] = []
                        for i, cert_bytes in enumerate(chain_certs):
                            parsed = self._parse_x509_cert(cert_bytes, is_leaf=(i == 0))
                            result["chain"].append(parsed)
                            if i == 0:
                                result["leaf"].update(parsed)
        except Exception:
            pass

        return result

    def _parse_cert(self, der_bytes: bytes, is_leaf: bool = False) -> dict[str, Any]:
        """Parse a DER-encoded certificate using cryptography library."""
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
            return self._extract_cert_fields(cert, is_leaf)
        except Exception as exc:
            logger.debug("Cert parsing error: %s", exc)
            return {"error": str(exc)}

    def _parse_x509_cert(self, cert_obj: Any, is_leaf: bool = False) -> dict[str, Any]:
        """Parse a certificate object from get_unverified_chain."""
        try:
            der_bytes = cert_obj.public_bytes(serialization.Encoding.DER)
            cert = x509.load_der_x509_certificate(der_bytes)
            return self._extract_cert_fields(cert, is_leaf)
        except Exception as exc:
            logger.debug("X509 cert parsing error: %s", exc)
            return {"error": str(exc)}

    def _extract_cert_fields(self, cert: x509.Certificate, is_leaf: bool) -> dict[str, Any]:
        """Extract all relevant fields from a parsed x509 certificate."""
        info: dict[str, Any] = {}

        # Subject
        try:
            info["subject"] = self._name_to_dict(cert.subject)
            info["subject_cn"] = info["subject"].get("CN", "Unknown")
        except Exception:
            info["subject"] = {}
            info["subject_cn"] = "Unknown"

        # Issuer
        try:
            info["issuer"] = self._name_to_dict(cert.issuer)
            info["issuer_cn"] = info["issuer"].get("CN", "Unknown")
        except Exception:
            info["issuer"] = {}
            info["issuer_cn"] = "Unknown"

        # Dates
        try:
            info["not_before"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat()
            info["not_after"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()
            not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
            not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
            info["days_remaining"] = (not_after - datetime.utcnow()).days
            info["validity_days"] = (not_after - not_before).days
        except Exception:
            info["not_before"] = "Unknown"
            info["not_after"] = "Unknown"
            info["days_remaining"] = None
            info["validity_days"] = None

        # Serial number
        try:
            info["serial_number"] = format(cert.serial_number, "x")
        except Exception:
            info["serial_number"] = "Unknown"

        # Signature algorithm
        try:
            info["signature_algorithm"] = cert.signature_algorithm_oid._name
        except Exception:
            info["signature_algorithm"] = "Unknown"

        # Key info
        try:
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                info["key_type"] = "RSA"
                info["key_size"] = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                info["key_type"] = "ECDSA"
                info["key_size"] = pub_key.key_size
                info["curve"] = pub_key.curve.name
            elif isinstance(pub_key, dsa.DSAPublicKey):
                info["key_type"] = "DSA"
                info["key_size"] = pub_key.key_size
            else:
                info["key_type"] = type(pub_key).__name__
                info["key_size"] = None
        except Exception:
            info["key_type"] = "Unknown"
            info["key_size"] = None

        # Fingerprints
        try:
            der = cert.public_bytes(serialization.Encoding.DER)
            info["sha256_fingerprint"] = hashlib.sha256(der).hexdigest()
            info["sha1_fingerprint"] = hashlib.sha1(der).hexdigest()
        except Exception:
            info["sha256_fingerprint"] = "Unknown"
            info["sha1_fingerprint"] = "Unknown"

        # Self-signed check
        try:
            info["is_self_signed"] = cert.issuer == cert.subject
        except Exception:
            info["is_self_signed"] = False

        if is_leaf:
            # SANs
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                info["sans"] = san_ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                info["sans"] = []

            # OCSP URLs
            try:
                aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                info["ocsp_urls"] = [
                    desc.access_location.value
                    for desc in aia.value
                    if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP
                ]
            except Exception:
                info["ocsp_urls"] = []

            # CRL URLs
            try:
                crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
                info["crl_urls"] = []
                for dp in crl_ext.value:
                    if dp.full_name:
                        for name in dp.full_name:
                            info["crl_urls"].append(name.value)
            except Exception:
                info["crl_urls"] = []

            # CT (Certificate Transparency) — SCT extension
            try:
                sct_ext = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
                )
                info["ct_present"] = True
                info["sct_count"] = len(sct_ext.value) if hasattr(sct_ext.value, '__len__') else 1
            except Exception:
                info["ct_present"] = False
                info["sct_count"] = 0

        return info

    def _parse_peer_cert(self, peer_cert: dict) -> dict[str, Any]:
        """Extract additional info from ssl.getpeercert() dict."""
        info: dict[str, Any] = {}
        try:
            # Subject Alt Names from peer cert
            san_tuples = peer_cert.get("subjectAltName", ())
            if san_tuples and "sans" not in info:
                info["sans"] = [v for t, v in san_tuples if t == "DNS"]
        except Exception:
            pass
        return info

    @staticmethod
    def _name_to_dict(name: x509.Name) -> dict[str, str]:
        """Convert x509.Name to a flat dictionary."""
        result: dict[str, str] = {}
        oid_map = {
            NameOID.COMMON_NAME: "CN",
            NameOID.ORGANIZATION_NAME: "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
            NameOID.COUNTRY_NAME: "C",
            NameOID.STATE_OR_PROVINCE_NAME: "ST",
            NameOID.LOCALITY_NAME: "L",
        }
        for attr in name:
            label = oid_map.get(attr.oid, attr.oid.dotted_string)
            result[label] = attr.value
        return result

    async def _check_vulnerabilities(
        self, leaf: dict[str, Any], chain: list[dict[str, Any]]
    ) -> list[dict[str, str]]:
        """Run vulnerability checks on cert data."""
        vulns: list[dict[str, str]] = []
        q = self.state.findings_queue

        # Self-signed cert
        if leaf.get("is_self_signed"):
            vulns.append({"name": "Self-Signed Certificate", "detail": "Certificate is self-signed — browsers will show warnings"})
            await push_finding(
                q, severity="HIGH", module="TLS",
                title="Self-Signed Certificate",
                detail="Leaf certificate is self-signed — not trusted by browsers",
                evidence=f"Subject: {leaf.get('subject_cn', 'N/A')}, Issuer: {leaf.get('issuer_cn', 'N/A')}",
            )

        # Expired cert
        days_remaining = leaf.get("days_remaining")
        if days_remaining is not None:
            if days_remaining < 0:
                vulns.append({"name": "Expired Certificate", "detail": f"Certificate expired {abs(days_remaining)} days ago"})
                await push_finding(
                    q, severity="CRITICAL", module="TLS",
                    title="Certificate Expired",
                    detail=f"Certificate expired {abs(days_remaining)} days ago",
                    evidence=f"Not After: {leaf.get('not_after', 'N/A')}",
                )
            elif days_remaining < 30:
                vulns.append({"name": "Certificate Expiring Soon", "detail": f"Certificate expires in {days_remaining} days"})
                await push_finding(
                    q, severity="HIGH", module="TLS",
                    title="Certificate Expiring Soon",
                    detail=f"Certificate expires in {days_remaining} days — renew immediately",
                    evidence=f"Not After: {leaf.get('not_after', 'N/A')}",
                )

        # Weak key size
        key_type = leaf.get("key_type", "")
        key_size = leaf.get("key_size")
        if key_type == "RSA" and key_size and key_size < 2048:
            vulns.append({"name": "Weak RSA Key", "detail": f"RSA key size {key_size} bits — minimum 2048 recommended"})
            await push_finding(
                q, severity="HIGH", module="TLS",
                title=f"Weak RSA Key ({key_size}-bit)",
                detail=f"RSA key size {key_size} is below the 2048-bit minimum recommendation",
                evidence=f"Key: RSA-{key_size}",
            )
        elif key_type == "ECDSA" and key_size and key_size < 256:
            vulns.append({"name": "Weak EC Key", "detail": f"EC key size {key_size} bits"})
            await push_finding(
                q, severity="MEDIUM", module="TLS",
                title=f"Weak EC Key ({key_size}-bit)",
                detail=f"ECDSA key size {key_size} is below the 256-bit recommendation",
                evidence=f"Key: ECDSA-{key_size}",
            )

        # SHA-1 signature
        sig_algo = leaf.get("signature_algorithm", "").lower()
        if "sha1" in sig_algo or "sha-1" in sig_algo:
            vulns.append({"name": "SHA-1 Signature", "detail": "Certificate uses SHA-1 signature — deprecated and insecure"})
            await push_finding(
                q, severity="HIGH", module="TLS",
                title="SHA-1 Certificate Signature",
                detail="Certificate signed with SHA-1 — deprecated and vulnerable to collision attacks",
                evidence=f"Signature Algorithm: {sig_algo}",
            )

        # Hostname mismatch check
        sans = leaf.get("sans", [])
        subject_cn = leaf.get("subject_cn", "")
        all_names = set(sans + ([subject_cn] if subject_cn else []))
        hostname = self.hostname
        name_matches = False
        for name in all_names:
            if name.startswith("*."):
                # Wildcard match
                wildcard_domain = name[2:]
                if hostname == wildcard_domain or hostname.endswith("." + wildcard_domain):
                    name_matches = True
                    break
            elif name.lower() == hostname.lower():
                name_matches = True
                break
        if all_names and not name_matches:
            vulns.append({"name": "Hostname Mismatch", "detail": f"Certificate does not match hostname {hostname}"})
            await push_finding(
                q, severity="HIGH", module="TLS",
                title="Certificate Hostname Mismatch",
                detail=f"Certificate CN/SANs do not include {hostname}",
                evidence=f"SANs: {', '.join(list(all_names)[:5])}, Hostname: {hostname}",
            )

        # Missing CT
        if not leaf.get("ct_present"):
            vulns.append({"name": "No Certificate Transparency", "detail": "No SCT extensions found — certificate may not be logged"})
            await push_finding(
                q, severity="LOW", module="TLS",
                title="No Certificate Transparency",
                detail="Certificate lacks SCT extensions — not logged to CT logs",
                evidence=f"SCT count: 0",
            )

        # Long validity (>398 days is non-compliant per CA/B Forum)
        validity_days = leaf.get("validity_days")
        if validity_days and validity_days > 398:
            vulns.append({"name": "Excessive Validity Period", "detail": f"Certificate valid for {validity_days} days — exceeds 398-day CA/B Forum limit"})
            await push_finding(
                q, severity="INFO", module="TLS",
                title="Excessive Certificate Validity",
                detail=f"Certificate validity period ({validity_days} days) exceeds the 398-day CA/B Forum maximum",
                evidence=f"Valid: {leaf.get('not_before', 'N/A')} to {leaf.get('not_after', 'N/A')}",
            )

        return vulns
