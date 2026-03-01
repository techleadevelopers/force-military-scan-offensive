import ssl
import socket
import asyncio
import datetime
from .base import BaseModule
from scanner.models import Finding


class TLSValidatorModule(BaseModule):
    name = "TLS Configuration Validator"
    phase = "exposure"
    description = "TLS/SSL certificate validation, protocol analysis, cipher suite assessment"

    WEAK_CIPHERS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]

    async def execute(self, job) -> list:
        findings = []
        hostname = job.hostname
        port = job.port or 443

        self.log(f"Analyzing TLS configuration for {hostname}:{port}")

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            self.log("Establishing TLS connection...")
            conn = socket.create_connection((hostname, port), timeout=10)
            sock = context.wrap_socket(conn, server_hostname=hostname)

            cert = sock.getpeercert(binary_form=True)
            cipher = sock.cipher()
            protocol = sock.version()
            sock.close()

            self.log(f"TLS Protocol: {protocol}", "success")
            self.log(f"Cipher Suite: {cipher[0] if cipher else 'unknown'}")
            self.log(f"Key Size: {cipher[2] if cipher else 'unknown'} bits")

            if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                findings.append(
                    Finding(
                        severity="high",
                        title="Outdated TLS Protocol",
                        description=f"Server supports deprecated protocol: {protocol}",
                        phase=self.phase,
                        recommendation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Only allow TLS 1.2 and TLS 1.3.",
                        cvss_score=7.4,
                        references=["https://tools.ietf.org/html/rfc8996"],
                    ),
                )
                self.finding("high", "Outdated TLS Protocol", f"Protocol: {protocol}", cvss_score=7.4)
            else:
                self.log(f"TLS protocol version is current: {protocol}", "success")

            if cipher:
                cipher_name = cipher[0]
                for weak in self.WEAK_CIPHERS:
                    if weak.lower() in cipher_name.lower():
                        findings.append(
                            Finding(
                                severity="high",
                                title="Weak Cipher Suite",
                                description=f"Weak cipher detected: {cipher_name}",
                                phase=self.phase,
                                recommendation=f"Disable weak cipher suite {cipher_name}. Use AES-GCM or ChaCha20-Poly1305.",
                                cvss_score=6.8,
                            ),
                        )
                        self.finding("high", "Weak Cipher Suite", f"Cipher: {cipher_name}", cvss_score=6.8)
                        break

                if cipher[2] and cipher[2] < 128:
                    findings.append(
                        Finding(
                            severity="high",
                            title="Insufficient Key Length",
                            description=f"Cipher key length is {cipher[2]} bits (minimum 128 recommended)",
                            phase=self.phase,
                            recommendation="Use cipher suites with at least 128-bit key length.",
                            cvss_score=6.5,
                        ),
                    )
                    self.finding("high", "Insufficient Key Length", f"Key: {cipher[2]} bits", cvss_score=6.5)

        except ssl.SSLError as e:
            self.log(f"TLS handshake error: {e}", "error")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self.log(f"Connection failed on port {port}: {e}", "warn")
            self.log("Target may not support TLS on this port", "info")
            return findings

        self.log("Validating certificate chain...")
        try:
            verify_ctx = ssl.create_default_context()
            conn2 = socket.create_connection((hostname, port), timeout=10)
            verified_sock = verify_ctx.wrap_socket(conn2, server_hostname=hostname)
            cert_info = verified_sock.getpeercert()
            verified_sock.close()

            if cert_info:
                not_after = ssl.cert_time_to_seconds(cert_info["notAfter"])
                not_before = ssl.cert_time_to_seconds(cert_info["notBefore"])
                now = datetime.datetime.now().timestamp()
                days_remaining = (not_after - now) / 86400

                self.log(f"Certificate valid until: {cert_info['notAfter']}")
                self.log(f"Days remaining: {int(days_remaining)}")

                issuer = dict(x[0] for x in cert_info.get("issuer", []))
                self.log(f"Issuer: {issuer.get('organizationName', 'Unknown')}")

                san = cert_info.get("subjectAltName", [])
                san_list = [name for typ, name in san if typ == "DNS"]
                if san_list:
                    self.log(f"SANs: {', '.join(san_list[:5])}")

                if days_remaining < 0:
                    findings.append(
                        Finding(
                            severity="critical",
                            title="Expired Certificate",
                            description=f"Certificate expired {int(abs(days_remaining))} days ago",
                            phase=self.phase,
                            recommendation="Renew the TLS certificate immediately.",
                            cvss_score=9.1,
                        ),
                    )
                    self.finding("critical", "Expired Certificate", f"Expired {int(abs(days_remaining))} days ago", cvss_score=9.1)
                elif days_remaining < 30:
                    findings.append(
                        Finding(
                            severity="medium",
                            title="Certificate Expiring Soon",
                            description=f"Certificate expires in {int(days_remaining)} days",
                            phase=self.phase,
                            recommendation="Renew the certificate before expiration. Consider automated renewal.",
                            cvss_score=4.0,
                        ),
                    )
                    self.finding("medium", "Certificate Expiring Soon", f"Expires in {int(days_remaining)} days", cvss_score=4.0)
                else:
                    self.log(f"Certificate validity: OK ({int(days_remaining)} days remaining)", "success")

            self.log("Certificate chain validated successfully", "success")
        except ssl.SSLCertVerificationError as e:
            self.log(f"Certificate validation failed: {e}", "error")
            findings.append(
                Finding(
                    severity="high",
                    title="Invalid Certificate",
                    description=f"Certificate verification failed: {str(e)[:200]}",
                    phase=self.phase,
                    recommendation="Install a valid certificate from a trusted Certificate Authority.",
                    cvss_score=7.5,
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"],
                ),
            )
            self.finding("high", "Invalid Certificate", str(e)[:120], cvss_score=7.5)
        except Exception as e:
            self.log(f"Certificate check error: {e}", "warn")

        self.log(f"TLS validation complete — {len(findings)} finding(s)")
        return findings
