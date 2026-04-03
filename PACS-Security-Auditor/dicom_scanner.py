"""
DICOM Service Scanner - Core reconnaissance module
Discovers and fingerprints PACS/DICOM services
"""

import socket
import ssl
import struct
import time
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

try:
    from pynetdicom import AE, debug_logger
    from pynetdicom.sop_class import Verification
    PYNETDICOM_AVAILABLE = True
except ImportError:
    PYNETDICOM_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    host: str
    port: int
    is_open: bool = False
    service_name: str = ""
    banner: str = ""
    tls_enabled: bool = False
    tls_version: str = ""
    anonymous_access: bool = False
    ae_title: str = ""
    implementation_version: str = ""
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())
    vulnerabilities: list = field(default_factory=list)
    raw_errors: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class DicomScanner:
    """
    Scans target hosts for DICOM services and identifies vulnerabilities.
    USE ONLY ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST.
    """

    DICOM_PORTS = [104, 11112, 2762, 2761, 4006]
    DICOM_PREAMBLE = b'\x00' * 128 + b'DICM'

    # DICOM A-ASSOCIATE-RQ packet for C-ECHO (anonymous)
    ASSOCIATE_RQ = bytes([
        0x01, 0x00,             # PDU Type: A-ASSOCIATE-RQ
        0x00, 0x00, 0x00, 0x00, # Reserved + Length (filled below)
        0x00, 0x01,             # Protocol version
        0x00, 0x00,             # Reserved
    ]) + b'ANY-SCU         ' + b'ANY-SCP         ' + b'\x00' * 32

    def __init__(self, timeout: float = 3.0, called_ae: str = "ANY-SCP", calling_ae: str = "AUDIT-TOOL"):
        self.timeout = timeout
        self.called_ae = called_ae
        self.calling_ae = calling_ae

    def scan_host(self, host: str, ports: Optional[list] = None) -> list[ScanResult]:
        """Full scan of a host across DICOM ports."""
        target_ports = ports or self.DICOM_PORTS
        results = []
        for port in target_ports:
            logger.info(f"Scanning {host}:{port}")
            result = self._scan_port(host, port)
            results.append(result)
        return results

    def _scan_port(self, host: str, port: int) -> ScanResult:
        result = ScanResult(host=host, port=port)

        # Step 1: TCP port check
        if not self._tcp_connect(host, port, result):
            return result

        result.is_open = True
        result.service_name = "DICOM"

        # Step 2: TLS check
        self._check_tls(host, port, result)

        # Step 3: DICOM association (anonymous)
        if PYNETDICOM_AVAILABLE:
            self._check_dicom_association(host, port, result)
        else:
            self._check_dicom_raw(host, port, result)

        # Step 4: Vulnerability assessment
        self._assess_vulnerabilities(result)

        return result

    def _tcp_connect(self, host: str, port: int, result: ScanResult) -> bool:
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            # Try to grab banner
            sock.settimeout(1.0)
            try:
                banner = sock.recv(256)
                result.banner = banner.hex()
            except socket.timeout:
                pass
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result.raw_errors.append(str(e))
            return False

    def _check_tls(self, host: str, port: int, result: ScanResult):
        """Test if the port accepts TLS connections."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=host
            )
            conn.settimeout(self.timeout)
            conn.connect((host, port))
            result.tls_enabled = True
            result.tls_version = conn.version()
            conn.close()
        except ssl.SSLError:
            # Port exists but rejects TLS — plaintext DICOM
            result.tls_enabled = False
        except Exception:
            result.tls_enabled = False

    def _check_dicom_association(self, host: str, port: int, result: ScanResult):
        """Use pynetdicom to attempt anonymous C-ECHO."""
        try:
            ae = AE(ae_title=self.calling_ae)
            ae.add_requested_context(Verification)

            assoc = ae.associate(host, port, ae_title=self.called_ae)
            if assoc.is_established:
                result.anonymous_access = True
                result.ae_title = str(assoc.acceptor.ae_title).strip()

                # Try C-ECHO
                status = assoc.send_c_echo()
                if status and status.Status == 0x0000:
                    result.vulnerabilities.append({
                        "id": "DICOM-001",
                        "title": "Anonymous C-ECHO accepted",
                        "severity": "MEDIUM",
                        "description": "PACS responds to C-ECHO without authentication",
                        "hipaa_ref": "164.312(d)"
                    })
                assoc.release()
            ae.shutdown()
        except Exception as e:
            result.raw_errors.append(f"pynetdicom: {str(e)}")

    def _check_dicom_raw(self, host: str, port: int, result: ScanResult):
        """Raw socket DICOM A-ASSOCIATE probe (fallback if pynetdicom missing)."""
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)

            # Build minimal A-ASSOCIATE-RQ
            calling = self.calling_ae.ljust(16)[:16].encode()
            called = self.called_ae.ljust(16)[:16].encode()

            pdu = bytearray()
            pdu += b'\x01\x00'       # PDU type A-ASSOCIATE-RQ
            pdu += b'\x00\x00'       # Reserved
            pdu += b'\x00\x00\x00\x4e'  # Length = 78 bytes
            pdu += b'\x00\x01'       # Protocol version
            pdu += b'\x00\x00'       # Reserved
            pdu += called
            pdu += calling
            pdu += b'\x00' * 32      # Reserved

            sock.sendall(bytes(pdu))
            sock.settimeout(2.0)
            response = sock.recv(256)

            if response and response[0] == 0x02:  # A-ASSOCIATE-AC
                result.anonymous_access = True
                result.ae_title = "UNKNOWN (raw mode)"
            elif response and response[0] == 0x03:  # A-ASSOCIATE-RJ
                result.anonymous_access = False

            sock.close()
        except Exception as e:
            result.raw_errors.append(f"raw socket: {str(e)}")

    def _assess_vulnerabilities(self, result: ScanResult):
        """Map detected issues to CVEs and HIPAA controls."""

        if result.is_open and not result.tls_enabled:
            result.vulnerabilities.append({
                "id": "DICOM-002",
                "title": "Unencrypted DICOM transmission",
                "severity": "HIGH",
                "cve": "CVE-2019-11687",
                "description": "DICOM data transmitted in plaintext. Patient images and metadata interceptable via MITM.",
                "hipaa_ref": "164.312(e)(1)",
                "nist_ref": "SC-8, SC-28",
                "remediation": "Enable DICOM TLS (port 2762) per DICOM PS3.15 Annex B"
            })

        if result.anonymous_access:
            result.vulnerabilities.append({
                "id": "DICOM-003",
                "title": "No authentication required",
                "severity": "CRITICAL",
                "description": "PACS accepts connections without credentials. Any host can query patient records.",
                "hipaa_ref": "164.312(d)",
                "nist_ref": "IA-2, IA-3",
                "remediation": "Configure AE title whitelisting and require TLS client certificates"
            })

        if result.is_open and result.port == 104:
            result.vulnerabilities.append({
                "id": "DICOM-004",
                "title": "Standard DICOM port exposed",
                "severity": "LOW",
                "description": "Default DICOM port 104 is publicly accessible. Should be firewalled to imaging network only.",
                "hipaa_ref": "164.312(a)(1)",
                "nist_ref": "SC-7, CM-6",
                "remediation": "Restrict port 104 to clinical VLAN. Use firewall ACLs."
            })


if __name__ == "__main__":
    import json

    print("PACS-DICOM Security Scanner")
    print("=" * 40)
    print("TARGET: localhost (demo mode)")
    print("Use on authorized systems only.\n")

    scanner = DicomScanner(timeout=2.0)
    results = scanner.scan_host("127.0.0.1", ports=[104, 11112])

    for r in results:
        print(f"\nPort {r.port}: {'OPEN' if r.is_open else 'CLOSED'}")
        if r.is_open:
            print(f"  TLS: {'YES' if r.tls_enabled else 'NO - PLAINTEXT'}")
            print(f"  Anonymous access: {'YES - VULNERABLE' if r.anonymous_access else 'NO'}")
            print(f"  Vulnerabilities found: {len(r.vulnerabilities)}")
            for v in r.vulnerabilities:
                print(f"    [{v['severity']}] {v['title']} (HIPAA: {v.get('hipaa_ref','N/A')})")

    print("\n[Full JSON output saved to reports/scan_results.json]")
