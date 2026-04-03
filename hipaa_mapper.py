"""
HIPAA Compliance Mapper
Maps discovered DICOM vulnerabilities to HIPAA Security Rule controls
and generates gap analysis reports
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
import json


@dataclass
class HipaaControl:
    section: str
    title: str
    requirement_type: str  # "Required" or "Addressable"
    description: str
    status: str = "UNKNOWN"  # PASS / FAIL / PARTIAL / UNKNOWN
    findings: list = field(default_factory=list)
    remediation: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# HIPAA Security Rule - Technical Safeguards (45 CFR § 164.312)
HIPAA_CONTROLS = {
    "164.312(a)(1)": HipaaControl(
        section="164.312(a)(1)",
        title="Access Control",
        requirement_type="Required",
        description="Implement technical policies to allow only authorized persons to access ePHI.",
        remediation=[
            "Implement AE title whitelisting on PACS",
            "Require client certificate authentication for DICOM connections",
            "Deploy network segmentation — DICOM services on clinical VLAN only",
            "Use role-based access control (RBAC) in DCM4CHEE"
        ]
    ),
    "164.312(a)(2)(i)": HipaaControl(
        section="164.312(a)(2)(i)",
        title="Unique User Identification",
        requirement_type="Required",
        description="Assign a unique name and/or number for identifying and tracking user identity.",
        remediation=[
            "Disable shared/generic DICOM AE titles",
            "Assign unique AE titles per workstation",
            "Integrate PACS with Active Directory or LDAP"
        ]
    ),
    "164.312(b)": HipaaControl(
        section="164.312(b)",
        title="Audit Controls",
        requirement_type="Required",
        description="Implement hardware, software, and/or procedural mechanisms to record and examine activity in systems that contain or use ePHI.",
        remediation=[
            "Enable DCM4CHEE audit logging (DICOM Audit Trail)",
            "Ship DICOM audit events to SIEM (Splunk/ELK)",
            "Log all C-FIND, C-STORE, C-MOVE operations",
            "Retain audit logs for minimum 6 years per HIPAA"
        ]
    ),
    "164.312(c)(1)": HipaaControl(
        section="164.312(c)(1)",
        title="Integrity",
        requirement_type="Required",
        description="Implement policies to protect ePHI from improper alteration or destruction.",
        remediation=[
            "Enable DICOM file integrity verification (SHA-256 checksums)",
            "Implement write-once storage for DICOM archives",
            "Deploy DICOM data validation on ingest",
            "Monitor for unauthorized DICOM C-STORE operations"
        ]
    ),
    "164.312(d)": HipaaControl(
        section="164.312(d)",
        title="Person or Entity Authentication",
        requirement_type="Required",
        description="Implement procedures to verify that a person or entity seeking access to ePHI is who they claim to be.",
        remediation=[
            "Require TLS mutual authentication for DICOM connections",
            "Implement DICOM TLS with X.509 certificates",
            "Enable DCM4CHEE user authentication",
            "Deploy multi-factor authentication for PACS admin console"
        ]
    ),
    "164.312(e)(1)": HipaaControl(
        section="164.312(e)(1)",
        title="Transmission Security",
        requirement_type="Required",
        description="Implement technical security measures to guard against unauthorized access to ePHI transmitted over electronic communications networks.",
        remediation=[
            "Enable DICOM TLS on port 2762 (DICOM TLS standard port)",
            "Disable plain DICOM on port 104 on production systems",
            "Use VPN for DICOM transmission between facilities",
            "Implement certificate pinning for DICOM TLS connections",
            "Enforce TLS 1.2+ only (disable TLS 1.0, 1.1, SSL 3.0)"
        ]
    ),
    "164.514(b)": HipaaControl(
        section="164.514(b)",
        title="De-identification of PHI",
        requirement_type="Required",
        description="Remove 18 Safe Harbor identifiers from DICOM datasets before research or secondary use.",
        remediation=[
            "Implement DICOM de-identification pipeline before research exports",
            "Use dcm4che de-identification tool or pydicom anonymizer",
            "Validate de-identification against DICOM PS3.15 Appendix E",
            "Audit C-FIND responses — ensure PHI not returned to unauthorized systems"
        ]
    ),
}

# Vulnerability ID to HIPAA control mapping
VULN_TO_HIPAA = {
    "DICOM-001": ["164.312(d)", "164.312(a)(1)"],
    "DICOM-002": ["164.312(e)(1)"],
    "DICOM-003": ["164.312(d)", "164.312(a)(1)", "164.312(a)(2)(i)"],
    "DICOM-004": ["164.312(a)(1)"],
    "DICOM-TAG-INJECT": ["164.312(c)(1)"],
    "DICOM-AUDIT": ["164.312(b)"],
    "DICOM-PHI": ["164.514(b)"],
}

SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 8,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 1
}


@dataclass
class ComplianceReport:
    target: str
    scan_date: str = field(default_factory=lambda: datetime.now().isoformat())
    controls: dict = field(default_factory=dict)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    compliance_score: float = 0.0
    risk_rating: str = ""
    executive_summary: str = ""

    def to_dict(self):
        return {
            "target": self.target,
            "scan_date": self.scan_date,
            "controls": {k: v.to_dict() for k, v in self.controls.items()},
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "compliance_score": self.compliance_score,
            "risk_rating": self.risk_rating,
            "executive_summary": self.executive_summary
        }


class HipaaMapper:
    """Maps scan/exploit results to HIPAA compliance gaps."""

    def generate_report(self, target: str, scan_results: list, exploit_results: list) -> ComplianceReport:
        """Generate full HIPAA gap analysis from scan findings."""
        report = ComplianceReport(target=target)

        # Clone controls for this report
        import copy
        report.controls = copy.deepcopy(HIPAA_CONTROLS)

        # Collect all vulnerabilities
        all_vulns = []
        for scan in scan_results:
            if hasattr(scan, 'vulnerabilities'):
                all_vulns.extend(scan.vulnerabilities)
            elif isinstance(scan, dict) and 'vulnerabilities' in scan:
                all_vulns.extend(scan['vulnerabilities'])

        for exploit in exploit_results:
            if hasattr(exploit, 'success') and exploit.success:
                synthetic_vuln = {
                    "id": f"EXPLOIT-{exploit.test_name.replace(' ','-').upper()[:20]}",
                    "title": exploit.test_name,
                    "severity": exploit.severity,
                    "description": exploit.finding,
                    "hipaa_ref": exploit.hipaa_ref
                }
                all_vulns.append(synthetic_vuln)

        # Map vulnerabilities to HIPAA controls
        for vuln in all_vulns:
            severity = vuln.get("severity", "LOW")
            hipaa_refs = vuln.get("hipaa_ref", "")

            # Count by severity
            if severity == "CRITICAL":
                report.critical_count += 1
            elif severity == "HIGH":
                report.high_count += 1
            elif severity == "MEDIUM":
                report.medium_count += 1
            else:
                report.low_count += 1

            report.total_vulnerabilities += 1

            # Update affected controls
            refs = [r.strip() for r in hipaa_refs.split(",") if r.strip()]
            for ref in refs:
                if ref in report.controls:
                    control = report.controls[ref]
                    control.status = "FAIL"
                    control.findings.append({
                        "vuln_id": vuln.get("id", ""),
                        "title": vuln.get("title", ""),
                        "severity": severity,
                        "description": vuln.get("description", "")[:200]
                    })

        # Mark controls with no findings as PASS
        for control in report.controls.values():
            if control.status == "UNKNOWN":
                control.status = "PASS"

        # Calculate compliance score
        total = len(report.controls)
        passing = sum(1 for c in report.controls.values() if c.status == "PASS")
        report.compliance_score = round((passing / total) * 100, 1) if total > 0 else 0

        # Risk rating
        if report.critical_count > 0:
            report.risk_rating = "CRITICAL"
        elif report.high_count >= 2:
            report.risk_rating = "HIGH"
        elif report.high_count == 1 or report.medium_count >= 3:
            report.risk_rating = "MEDIUM"
        else:
            report.risk_rating = "LOW"

        # Executive summary
        report.executive_summary = self._generate_summary(report)

        return report

    def _generate_summary(self, report: ComplianceReport) -> str:
        failing = [c for c in report.controls.values() if c.status == "FAIL"]
        return (
            f"Security assessment of {report.target} identified {report.total_vulnerabilities} vulnerabilities "
            f"({report.critical_count} Critical, {report.high_count} High, {report.medium_count} Medium, {report.low_count} Low). "
            f"HIPAA compliance score: {report.compliance_score}%. "
            f"{len(failing)} of {len(report.controls)} required Technical Safeguard controls are failing. "
            f"Overall risk rating: {report.risk_rating}. "
            f"Immediate remediation required for transmission security (164.312(e)(1)) and "
            f"access control (164.312(d)) deficiencies."
        )


# Demo mode: simulate a vulnerable PACS scan
def demo_report(target: str = "192.168.1.100") -> ComplianceReport:
    """Generate a realistic demo compliance report."""

    # Simulated scan results
    demo_vulns = [
        {
            "id": "DICOM-002",
            "title": "Unencrypted DICOM transmission",
            "severity": "HIGH",
            "description": "DICOM traffic on port 104 is plaintext. Patient images interceptable.",
            "hipaa_ref": "164.312(e)(1)"
        },
        {
            "id": "DICOM-003",
            "title": "No authentication required",
            "severity": "CRITICAL",
            "description": "PACS accepts anonymous connections and returns patient data.",
            "hipaa_ref": "164.312(d), 164.312(a)(1)"
        },
        {
            "id": "DICOM-004",
            "title": "Default DICOM port exposed",
            "severity": "LOW",
            "description": "Port 104 accessible from untrusted network segments.",
            "hipaa_ref": "164.312(a)(1)"
        },
        {
            "id": "DICOM-AUDIT",
            "title": "Insufficient audit logging",
            "severity": "HIGH",
            "description": "DICOM operations not logged. Unable to detect unauthorized PHI access.",
            "hipaa_ref": "164.312(b)"
        }
    ]

    class MockScanResult:
        def __init__(self, vulns):
            self.vulnerabilities = vulns

    class MockExploitResult:
        def __init__(self):
            self.success = True
            self.test_name = "Anonymous C-FIND Patient Query"
            self.severity = "CRITICAL"
            self.finding = "Retrieved 247 patient records without authentication."
            self.hipaa_ref = "164.312(a)(1), 164.312(d)"

    mapper = HipaaMapper()
    return mapper.generate_report(
        target,
        [MockScanResult(demo_vulns)],
        [MockExploitResult()]
    )


if __name__ == "__main__":
    report = demo_report("192.168.1.100")
    print(f"HIPAA Compliance Report: {report.target}")
    print(f"Score: {report.compliance_score}%  |  Risk: {report.risk_rating}")
    print(f"\nSummary: {report.executive_summary}")
    print(f"\nFailing Controls:")
    for ctrl in report.controls.values():
        if ctrl.status == "FAIL":
            print(f"  [{ctrl.section}] {ctrl.title} — {len(ctrl.findings)} finding(s)")
