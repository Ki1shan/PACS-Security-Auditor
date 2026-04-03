"""
Test suite for PACS Security Auditor
Tests run in MOCK MODE — no live DICOM server needed
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from scanner.dicom_scanner import DicomScanner, ScanResult
from compliance.hipaa_mapper import HipaaMapper, demo_report, HIPAA_CONTROLS


class TestDicomScanner:
    """Unit tests for the DICOM scanner module."""

    def test_scan_result_dataclass(self):
        result = ScanResult(host="127.0.0.1", port=104)
        assert result.host == "127.0.0.1"
        assert result.port == 104
        assert result.is_open is False
        assert result.tls_enabled is False
        assert result.vulnerabilities == []

    def test_scan_result_to_dict(self):
        result = ScanResult(host="127.0.0.1", port=104, is_open=True)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["host"] == "127.0.0.1"
        assert d["is_open"] is True

    def test_scanner_initializes(self):
        scanner = DicomScanner(timeout=1.0)
        assert scanner.timeout == 1.0
        assert len(scanner.DICOM_PORTS) >= 4

    def test_closed_port_returns_not_open(self):
        """Port 1 is always closed — confirms scanner handles closed ports."""
        scanner = DicomScanner(timeout=0.5)
        result = scanner._scan_port("127.0.0.1", 1)
        assert result.is_open is False
        assert result.host == "127.0.0.1"
        assert result.port == 1

    def test_vulnerability_structure(self):
        """Vulnerabilities must have required fields."""
        required_fields = {"id", "title", "severity", "description", "hipaa_ref"}
        scanner = DicomScanner()
        mock_result = ScanResult(host="127.0.0.1", port=104, is_open=True, tls_enabled=False)
        scanner._assess_vulnerabilities(mock_result)

        for vuln in mock_result.vulnerabilities:
            for field in required_fields:
                assert field in vuln, f"Vulnerability missing field: {field}"

    def test_no_tls_generates_high_vuln(self):
        """Open port without TLS must generate HIGH vulnerability."""
        scanner = DicomScanner()
        result = ScanResult(host="127.0.0.1", port=104, is_open=True, tls_enabled=False)
        scanner._assess_vulnerabilities(result)

        high_vulns = [v for v in result.vulnerabilities if v["severity"] == "HIGH"]
        tls_vulns = [v for v in result.vulnerabilities if v["id"] == "DICOM-002"]
        assert len(high_vulns) >= 1
        assert len(tls_vulns) == 1

    def test_anonymous_access_generates_critical_vuln(self):
        """Anonymous access must generate CRITICAL vulnerability."""
        scanner = DicomScanner()
        result = ScanResult(
            host="127.0.0.1", port=104,
            is_open=True, tls_enabled=False,
            anonymous_access=True
        )
        scanner._assess_vulnerabilities(result)

        critical_vulns = [v for v in result.vulnerabilities if v["severity"] == "CRITICAL"]
        assert len(critical_vulns) >= 1

    def test_port_104_generates_low_vuln(self):
        """Exposed port 104 should generate LOW severity finding."""
        scanner = DicomScanner()
        result = ScanResult(host="127.0.0.1", port=104, is_open=True)
        scanner._assess_vulnerabilities(result)

        port_vulns = [v for v in result.vulnerabilities if v["id"] == "DICOM-004"]
        assert len(port_vulns) == 1
        assert port_vulns[0]["severity"] == "LOW"

    def test_severity_values_are_valid(self):
        """All severities must be from the allowed set."""
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        scanner = DicomScanner()
        result = ScanResult(
            host="127.0.0.1", port=104,
            is_open=True, tls_enabled=False,
            anonymous_access=True
        )
        scanner._assess_vulnerabilities(result)
        for v in result.vulnerabilities:
            assert v["severity"] in valid_severities


class TestHipaaMapper:
    """Unit tests for HIPAA compliance mapping."""

    def test_all_required_controls_present(self):
        """Must have all 7 HIPAA Technical Safeguard controls."""
        required_sections = [
            "164.312(a)(1)",
            "164.312(a)(2)(i)",
            "164.312(b)",
            "164.312(c)(1)",
            "164.312(d)",
            "164.312(e)(1)",
            "164.514(b)"
        ]
        for section in required_sections:
            assert section in HIPAA_CONTROLS, f"Missing HIPAA control: {section}"

    def test_demo_report_generates(self):
        """Demo report should generate without exceptions."""
        report = demo_report("192.168.1.100")
        assert report is not None
        assert report.target == "192.168.1.100"
        assert report.compliance_score >= 0
        assert report.compliance_score <= 100

    def test_risk_rating_is_valid(self):
        report = demo_report()
        assert report.risk_rating in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_failing_controls_have_findings(self):
        """Every FAIL control must have at least one finding."""
        report = demo_report()
        for ctrl in report.controls.values():
            if ctrl.status == "FAIL":
                assert len(ctrl.findings) >= 1

    def test_compliance_score_decreases_with_vulns(self):
        """More vulnerabilities = lower score."""
        # Clean report (no vulns)
        mapper = HipaaMapper()
        clean = mapper.generate_report("target", [], [])

        # Vulnerable report
        class MockScan:
            vulnerabilities = [
                {"id": "D1", "title": "t", "severity": "CRITICAL",
                 "description": "d", "hipaa_ref": "164.312(d)"},
                {"id": "D2", "title": "t", "severity": "HIGH",
                 "description": "d", "hipaa_ref": "164.312(e)(1)"},
                {"id": "D3", "title": "t", "severity": "HIGH",
                 "description": "d", "hipaa_ref": "164.312(b)"},
            ]

        vuln = mapper.generate_report("target", [MockScan()], [])
        assert vuln.compliance_score < clean.compliance_score

    def test_critical_count_tracked_correctly(self):
        mapper = HipaaMapper()

        class MockScan:
            vulnerabilities = [
                {"id": "D1", "title": "t", "severity": "CRITICAL",
                 "description": "d", "hipaa_ref": "164.312(d)"},
                {"id": "D2", "title": "t", "severity": "CRITICAL",
                 "description": "d", "hipaa_ref": "164.312(e)(1)"},
            ]

        report = mapper.generate_report("target", [MockScan()], [])
        assert report.critical_count == 2

    def test_executive_summary_is_string(self):
        report = demo_report()
        assert isinstance(report.executive_summary, str)
        assert len(report.executive_summary) > 50

    def test_controls_have_remediation_steps(self):
        """Every control must have at least 2 remediation steps."""
        for ctrl in HIPAA_CONTROLS.values():
            assert len(ctrl.remediation) >= 2, f"{ctrl.section} needs more remediation steps"


class TestAPIValidation:
    """Test API input validation logic."""

    def test_private_ip_allowed(self):
        """Private IPs should pass validation."""
        import ipaddress
        private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]
        for ip in private_ips:
            parsed = ipaddress.ip_address(ip)
            assert parsed.is_private or parsed.is_loopback

    def test_public_ip_is_public(self):
        """Public IPs should be flagged."""
        import ipaddress
        public_ips = ["8.8.8.8", "1.1.1.1"]
        for ip in public_ips:
            parsed = ipaddress.ip_address(ip)
            assert not (parsed.is_private or parsed.is_loopback)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
