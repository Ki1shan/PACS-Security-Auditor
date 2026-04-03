"""
PACS Security Auditor - FastAPI Backend
Exposes scan, exploit, and compliance endpoints for the dashboard
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import asyncio
import uuid
import json
import ipaddress
import socket
from datetime import datetime
from typing import Optional

# Internal modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner.dicom_scanner import DicomScanner
from scanner.dicom_exploiter import DicomExploiter
from compliance.hipaa_mapper import HipaaMapper, demo_report

app = FastAPI(
    title="PACS Security Auditor API",
    description="DICOM/PACS penetration testing and HIPAA compliance API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store (use Redis in production)
jobs: dict = {}
scan_history: list = []


class ScanRequest(BaseModel):
    host: str
    ports: Optional[list[int]] = None
    run_exploits: bool = False

    @validator('host')
    def validate_host(cls, v):
        # Allow localhost and private IPs only for safety
        try:
            ip = ipaddress.ip_address(v)
            if not (ip.is_loopback or ip.is_private):
                raise ValueError("Only private/loopback IPs allowed for safety")
        except ValueError as e:
            if 'Only private' in str(e):
                raise
            # Try hostname resolution
            try:
                resolved = socket.gethostbyname(v)
                ip = ipaddress.ip_address(resolved)
                if not (ip.is_loopback or ip.is_private):
                    raise ValueError("Hostname resolves to public IP — use authorized private targets only")
            except socket.gaierror:
                pass  # Allow unresolvable hostnames in demo mode
        return v


class JobStatus(BaseModel):
    job_id: str
    status: str  # pending / running / complete / failed
    progress: int = 0
    result: Optional[dict] = None
    error: Optional[str] = None


async def run_scan_job(job_id: str, request: ScanRequest):
    """Background task: runs full scan pipeline."""
    jobs[job_id]["status"] = "running"
    jobs[job_id]["progress"] = 10

    try:
        scanner = DicomScanner(timeout=3.0)
        scan_results_raw = scanner.scan_host(request.host, request.ports)
        scan_results = [r.to_dict() for r in scan_results_raw]

        jobs[job_id]["progress"] = 40

        exploit_results = []
        exploit_results_raw = []

        if request.run_exploits:
            for result in scan_results_raw:
                if result.is_open:
                    exploiter = DicomExploiter(request.host, result.port)
                    ex_results = exploiter.run_all_tests()
                    exploit_results_raw.extend(ex_results)
                    exploit_results.extend([r.to_dict() for r in ex_results])

        jobs[job_id]["progress"] = 70

        mapper = HipaaMapper()
        compliance = mapper.generate_report(request.host, scan_results_raw, exploit_results_raw)

        jobs[job_id]["progress"] = 100
        jobs[job_id]["status"] = "complete"
        jobs[job_id]["result"] = {
            "scan_results": scan_results,
            "exploit_results": exploit_results,
            "compliance_report": compliance.to_dict(),
            "completed_at": datetime.now().isoformat()
        }

        # Save to history
        scan_history.append({
            "job_id": job_id,
            "target": request.host,
            "timestamp": datetime.now().isoformat(),
            "risk_rating": compliance.risk_rating,
            "compliance_score": compliance.compliance_score,
            "total_vulns": compliance.total_vulnerabilities
        })

    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)


@app.get("/")
def root():
    return {
        "service": "PACS Security Auditor",
        "version": "1.0.0",
        "status": "operational"
    }


@app.post("/scan", response_model=dict)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start an async DICOM security scan."""
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "progress": 0,
        "target": request.host,
        "created_at": datetime.now().isoformat()
    }
    background_tasks.add_task(run_scan_job, job_id, request)
    return {"job_id": job_id, "message": "Scan started"}


@app.get("/scan/{job_id}", response_model=dict)
def get_scan_result(job_id: str):
    """Poll scan job status and results."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/demo")
def get_demo_report():
    """Return a pre-built demo report for development/portfolio."""
    report = demo_report("192.168.1.100")
    return {
        "scan_results": [
            {
                "host": "192.168.1.100",
                "port": 104,
                "is_open": True,
                "service_name": "DICOM",
                "tls_enabled": False,
                "anonymous_access": True,
                "ae_title": "DCM4CHEE",
                "vulnerabilities": [
                    {
                        "id": "DICOM-002",
                        "title": "Unencrypted DICOM transmission",
                        "severity": "HIGH",
                        "hipaa_ref": "164.312(e)(1)"
                    },
                    {
                        "id": "DICOM-003",
                        "title": "No authentication required",
                        "severity": "CRITICAL",
                        "hipaa_ref": "164.312(d)"
                    }
                ]
            },
            {
                "host": "192.168.1.100",
                "port": 11112,
                "is_open": True,
                "service_name": "DICOM",
                "tls_enabled": False,
                "anonymous_access": True,
                "ae_title": "DCM4CHEE",
                "vulnerabilities": [
                    {
                        "id": "DICOM-004",
                        "title": "Default DICOM port exposed",
                        "severity": "LOW",
                        "hipaa_ref": "164.312(a)(1)"
                    }
                ]
            }
        ],
        "exploit_results": [
            {
                "test_name": "Anonymous C-FIND Patient Query",
                "success": True,
                "severity": "CRITICAL",
                "finding": "Retrieved 247 patient records without authentication. Full PHI database is exposed.",
                "hipaa_ref": "164.312(a)(1), 164.312(d)",
                "data_exposed": [
                    {"PatientID": "PT-10021", "PatientName": "DOE^JOHN", "PatientBirthDate": "19681103"},
                    {"PatientID": "PT-10022", "PatientName": "SMITH^JANE", "PatientBirthDate": "19751205"},
                    {"PatientID": "PT-10023", "PatientName": "BROWN^ROBERT", "PatientBirthDate": "19550822"},
                ]
            },
            {
                "test_name": "AE Title Bypass",
                "success": True,
                "severity": "HIGH",
                "finding": "PACS accepted connection with spoofed AE title 'ANY-SCP'",
                "hipaa_ref": "164.312(d)"
            },
            {
                "test_name": "Wildcard Patient Enumeration",
                "success": True,
                "severity": "HIGH",
                "finding": "Wildcard study query returned 500+ studies. Entire PACS study list is enumerable.",
                "hipaa_ref": "164.312(a)(1)"
            }
        ],
        "compliance_report": report.to_dict()
    }


@app.get("/history")
def get_scan_history():
    """Return list of past scans."""
    return scan_history


@app.get("/vulnerabilities/reference")
def get_vuln_reference():
    """Reference database of DICOM vulnerability patterns."""
    return {
        "vulnerabilities": [
            {
                "id": "DICOM-001",
                "title": "Anonymous C-ECHO accepted",
                "severity": "MEDIUM",
                "cve": None,
                "description": "PACS responds to C-ECHO without authentication",
                "hipaa_ref": "164.312(d)"
            },
            {
                "id": "DICOM-002",
                "title": "Unencrypted DICOM transmission",
                "severity": "HIGH",
                "cve": "CVE-2019-11687",
                "description": "DICOM data transmitted in plaintext",
                "hipaa_ref": "164.312(e)(1)"
            },
            {
                "id": "DICOM-003",
                "title": "No authentication required",
                "severity": "CRITICAL",
                "cve": None,
                "description": "PACS accepts connections without credentials",
                "hipaa_ref": "164.312(d)"
            },
            {
                "id": "DICOM-004",
                "title": "Default DICOM port exposed",
                "severity": "LOW",
                "cve": None,
                "description": "Port 104 publicly accessible",
                "hipaa_ref": "164.312(a)(1)"
            }
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
