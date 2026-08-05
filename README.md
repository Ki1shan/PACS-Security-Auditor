# 🏥 PACS Security Auditor

![Python](https://img.shields.io/badge/python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/fastapi-0.100+-green)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Protocol](https://img.shields.io/badge/protocol-DICOM-blueviolet)
![Compliance](https://img.shields.io/badge/compliance-HIPAA-red)

> Full-stack DICOM/PACS security auditing platform with exploitation simulation, HIPAA compliance mapping, and a real-time web dashboard — built for healthcare cybersecurity research.

---

## ⚠️ Disclaimer

This tool is intended **ONLY** for:

- Authorized penetration testing of healthcare infrastructure
- Security research in controlled lab environments
- HIPAA compliance auditing with written authorization
- Educational and training purposes

**All testing was performed in a controlled Docker lab environment using DCM4CHEE and Orthanc. No real-world patient systems were targeted. Unauthorized use against production systems is strictly prohibited.**

---

## Overview

PACS (Picture Archiving and Communication System) servers are among the most commonly misconfigured systems in healthcare infrastructure. Thousands of DICOM servers are exposed on the internet with no authentication, leaking patient PHI to anyone who connects.

PACS Security Auditor is a full-stack platform that:

- **Scans** DICOM services across standard ports (104, 11112, 2762, 2761, 4006)
- **Fingerprints** PACS servers — AE titles, TLS status, anonymous access
- **Exploits** access control weaknesses — AE title bypass, anonymous C-FIND, wildcard patient enumeration, tag injection, PHI exposure
- **Maps** every finding to specific **HIPAA Security Rule controls** (45 CFR § 164.312)
- **Scores** compliance and generates executive-level risk reports
- **Visualizes** everything in a real-time web dashboard

---

## Images 

<img width="1919" height="914" alt="image" src="https://github.com/user-attachments/assets/56b8344b-27fb-416f-b12d-d963625d54d6" />

---
## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    PACS SECURITY AUDITOR                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                   WEB DASHBOARD (index.html)               │ │
│  │         Real-time scan results, compliance visualizations   │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              FASTAPI BACKEND (main.py)                     │ │
│  │   Async job execution, scan history, demo endpoint         │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│            ┌─────────────────┼──────────────────┐               │
│            ▼                 ▼                  ▼               │
│  ┌──────────────────┐ ┌──────────────┐ ┌──────────────────────┐ │
│  │  DICOM SCANNER   │ │   EXPLOITER  │ │   HIPAA MAPPER       │ │
│  │  dicom_scanner.py│ │ dicom_exp... │ │  hipaa_mapper.py     │ │
│  │                  │ │              │ │                      │ │
│  │  - Port scanning │ │  - AE bypass │ │  - Control mapping   │ │
│  │  - TLS check     │ │  - C-FIND    │ │  - Gap analysis      │ │
│  │  - DICOM assoc   │ │  - Wildcard  │ │  - Compliance score  │ │
│  │  - Vuln assess   │ │  - Tag inject│ │  - Risk rating       │ │
│  │  - CVE mapping   │ │  - PHI audit │ │  - Exec summary      │ │
│  └──────────────────┘ └──────────────┘ └──────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                   DOCKER LAB ENVIRONMENT                   │ │
│  │   DCM4CHEE (target) + Orthanc + PostgreSQL + tcpdump       │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## Features

### 🔍 DICOM Reconnaissance & Scanning (`dicom_scanner.py`)
- TCP port discovery across standard DICOM ports (104, 11112, 2762, 2761, 4006)
- TLS/SSL detection — identifies plaintext DICOM transmissions
- Anonymous DICOM association via pynetdicom (C-ECHO probe)
- Raw socket fallback when pynetdicom is unavailable
- AE title fingerprinting and implementation version extraction
- Automatic CVE mapping (e.g. CVE-2019-11687 for unencrypted DICOM)
- NIST control mapping (SC-8, SC-28, IA-2, IA-3, SC-7, CM-6)

### 💀 Exploitation Simulation (`dicom_exploiter.py`)
- **AE Title Bypass** — iterates 16 common AE titles to test access control
- **Anonymous C-FIND** — queries patient database without credentials (most common real-world DICOM attack)
- **Wildcard Patient Enumeration** — dumps entire study list via wildcard query
- **DICOM Tag Injection** — crafts oversized strings, SQL payloads, XSS, null bytes in DICOM metadata fields
- **PHI Exposure Audit** — identifies all 18 HIPAA Safe Harbor identifiers returned unmasked in C-FIND responses

### 📊 HIPAA Compliance Mapping (`hipaa_mapper.py`)
Full mapping to 45 CFR § 164.312 Technical Safeguards:

| HIPAA Control | Title | Type |
|--------------|-------|------|
| 164.312(a)(1) | Access Control | Required |
| 164.312(a)(2)(i) | Unique User Identification | Required |
| 164.312(b) | Audit Controls | Required |
| 164.312(c)(1) | Integrity | Required |
| 164.312(d) | Person or Entity Authentication | Required |
| 164.312(e)(1) | Transmission Security | Required |
| 164.514(b) | De-identification of PHI | Required |

- Per-control PASS/FAIL/PARTIAL status
- Compliance score (0-100%)
- Risk rating: CRITICAL / HIGH / MEDIUM / LOW
- Detailed remediation guidance per failing control
- Executive summary generation

### 🌐 FastAPI Backend (`main.py`)
- Async background scan jobs with progress tracking
- Input validation — restricts scans to private/loopback IPs for safety
- `/scan` — start async scan job
- `/scan/{job_id}` — poll job status and results
- `/demo` — pre-built demo report (no live target needed)
- `/history` — scan history log
- `/vulnerabilities/reference` — DICOM vulnerability reference database

### 🐳 Docker Lab Environment (`docker-compose.yml`)
- **DCM4CHEE** — intentionally misconfigured PACS target (no TLS, anonymous access enabled)
- **Orthanc** — secondary PACS target for comparison testing
- **PostgreSQL** — PACS database backend
- **tcpdump capture** — proves DICOM traffic is plaintext (`.pcap` output)
- **Keycloak** — optional OIDC identity provider (commented out, for advanced testing)

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, FastAPI, uvicorn |
| Frontend | HTML, JavaScript |
| DICOM Protocol | pynetdicom, pydicom |
| Lab Environment | Docker, DCM4CHEE, Orthanc |
| Database | PostgreSQL |
| Traffic Analysis | tcpdump / Wireshark |
| Compliance | HIPAA 45 CFR § 164.312 |

---

## Installation

**Clone the repository:**
```bash
git clone https://github.com/Ki1shan/PACS-Security-Auditor.git
cd PACS-Security-Auditor
```

**Install dependencies:**
```bash
pip install fastapi uvicorn pynetdicom pydicom pydantic
```

---

## Usage

### Option 1 — Docker Lab (Recommended)

Spin up the full lab environment with one command:
```bash
docker compose up -d
```

This starts:
- DCM4CHEE PACS on port 104 (intentionally vulnerable)
- Orthanc PACS on port 4242
- Security Auditor API on port 8000
- PostgreSQL backend

**Start the API:**
```bash
python main.py
# API runs at http://localhost:8000
```

**View the dashboard:**
```
Open index.html in your browser
```

### Option 2 — Demo Mode (No Live Target)

Hit the `/demo` endpoint for a pre-built realistic report without any live PACS:
```bash
curl http://localhost:8000/demo
```

Returns a full scan + exploit + HIPAA compliance report against a simulated vulnerable DCM4CHEE instance.

### Option 3 — API Scan

**Start a scan:**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "192.168.1.100", "run_exploits": true}'
```

**Poll for results:**
```bash
curl http://localhost:8000/scan/{job_id}
```

**Enable traffic capture (proves plaintext DICOM):**
```bash
docker compose --profile capture up -d
# PCAP saved to ./captures/dicom_traffic.pcap
```

---

## Sample Output

**Scan finding:**
```json
{
  "host": "192.168.1.100",
  "port": 104,
  "is_open": true,
  "tls_enabled": false,
  "anonymous_access": true,
  "vulnerabilities": [
    {
      "id": "DICOM-002",
      "title": "Unencrypted DICOM transmission",
      "severity": "HIGH",
      "cve": "CVE-2019-11687",
      "hipaa_ref": "164.312(e)(1)",
      "nist_ref": "SC-8, SC-28",
      "remediation": "Enable DICOM TLS (port 2762) per DICOM PS3.15 Annex B"
    },
    {
      "id": "DICOM-003",
      "title": "No authentication required",
      "severity": "CRITICAL",
      "hipaa_ref": "164.312(d)",
      "nist_ref": "IA-2, IA-3"
    }
  ]
}
```

**HIPAA Compliance Report:**
```json
{
  "compliance_score": 28.6,
  "risk_rating": "CRITICAL",
  "total_vulnerabilities": 5,
  "critical_count": 2,
  "high_count": 2,
  "executive_summary": "Security assessment identified 5 vulnerabilities. 5 of 7 required Technical Safeguard controls are failing. Immediate remediation required."
}
```

---

## Key Security Concepts

- **DICOM Protocol Security** — AE title authentication, C-ECHO, C-FIND, C-STORE, C-MOVE operations
- **PHI Exposure** — 18 HIPAA Safe Harbor identifiers, patient record enumeration
- **TLS in Healthcare** — DICOM TLS (PS3.15 Annex B), port 2762, X.509 certificates
- **Access Control Testing** — AE title whitelisting bypass, anonymous association attacks
- **HIPAA Technical Safeguards** — 45 CFR § 164.312 full control framework
- **CVE Mapping** — CVE-2019-11687 and related DICOM vulnerabilities
- **Network Segmentation** — Clinical VLAN isolation, firewall ACL recommendations

---

## Lab Environment Details

```
DCM4CHEE (pacs.lab.local)
  Port 104   → DICOM plaintext (vulnerable — no TLS)
  Port 2762  → DICOM TLS
  Port 8080  → Web UI
  Port 8443  → HTTPS

Orthanc
  Port 4242  → DICOM
  Port 8042  → REST API

Auditor API
  Port 8000  → FastAPI

Network: 172.20.0.0/16 (isolated bridge)
```

⚠️ The lab is intentionally configured insecurely for training purposes. Never expose to public internet.

---

## Author

**Kishan N**
Offensive Security Engineer | Healthcare Cybersecurity Researcher

Built PACS Security Auditor to address the critically underexplored area of medical imaging infrastructure security — where misconfigured DICOM servers continue to expose patient records at scale.

---

## License

MIT License — see `LICENSE` file for details.

---

*Built for the defenders. Tested in the lab. Never on real patients.*
