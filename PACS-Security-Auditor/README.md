# PACS-DICOM Security Auditor

**Portfolio project for Cybersecurity Analyst / Jr Penetration Tester roles**  
Demonstrates: Recon → Exploitation → Compliance Mapping → Reporting

> ⚠️ **AUTHORIZED TESTING ONLY** — all scanning restricted to private/loopback IPs.
> Never run against systems you do not own or have explicit written permission to test.

---

## What This Project Demonstrates

| Skill | How it's shown |
|---|---|
| DICOM protocol knowledge | pynetdicom C-ECHO, C-FIND, A-ASSOCIATE |
| Network reconnaissance | Port scanning, service fingerprinting, TLS detection |
| Exploitation techniques | AE title bypass, anonymous C-FIND, wildcard enumeration |
| Healthcare compliance | HIPAA 164.312 gap analysis, NIST control mapping |
| Full-stack development | FastAPI backend + React-style dashboard |
| Lab setup | Docker Compose with DCM4CHEE target |
| Testing discipline | pytest unit tests for all modules |

---

## Project Structure

```
pacs-security-auditor/
├── backend/
│   ├── scanner/
│   │   ├── dicom_scanner.py       # Port scan, TLS check, anon-access probe
│   │   └── dicom_exploiter.py     # C-FIND, AE bypass, tag injection tests
│   ├── compliance/
│   │   └── hipaa_mapper.py        # Maps vulns → HIPAA 164.312 controls
│   ├── api/
│   │   └── main.py                # FastAPI REST API
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   └── index.html                 # Full security dashboard (single file)
├── docker/
│   ├── docker-compose.yml         # DCM4CHEE + Orthanc lab targets
│   └── orthanc.json               # Orthanc config (insecure, for training)
├── tests/
│   └── test_scanner.py            # 16 pytest unit tests
└── README.md
```

---

## Quick Start

### Option A: Dashboard only (no Docker needed)
```bash
# Just open the dashboard in your browser
open frontend/index.html
```

### Option B: Full lab with live PACS target
```bash
# 1. Start the lab (DCM4CHEE + Orthanc + Auditor API)
cd docker
docker compose up -d

# 2. Wait ~60 seconds for DCM4CHEE to initialize, then:
# Dashboard: http://localhost:8080  (DCM4CHEE)
# Auditor API: http://localhost:8000
# API docs: http://localhost:8000/docs
# Demo report: http://localhost:8000/demo

# 3. Run a scan via API
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"host": "172.20.0.1", "run_exploits": true}'
```

### Option C: Python scanner only
```bash
cd backend
pip install -r requirements.txt

# Run scanner directly
python scanner/dicom_scanner.py

# Run exploiter
python scanner/dicom_exploiter.py

# Run compliance demo
python compliance/hipaa_mapper.py

# Start API server
uvicorn api.main:app --reload --port 8000
```

### Run tests
```bash
cd backend
pip install pytest
pytest ../tests/test_scanner.py -v
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/scan` | Start async DICOM security scan |
| GET | `/scan/{job_id}` | Poll scan progress and results |
| GET | `/demo` | Pre-built demo report (no target needed) |
| GET | `/history` | Past scan history |
| GET | `/vulnerabilities/reference` | DICOM vulnerability reference DB |
| GET | `/docs` | Interactive API documentation |

---

## Vulnerability Coverage

| ID | Title | Severity | HIPAA | CVE |
|---|---|---|---|---|
| DICOM-001 | Anonymous C-ECHO accepted | MEDIUM | 164.312(d) | — |
| DICOM-002 | Unencrypted DICOM transmission | HIGH | 164.312(e)(1) | CVE-2019-11687 |
| DICOM-003 | No authentication required | CRITICAL | 164.312(d) | — |
| DICOM-004 | Default DICOM port exposed | LOW | 164.312(a)(1) | — |
| EXPLOIT-CFIND | PHI exposed via C-FIND | CRITICAL | 164.312(a)(1) | — |
| EXPLOIT-AETITLE | AE title bypass | HIGH | 164.312(d) | — |

---

## HIPAA Controls Checked

All 7 Technical Safeguards under **45 CFR § 164.312**:

- `164.312(a)(1)` — Access Control *(Required)*
- `164.312(a)(2)(i)` — Unique User Identification *(Required)*
- `164.312(b)` — Audit Controls *(Required)*
- `164.312(c)(1)` — Integrity *(Required)*
- `164.312(d)` — Person/Entity Authentication *(Required)*
- `164.312(e)(1)` — Transmission Security *(Required)*
- `164.514(b)` — De-identification of PHI *(Required)*

---

## Talking Points for Interviews

1. **"Walk me through your methodology"** → Recon (port scan + service fingerprint) → Vulnerability identification (TLS check, anon access) → Exploitation (C-FIND, AE bypass) → Compliance mapping → Report

2. **"What is DICOM and why is it a security concern?"** → Healthcare imaging protocol, typically no auth, plaintext by default, carries PHI. Legacy design predates modern security.

3. **"How does AE title bypass work?"** → DICOM uses Application Entity titles as identifiers, not auth. By spoofing a common title (ANY-SCP, DCM4CHEE), an attacker gains access to an improperly configured PACS.

4. **"What HIPAA violations did you find?"** → 164.312(e)(1) transmission security (no TLS), 164.312(d) authentication (anonymous access), 164.312(b) audit controls missing.

5. **"How would you remediate?"** → DICOM TLS on port 2762, X.509 client certificates, AE title whitelisting, network segmentation to clinical VLAN, SIEM integration for audit trail.

---

## References

- [DICOM Standard PS3.15 — Security Profiles](https://www.dicomstandard.org/current)
- [NEMA DICOM Security Guidelines](https://www.nema.org)
- [HIPAA Security Rule — 45 CFR Part 164](https://www.hhs.gov/hipaa)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [DCM4CHEE Documentation](https://dcm4che.org)
- [pynetdicom](https://pydicom.github.io/pynetdicom/)
