# 🏥 PACS Security Auditor (DICOM Healthcare Cybersecurity Platform)

## 📌 Overview
PACS Security Auditor is a full-stack cybersecurity platform designed to identify, analyze, and report vulnerabilities in DICOM-based medical imaging systems.  
The project focuses on securing healthcare infrastructure by detecting misconfigurations, unauthorized access, and compliance gaps.

---

## 🚀 Features

- 🔍 DICOM Reconnaissance & Scanning  
  - Detection of open DICOM ports and services  
  - Identification of insecure configurations (TLS disabled, anonymous access)

- 💀 Vulnerability Assessment  
  - AE Title misconfiguration detection  
  - Anonymous C-FIND queries (PHI exposure)  
  - Weak authentication and access control issues  

- ⚡ Exploitation Simulation  
  - DICOM protocol interaction using C-ECHO, C-FIND  
  - Data exposure validation in controlled lab environment  

- 📊 Compliance Mapping  
  - HIPAA (45 CFR 164.312) based risk analysis  
  - Automated mapping of vulnerabilities to compliance controls  

- 🧠 Risk Scoring Engine  
  - Severity classification based on impact  
  - Prioritized remediation suggestions  

- 🌐 Web Dashboard  
  - Interactive UI for vulnerability visualization  
  - Real-time scan results and reports  

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI  
- **Frontend:** HTML, JavaScript  
- **Protocols:** DICOM (pynetdicom)  
- **Environment:** Docker (DCM4CHEE, Orthanc)  
- **Security Tools:** Wireshark, Custom Python Scripts  

---

## ⚙️ Project Architecture
User → Web Interface → FastAPI Backend → Scanner & Exploiter → Compliance Engine → Dashboard

---

## 🧪 Lab Environment

This project was developed and tested in a **controlled lab environment** using:

- DCM4CHEE PACS Server  
- Orthanc PACS Server  
- Docker-based deployment  
- Simulated healthcare network  

⚠️ No real-world systems were targeted.

---

## 🔐 Key Security Concepts Implemented

- DICOM Protocol Security  
- Access Control & Authentication Testing  
- Network Traffic Analysis  
- Healthcare Compliance (HIPAA)  
- Vulnerability Assessment & Reporting  

---

## 📸 Sample Output

- Vulnerability reports with severity  
- PHI exposure detection  
- Compliance risk mapping  
- Interactive dashboard visualization  

---

## 🎯 Learning Outcomes

- Deep understanding of DICOM and PACS security  
- Hands-on experience in healthcare cybersecurity  
- Real-world vulnerability assessment workflow  
- Integration of security with compliance (HIPAA)  

---

## ⚠️ Disclaimer

This project is strictly for **educational and ethical purposes only**.  
All testing was performed in a controlled lab environment.  

---

## 📬 Author

**Kishan N**  
