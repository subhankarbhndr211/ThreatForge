# ThreatForge 🛡️

**Advanced Threat Detection, Analysis & SOC Automation Lab**

---

## 📌 Overview

ThreatForge is an enterprise-grade Security Operations Center (SOC) platform and cybersecurity detection lab designed for SOC Analysts, Threat Hunters, and Security Engineers.

It focuses on:
- Real-world attack detection
- SIEM & EDR correlation rules
- Malware & network traffic analysis
- Threat hunting scenarios
- Incident response playbooks
- AI-powered autonomous triage

This repository simulates real SOC Level 2+ operations and demonstrates practical detection engineering skills.

## 🎯 Objectives

- Build production-ready detection rules
- Simulate real cyber attacks (APT / malware / phishing)
- Improve SOC triage & incident response
- Create a threat hunting knowledge base
- Develop automation-ready security workflows
- AI-powered autonomous threat investigation

---

## 🧠 Key Features

### 🔍 Packet Analysis & Network Detection
- **Deep PCAP Parsing** - Client-side pure JS parser for .pcap/.pcapng/.cap files
- **Protocol Decoding** - Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS, QUIC, SSH, SMB, RDP, FTP, SMTP
- **TCP Stream Reassembly** - Reconstruct and analyze TCP conversations
- **Hex Dump View** - Wireshark-style packet hex display
- **C2 Detection** - Detect known RAT ports (7492, 10042, 4444, etc.)
- **Beaconing Detection** - Identify C2 beacon patterns
- **Malicious Payload Analysis** - Pattern-based malware detection

### 🧬 Threat Hunting & Detection Engineering
- **MITRE ATT&CK Mapping** - Map detections to ATT&CK techniques
- **IOC & behavioral detection** - Domain generation, DNS tunneling, suspicious TLS
- **Threat actor simulation** - APT-style attack scenarios
- **PowerShell attack detection** - Fileless attack detection
- **LOLBins & fileless attack detection**
- **Privilege escalation & lateral movement detection**

### 🚨 Incident Response & SIEM
- **Windows Event Log detections** - 4624, 4688, 4672
- **Correlation rules** - Multi-stage attack detection
- **Incident Response Playbooks**:
  - Ransomware response
  - Phishing investigation
  - Endpoint compromise handling
  - Cloud security incident response (AWS/Azure)

### 🤖 AI Triage & Automation (v7.0)
- **Autonomous Investigation** - Auto-analyze IOCs with VT & AbuseIPDB
- **Risk Scoring** - Calculate risk scores for each IP/endpoint
- **Recommendations** - Context-aware remediation actions
- **Auto alert triage** - AI-based threat classification
- **Export Reports** - JSON, Markdown, CSV formats

### 🐞 CVE & Threat Intelligence
- **CVE Database** - Auto-ingestion from NVD (National Vulnerability Database)
- **CVE Analysis** - AI-powered CVE analysis with detection rules
- **EPSS Scoring** - Exploit Prediction Scoring System integration
- **KEV Integration** - CISA Known Exploited Vulnerabilities catalog
- **CVSS Analysis** - Severity scoring and vulnerability prioritization
- **MITRE ATT&CK Mapping** - Map CVEs to ATT&CK techniques
- **Search & Filter** - Search CVEs by keyword, severity, date

### 🎣 Phishing Analysis
- **Email Parsing** - Extract IOCs from .eml/.msg files
- **IOC Extraction** - URLs, IPs, domains, hashes
- **Typosquatting Detection** - Impersonation detection
- **Safe Sandbox** - Client-side analysis only (no auto-execution)

---

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start the server
node server/server.js

# Open in browser
http://localhost:3001
```

### Python Services (Optional)

```bash
# Install Python dependencies
cd packet-engine
pip install -r requirements.txt

# Start AI service
cd ai-service
pip install -r requirements.txt
python zeroday_ai.py
```

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure:

```env
# Database (PostgreSQL)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=threatforge_soc
DB_USER=postgres
DB_PASSWORD=your_password

# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
GREYNOISE_API_KEY=your_key
PORTAL_API_KEY=your_key

# Server Configuration
PORT=3001
NODE_ENV=development
```

**Database Setup** (PostgreSQL):
```sql
CREATE DATABASE threatforge_soc;
-- The app will auto-create tables on startup
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Frontend** | Vanilla JS, HTML, CSS |
| **Backend** | Node.js, Express |
| **Database** | PostgreSQL (CVE storage, IOC data) |
| **Packet Engine** | Python (Scapy, PyShark) |
| **AI/ML Service** | Python (TensorFlow, Scikit-learn) |
| **CVE Source** | NVD API, CISA KEV, First.org EPSS |
| **Deployment** | Docker, Kubernetes |

---

## 📁 Project Structure

```
ThreatForge/
├── public/                  # Frontend UI (Single Page App)
│   ├── index.html          # Main application
│   ├── js/                 # Client-side scripts
│   │   └── packet-parser.js
│   └── static/            # CSS, assets
├── server/                 # Express backend
│   ├── routes/            # API endpoints
│   │   ├── packet.js      # Packet analysis routes
│   │   ├── phishing.js    # Phishing analysis
│   │   ├── ioc.js         # IOC enrichment
│   │   └── mitre.js       # MITRE ATT&CK
│   ├── services/          # Background services
│   │   ├── cveIngestion.js
│   │   └── feedEngine.js
│   └── packet/            # Packet processing modules
├── packet-engine/         # Python packet analyzers
│   ├── packet_analyzer.py
│   ├── deep_analyzer.py
│   └── live_monitor.py
├── ai-service/            # Python AI service
│   └── zeroday_ai.py
├── tests/                 # Test files
├── k8s/                   # Kubernetes configs
└── docs/                  # API documentation
```

---

## 🐳 Docker (Optional)

```bash
# Build image
docker build -t threatforge .

# Run container
docker run -p 3001:3001 threatforge

# Or use docker-compose
docker-compose up -d
```

---

## 📊 Supported Detection Categories

| Category | Examples |
|----------|----------|
| **RAT/C2** | njRAT, AsyncRAT, Metasploit (ports 7492, 4444, etc.) |
| **Beaconing** | Regular interval C2 communication patterns |
| **DNS Tunneling** | Long domain names, fast-flux detection |
| **Phishing** | Email impersonation, typosquatting, malicious URLs |
| **Fileless Attacks** | PowerShell encoded commands, WMI abuse |
| **Deprecated TLS** | TLSv1.0/1.1 used by malware |

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 📜 License

MIT License

---

**Version**: 7.0  
**Author**: Subhankar Bhandari  
**GitHub**: https://github.com/subhankarbhndr211/ThreatForge