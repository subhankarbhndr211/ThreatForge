# ThreatForge v7.0 🛡️

**Advanced SOC Platform with AI-Powered Packet Analysis**

ThreatForge is an enterprise-grade Security Operations Center (SOC) platform featuring advanced packet analysis, threat detection, and autonomous AI triage.

## Features

### 🔍 Packet Analysis
- **Deep PCAP Parsing** - Client-side pure JS parser for .pcap/.pcapng/.cap files
- **Protocol Decoding** - Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP, TLS, QUIC, SSH, SMB, RDP, FTP, SMTP
- **TCP Stream Reassembly** - Reconstruct and analyze TCP conversations
- **Hex Dump View** - Wireshark-style packet hex display

### 🚨 Threat Detection
- **RAT/C2 Detection** - Detect known RAT ports (7492, 10042, 4444, etc.)
- **Beaconing Detection** - Identify C2 beacon patterns
- **Malicious Payload Analysis** - Pattern-based malware detection
- **Deprecated TLS Detection** - Flag outdated TLS versions
- **MITRE ATT&CK Mapping** - Map detections to ATT&CK techniques

### 🤖 AI Triage
- **Autonomous Investigation** - Auto-analyze IOCs with VT & AbuseIPDB
- **Risk Scoring** - Calculate risk scores for each IP
- **Recommendations** - Context-aware remediation actions
- **Export Reports** - JSON, Markdown, CSV formats

### 🎣 Phishing Analysis
- **Email Parsing** - Extract IOCs from .eml/.msg files
- **IOC Extraction** - URLs, IPs, domains, hashes
- **Safe Sandbox** - Client-side analysis only

## Quick Start

```bash
# Install dependencies
npm install

# Start the server
node server/server.js

# Open in browser
http://localhost:3001
```

## Configuration

Copy `.env.example` to `.env` and add your API keys:

```env
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
GREYNOISE_API_KEY=your_key
```

## Tech Stack

- **Frontend**: Vanilla JS, HTML, CSS
- **Backend**: Node.js, Express
- **Packet Engine**: Python (Scapy, PyShark)
- **AI Service**: Python (ML-based threat analysis)

## Project Structure

```
ThreatForge/
├── public/           # Frontend UI
├── server/           # Express backend
│   ├── routes/      # API endpoints
│   ├── services/     # Background services
│   └── packet/       # Packet processing
├── packet-engine/    # Python packet analyzers
├── ai-service/       # Python AI service
├── tests/            # Test files
└── k8s/              # Kubernetes configs
```

## Docker (Optional)

```bash
# Build
docker build -t threatforge .

# Run
docker run -p 3001:3001 threatforge
```

## License

MIT License - See LICENSE file

---

**Version**: 7.0  
**Author**: Subhankar Bhondr