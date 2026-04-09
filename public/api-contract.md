# ThreatForge SOC — Backend API Contract
All data has been removed from the frontend. The server must expose these endpoints.

---

## Base URL
- **With backend running:** `http://localhost:3000` (auto-detected)
- **Same-origin (deployed):** relative paths `/api/...`

---

## Endpoints

### `GET /health`
**Purpose:** Startup probe — must respond for the app to initialize.
```json
{ "status": "ok", "version": "5.0" }
```

---

### `GET /api/queries/status`
**Purpose:** Check if AI query generation is available.
```json
{
  "aiEnabled": true,
  "provider": "openai",
  "engine": "ai"
}
```

---

### `GET /api/actors`
**Purpose:** Threat actor profiles.
```json
[
  {
    "id": "apt28",
    "name": "APT28 / Fancy Bear",
    "icon": "🐻",
    "origin": "Russia",
    "sponsor": "GRU",
    "severity": "CRIT",
    "active": true,
    "motivation": "Espionage",
    "aliases": ["Fancy Bear", "STRONTIUM", "Sofacy"],
    "campaigns": ["SolarWinds", "NotPetya", "DNC Hack 2016"],
    "tools": ["Mimikatz", "X-Agent", "Zebrocy", "CHOPSTICK"],
    "detection_tips": [
      "Monitor for X-Agent C2 traffic on port 443 with unusual certificate patterns",
      "Alert on credential dumping from LSASS followed by lateral movement"
    ],
    "ttps": [
      { "tactic": "Initial Access", "id": "T1566", "name": "Phishing" },
      { "tactic": "Credential Access", "id": "T1003", "name": "OS Credential Dumping" }
    ],
    "hunt_queries": {
      "splunk": "index=* EventCode=4624 Logon_Type=3 | stats count by src_ip, user | where count > 5",
      "sentinel": "SecurityEvent | where EventID == 4624 | where LogonType == 3 | summarize count() by IpAddress, Account"
    }
  }
]
```

---

### `GET /api/mitre`
**Purpose:** MITRE ATT&CK tactics and techniques.
```json
{
  "tactics": [
    { "id": "TA0001", "name": "Initial Access", "icon": "🚪" },
    { "id": "TA0002", "name": "Execution", "icon": "⚡" }
  ],
  "techniques": {
    "TA0001": [
      {
        "id": "T1566",
        "name": "Phishing",
        "sub": ["T1566.001 Spearphishing Attachment", "T1566.002 Spearphishing Link"],
        "detect": "Monitor for suspicious email attachments and macro execution",
        "splunk": "index=* EventCode=1 ParentImage=*OUTLOOK.EXE | stats count by Image, CommandLine",
        "sentinel": "DeviceProcessEvents | where InitiatingProcessFileName =~ 'OUTLOOK.EXE'",
        "severity": "HIGH"
      }
    ]
  }
}
```

---

### `GET /api/logs`
**Purpose:** Log event library by platform.
```json
{
  "library": {
    "windows": {
      "label": "Windows Security",
      "icon": "🪟",
      "categories": {
        "auth": {
          "label": "Authentication Events",
          "source": "Security.evtx",
          "events": [
            {
              "id": "4624",
              "name": "Successful Logon",
              "desc": "An account was successfully logged on",
              "mitre": "T1078",
              "severity": "INFO",
              "threat": "Baseline normal — watch for anomalous hours or source IPs"
            },
            {
              "id": "4625",
              "name": "Failed Logon",
              "desc": "An account failed to log on",
              "mitre": "T1110",
              "severity": "MED",
              "threat": "Brute force indicator when count > 10 from same source"
            }
          ]
        }
      }
    },
    "linux": {
      "label": "Linux / Syslog",
      "icon": "🐧",
      "categories": {
        "auth": {
          "label": "Authentication",
          "source": "/var/log/auth.log",
          "events": [
            {
              "id": "su-fail",
              "name": "su Authentication Failure",
              "desc": "Failed attempt to switch user",
              "mitre": "T1548",
              "severity": "MED",
              "threat": "Privilege escalation attempt"
            }
          ]
        }
      }
    }
  }
}
```

---

### `GET /api/platforms`
**Purpose:** Available SIEM/EDR/Cloud platforms for query builder.
```json
[
  { "id": "splunk",      "label": "Splunk",          "icon": "🔍", "type": "SIEM" },
  { "id": "elastic",     "label": "Elastic",         "icon": "⚡", "type": "SIEM" },
  { "id": "sentinel",    "label": "Sentinel",        "icon": "☁️", "type": "SIEM" },
  { "id": "qradar",      "label": "QRadar",          "icon": "🔷", "type": "SIEM" },
  { "id": "chronicle",   "label": "Chronicle",       "icon": "🌐", "type": "SIEM" },
  { "id": "crowdstrike", "label": "CrowdStrike",     "icon": "🦅", "type": "EDR" },
  { "id": "defender",    "label": "Defender",        "icon": "🛡️", "type": "EDR" },
  { "id": "sentinelone", "label": "SentinelOne",     "icon": "💜", "type": "EDR" },
  { "id": "aws",         "label": "AWS CloudTrail",  "icon": "☁️", "type": "Cloud" },
  { "id": "azure",       "label": "Azure Activity",  "icon": "🌤", "type": "Cloud" },
  { "id": "gcp",         "label": "GCP Audit",       "icon": "🌀", "type": "Cloud" },
  { "id": "firewall",    "label": "Firewall",        "icon": "🔥", "type": "Network" },
  { "id": "zeek",        "label": "Zeek/Bro",        "icon": "🔍", "type": "Network" }
]
```

---

### `GET /api/playbooks`
**Purpose:** Incident response playbook steps.
```json
{
  "playbooks": {
    "ransomware": {
      "label": "Ransomware",
      "icon": "🔒",
      "steps": [
        {
          "title": "Immediate Isolation",
          "desc": "Disconnect affected systems from network immediately. Do NOT shut down — preserve memory for forensics."
        },
        {
          "title": "Scope Assessment",
          "desc": "Identify all encrypted systems. Check shadow copies. Determine patient zero via EDR telemetry."
        }
      ]
    },
    "phishing": {
      "label": "Phishing",
      "icon": "🎣",
      "steps": [
        {
          "title": "Email Triage",
          "desc": "Pull email headers. Identify sender infrastructure. Check all recipients of same campaign."
        }
      ]
    }
  }
}
```

---

### `GET /api/feed`
**Purpose:** Live threat intelligence feed items.
```json
{
  "items": [
    {
      "type": "malware",
      "source": "MalwareBazaar",
      "severity": "HIGH",
      "title": "AgentTesla infostealer detected",
      "value": "a1b2c3d4e5f6...sha256",
      "family": "AgentTesla",
      "firstSeen": "2026-03-13T07:00:00Z"
    },
    {
      "type": "cve",
      "source": "CISA KEV",
      "severity": "CRIT",
      "title": "CVE-2024-3400 — Palo Alto GlobalProtect RCE",
      "value": "CVE-2024-3400",
      "firstSeen": "2026-03-13T06:00:00Z"
    }
  ]
}
```
Feed items: `type` = `malware | ioc | cve | url`

---

### `POST /api/queries/generate`
**Purpose:** Generate detection queries for given context and platforms.

**Request:**
```json
{
  "context": "Detect PowerShell encoded commands from Office applications",
  "tools": ["splunk", "sentinel", "crowdstrike"],
  "severity": "HIGH"
}
```

**Response:**
```json
{
  "queries": [
    {
      "id": "splunk",
      "platform": "Splunk",
      "language": "SPL",
      "icon": "🔍",
      "query": "index=* EventCode=4688\n| where CommandLine matches \"-enc\"\n| stats count by host, user",
      "description": "Detects encoded PowerShell execution",
      "notes": ["Check for base64-encoded payloads", "Correlate with parent process Office apps"]
    }
  ],
  "aiEnabled": true,
  "engine": "ai"
}
```

---

### `POST /api/agent`
**Purpose:** AI chat agent for SOC questions.

**Request:**
```json
{
  "question": "How do I detect lateral movement?",
  "messages": [
    { "role": "user", "content": "prior message" },
    { "role": "assistant", "content": "prior answer" }
  ],
  "context": "dashboard"
}
```

**Response:**
```json
{
  "answer": "Lateral movement can be detected by monitoring Windows Event ID 4624 (Type 3)..."
}
```

---

### `GET /api/misp/status`
```json
{ "connected": true, "url": "https://misp.yourdomain.com", "message": "" }
```

### `GET /api/misp/events`
```json
{ "events": [{ "id": "1", "info": "Cobalt Strike campaign", "date": "2026-03-13", "tags": ["APT"], "attribute_count": 47 }] }
```

### `GET /api/cve/recent`
```json
{ "cves": [{ "id": "CVE-2024-3400", "description": "...", "cvss": 10.0, "severity": "CRITICAL", "published": "2024-04-12" }] }
```

### `GET /api/zeroday`
```json
{ "items": [{ "title": "...", "source": "...", "severity": "CRIT", "published": "..." }] }
```

### `GET /api/enrich/status`
```json
{ "virustotal": true, "abuseipdb": true, "shodan": false }
```

---

## CORS Headers Required
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
```

## Express.js Quickstart
```js
const express = require('express');
const app = express();
app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/actors',    (req, res) => res.json(require('./data/actors.json')));
app.get('/api/mitre',     (req, res) => res.json(require('./data/mitre.json')));
app.get('/api/logs',      (req, res) => res.json(require('./data/logs.json')));
app.get('/api/platforms', (req, res) => res.json(require('./data/platforms.json')));
app.get('/api/playbooks', (req, res) => res.json(require('./data/playbooks.json')));
app.get('/api/feed',      (req, res) => res.json(require('./data/feed.json')));

app.listen(3000, () => console.log('ThreatForge backend running on :3000'));
```
