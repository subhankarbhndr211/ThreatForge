# ThreatForge Enterprise API Documentation

## Overview

ThreatForge Enterprise is an advanced phishing detection and SOC automation platform providing:
- Deep behavioral analysis
- AI-powered classification
- Real-time threat intelligence enrichment
- Automated response capabilities
- Campaign correlation and detection

## Base URL

```
http://localhost:3001/api
```

## Authentication

Currently in open-beta. Authentication will be added in production release.

## Endpoints

### Analyze Email

Submit email content for comprehensive phishing analysis.

**POST** `/analyze`

#### Request Body

```json
{
  "title": "Suspicious Email Analysis",
  "headers": "Full email headers...",
  "content": "Email body content...",
  "attachments": []
}
```

#### Response

```json
{
  "success": true,
  "analysisId": "uuid-string",
  "status": "complete",
  "riskScore": 85,
  "confidence": 92,
  "iocs": {
    "urls": ["https://malicious-site.com/phish"],
    "domains": ["malicious-site.com"],
    "ips": ["192.168.1.1"],
    "hashes": [],
    "emails": []
  },
  "verdicts": [
    {
      "type": "phishing",
      "severity": "high",
      "description": "Credential harvesting attempt detected"
    }
  ],
  "recommendations": [
    {
      "priority": "critical",
      "action": "QUARANTINE",
      "description": "Quarantine the email immediately"
    }
  ],
  "campaign": {
    "id": "campaign:xxx",
    "confidence": 0.85,
    "indicators": []
  },
  "processingTime": 2450
}
```

---

### Upload Email File

Upload .eml, .msg, or .txt file for analysis.

**POST** `/analyze/upload`

#### Request

- Content-Type: `multipart/form-data`
- Field: `file` (the email file)

#### Response

Same as `/analyze` endpoint.

---

### IOC Lookup

Query threat intelligence for a specific indicator.

**GET** `/iocs/lookup`

#### Query Parameters

| Parameter | Type   | Required | Description              |
|-----------|--------|----------|--------------------------|
| type      | string | Yes      | `domain`, `ip`, `url`, `hash` |
| value     | string | Yes      | The indicator value      |

#### Example

```
GET /iocs/lookup?type=domain&value=malicious-site.com
```

#### Response

```json
{
  "success": true,
  "type": "domain",
  "value": "malicious-site.com",
  "result": {
    "indicator": "malicious-site.com",
    "type": "domain",
    "verdicts": {
      "virusTotal": "malicious",
      "otx": "clean"
    },
    "scores": {
      "virusTotal": 85
    },
    "finalVerdict": "malicious",
    "riskLevel": "high",
    "tags": ["phishing", "malware"],
    "sources": ["virusTotal", "otx"]
  }
}
```

---

### Get Campaigns

Retrieve detected phishing campaigns.

**GET** `/campaigns`

#### Response

```json
{
  "success": true,
  "campaigns": [
    {
      "id": "campaign:xxx",
      "confidence": 0.85,
      "indicators": [...],
      "iocCount": {
        "domains": 3,
        "urls": 5,
        "total": 12
      },
      "firstSeen": "2024-01-15T00:00:00Z",
      "lastSeen": "2024-01-16T12:30:00Z",
      "attribution": {
        "target": "amazon",
        "type": "brand_impersonation"
      }
    }
  ],
  "totalIOCs": 45,
  "connections": 120
}
```

---

### Execute Response Action

Execute automated response actions (if enabled).

**POST** `/response/execute`

#### Request Body

```json
{
  "action": "block_domain",
  "targets": ["malicious-domain.com", "phishing-site.net"]
}
```

#### Supported Actions

- `block_domain` - Block domain in DNS sinkhole
- `block_url` - Block URL in proxy/firewall
- `block_ip` - Block IP in firewall

#### Response

```json
{
  "success": true,
  "action": "block_domain",
  "results": [
    {
      "type": "block_domain",
      "target": "malicious-domain.com",
      "status": "simulated",
      "message": "Would block domain in DNS sinkhole"
    }
  ]
}
```

---

### Health Check

Check system health and module status.

**GET** `/health`

#### Response

```json
{
  "success": true,
  "status": "healthy",
  "modules": {
    "detection": { "status": "healthy" },
    "ai": { "status": "healthy" },
    "intel": { "status": "healthy" },
    "automation": { "status": "healthy", "dryRun": true },
    "graph": { "status": "healthy" }
  },
  "uptime": 3600,
  "memory": {
    "rss": 125829120,
    "heapTotal": 62914560,
    "heapUsed": 41943040,
    "external": 2097152
  }
}
```

---

## Risk Scoring

| Score Range | Level    | Recommendation                          |
|-------------|----------|----------------------------------------|
| 0-30        | Low      | Monitor, no immediate action            |
| 31-50       | Medium   | Review, consider blocking              |
| 51-70       | High     | Block sender, alert users              |
| 71-100      | Critical | Quarantine, full investigation         |

## Error Codes

| Code | Description                              |
|------|------------------------------------------|
| 400  | Bad request - invalid parameters          |
| 413  | Payload too large                         |
| 429  | Rate limit exceeded                      |
| 503  | Service unavailable - engine not ready    |
| 500  | Internal server error                    |

## Rate Limits

- **Default:** 100 requests per 15 minutes
- **Configurable** via `RATE_LIMIT_MAX` environment variable

## Webhooks

Configure webhooks for real-time alerts in `config/webhooks.json`:

```json
{
  "enabled": true,
  "endpoints": [
    {
      "name": "Slack SOC Channel",
      "url": "https://hooks.slack.com/services/xxx",
      "events": ["critical", "high"],
      "filter": {
        "riskScore": 70
      }
    }
  ]
}
```

## Integration Examples

### cURL

```bash
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Analysis",
    "content": "Your account has been suspended...",
    "headers": "From: support@amazon.com..."
  }'
```

### Python

```python
import requests

response = requests.post('http://localhost:3001/api/analyze', json={
    'title': 'Phishing Test',
    'content': 'Please verify your account...',
    'headers': 'From: amazon@secure-login.com'
})

data = response.json()
print(f"Risk Score: {data['riskScore']}%")
print(f"Campaign: {data['campaign']}")
```

### Node.js

```javascript
const response = await fetch('http://localhost:3001/api/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    title: 'Phishing Analysis',
    content: emailContent,
    headers: emailHeaders
  })
});

const result = await response.json();
console.log('Risk:', result.riskScore);
```
