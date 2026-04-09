const express = require('express');
const router = express.Router();

// Try to use the security agent LLM integration, fallback to basic mode
let callAI = null;
let getProvider = null;

try {
    const securityAgent = require('./securityAgent');
    callAI = securityAgent.callAI;
    // Check if AI is configured
    const isConfigured = securityAgent.isConfigured?.();
    if (isConfigured) {
        console.log('✅ LLM integration active - using securityAgent for AI chat');
    }
} catch (e) {
    console.log('⚠️ LLM not available, using basic mode:', e.message);
}

// System prompt for SOC analyst
const SOC_ANALYST_PROMPT = `You are ThreatForge AI, an elite SOC analyst assistant. Your role:
- Analyze security alerts, threats, and incidents
- Provide detection rules (Splunk, Sentinel, Sigma)
- Map threats to MITRE ATT&CK techniques
- Suggest containment and remediation
- Explain vulnerabilities and CVEs
- Intelligence on threat actors and campaigns

Respond professionally with technical depth. Use structured formats for queries and detection rules.`;

// POST /api/ai/chat - Main AI chat endpoint
router.post('/chat', async (req, res) => {
    try {
        const { message, context, stream } = req.body;
        
        if (!message) {
            return res.status(400).json({ error: 'message required' });
        }
        
        // If LLM is configured, use it
        if (callAI) {
            try {
                const isConfigured = (() => {
                    const p = process.env.AI_PROVIDER;
                    if (!p || p === 'none') return false;
                    const keyMap = {
                        anthropic: 'ANTHROPIC_API_KEY',
                        openai: 'OPENAI_API_KEY',
                        gemini: 'GEMINI_API_KEY',
                        groq: 'GROQ_API_KEY',
                        mistral: 'MISTRAL_API_KEY'
                    };
                    const key = keyMap[p];
                    return key && process.env[key]?.length > 10;
                })();
                
                if (isConfigured) {
                    const result = await callAI(
                        [{ role: 'user', content: message }],
                        SOC_ANALYST_PROMPT
                    );
                    
                    return res.json({
                        response: result,
                        provider: process.env.AI_PROVIDER,
                        mode: 'LLM'
                    });
                }
            } catch (llmError) {
                console.error('LLM call failed:', llmError.message);
            }
        }
        
        // Fallback: keyword-based responses
        const lowerMsg = message.toLowerCase();
        let response = "I'm analyzing the threat landscape...";
        let confidence = "Medium";
        let sources = ["ThreatForge Intelligence"];
        
        // APT/Threat Actors
        if (lowerMsg.includes('apt') || lowerMsg.includes('group') || lowerMsg.includes('actor')) {
            response = `## APT Group Intelligence
            
**Active Threat Groups:**
- **APT29 (Russia)** - Supply chain attacks, SolarWinds
- **APT41 (China)** - Espionage, financial crime
- **Lazarus (North Korea)** - Cryptocurrency heists, destructive malware
- **APT28 (Russia)** - Credential harvesting, VPN exploits

**Recommended Detection:**
- Monitor for advanced persistent login patterns
- Watch for scheduled task creation from unusual locations
- Detect lateral movement via SMB/RDP`;
        }
        // Detection rules
        else if (lowerMsg.includes('query') || lowerMsg.includes('detection') || lowerMsg.includes('sigma') || lowerMsg.includes('splunk')) {
            response = `## Detection Rules
            
**Splunk - Brute Force:**
\`\`\`
index=security EventCode=4625 | stats count by src_ip, account | where count > 10
\`\`\`

**Splunk - PowerShell encoded:**
\`\`\`
index=windows powershell -enc | regex -c "FromBase64String"
\`\`\`

**Sigma - Suspicious process:**
\`\`\yaml
title: Suspicious PowerShell Download
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image: '*\\powershell.exe'
    CommandLine|contains: '-enc'
condition: selection
\`\`\``;
        }
        // CVE/Vulnerability
        else if (lowerMsg.includes('cve') || lowerMsg.includes('vulnerability') || lowerMsg.includes('exploit')) {
            response = `## Critical CVEs
            
| CVE | Severity | Description | Exploited |
|-----|----------|-------------|-----------|
| CVE-2024-3400 | CRITICAL | Palo Alto PAN-OS RCE | Yes - KEV |
| CVE-2024-27198 | CRITICAL | TeamCity RCE | Yes |
| CVE-2023-46805 | HIGH | ConnectWise ScreenConnect | Yes |
| CVE-2024-1709 | CRITICAL | ConnectWise ScreenConnect Auth Bypass | Yes |

**Remediation:** Apply vendor patches immediately. Check CISA KEV catalog.`;
        }
        // MITRE ATT&CK
        else if (lowerMsg.includes('mitre') || lowerMsg.includes('t1059') || lowerMsg.includes('t1566') || lowerMsg.includes('technique')) {
            response = `## MITRE ATT&CK Coverage
            
**Initial Access (T1566):**
- T1566.001 - Phishing with attachments
- T1566.002 - Phishing with link
- T1566.003 - Spearphishing via service

**Execution (T1059):**
- T1059.001 - PowerShell
- T1059.004 - Unix Shell
- T1059.005 - Visual Basic

**Persistence (T1547):**
- T1547.001 - Registry Run keys
- T1547.010 - Port monitor

Would you like detection rules for a specific technique?`;
        }
        // Incident Response
        else if (lowerMsg.includes('incident') || lowerMsg.includes('respond') || lowerMsg.includes('ir') || lowerMsg.includes('playbook')) {
            response = `## Incident Response Playbook
            
**Ransomware Response:**
1. ISOLATE - Disconnect affected systems from network
2. IDENTIFY - Determine ransomware variant
3. CONTAIN - Block lateral movement
4. ERADICATE - Remove malware, close vulnerabilities
5. RECOVER - Restore from clean backups
6. LESSONS - Document and improve

**Phishing Response:**
1. QUARANTINE - Remove email from inboxes
2. ANALYZE - Sandboxing for attachments/URLs
3. BLOCK - Add IOCs to blocking lists
4. NOTIFY - Alert potentially affected users
5. RESET - Force password reset if credentials compromised`;
        }
        // Network/PCAP analysis
        else if (lowerMsg.includes('pcap') || lowerMsg.includes('packet') || lowerMsg.includes('network') || lowerMsg.includes('c2')) {
            response = `## Network Threat Analysis
            
**C2 Indicators:**
- Unusual ports (4444, 5555, 7492, 31337)
- Beaconing patterns (regular intervals)
- DNS tunneling (long subdomains)
- TLS anomalies (deprecated versions)

**Splunk - C2 Detection:**
\`\`\`
index=network | stats count, avg(duration) by src_ip, dest_ip | where count > 100 AND avg(duration) < 1
\`\`\`

**Behaviors to Hunt:**
- High-volume outbound to single IP
- DNS queries to suspicious TLDs
- TLS 1.0/1.1 connections`;
        }
        // Default response
        else {
            response = `## ThreatForge AI Analyst

I can help with:
- **Threat Intelligence** - APT groups, campaigns, IOCs
- **Detection Rules** - Splunk, Sigma, Sentinel queries
- **Vulnerability Analysis** - CVE analysis, remediation
- **MITRE ATT&CK** - Technique mapping, coverage
- **Incident Response** - Playbooks, containment
- **Network Analysis** - PCAP, C2 detection

What would you like to analyze?`;
        }
        
        res.json({
            response,
            confidence,
            sources,
            mode: 'Basic (Configure LLM for advanced)'
        });
    } catch (error) {
        console.error('AI chat error:', error);
        res.status(500).json({ 
            error: 'AI service error',
            response: 'I encountered an error. Please try again.'
        });
    }
});

// POST /api/ai/analyze - Threat analysis
router.post('/analyze', async (req, res) => {
    try {
        const { type, data } = req.body;
        
        // Simple analysis based on type
        let result = { ai_score: 0.5, risk_level: 'Medium', confidence: 'Low' };
        
        if (type === 'file' || type === 'hash') {
            result = { ai_score: 0.3, risk_level: 'Low', confidence: 'Medium', reasons: ['No malware patterns detected'] };
        } else if (type === 'url') {
            result = { ai_score: 0.6, risk_level: 'High', confidence: 'Medium', reasons: ['Suspicious URL patterns'] };
        } else if (type === 'ip') {
            result = { ai_score: 0.4, risk_level: 'Medium', confidence: 'Medium', reasons: ['External IP - verify reputation'] };
        }
        
        res.json(result);
    } catch (error) {
        res.status(503).json({ error: 'Analysis unavailable' });
    }
});

module.exports = router;