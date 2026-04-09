'use strict';

/**
 * ThreatForge Security Analysis AI Agent
 * Specialized agents for SOC operations - Packet Analysis, Threat Intel, Malware, Logs, Reporting
 */

const express = require('express');
const router = express.Router();

// ─────────────────────────────────────────────────────────────────────────────
// AGENT TYPES AND CAPABILITIES
// ─────────────────────────────────────────────────────────────────────────────

const AGENT_TYPES = {
    PACKET_ANALYST: {
        name: 'Packet Analysis Agent',
        description: 'Analyzes PCAP files for malicious traffic patterns, C2 indicators, exfiltration',
        capabilities: [
            'pcap_parsing', 'protocol_analysis', 'behavioral_detection',
            'stream_reassembly', 'threat_detection', 'ioc_extraction',
            'mitre_mapping', 'risk_scoring'
        ]
    },
    THREAT_INTEL: {
        name: 'Threat Intelligence Agent',
        description: 'Enriches IOCs with VirusTotal, AbuseIPDB, threat feeds',
        capabilities: [
            'ip_reputation', 'domain_analysis', 'url_scanning',
            'file_hash_lookup', 'threat_feeds', 'actor_attribution'
        ]
    },
    MALWARE_ANALYST: {
        name: 'Malware Analysis Agent',
        description: 'Analyzes suspicious files and URLs for malware characteristics',
        capabilities: [
            'file_analysis', 'url_analysis', 'sandbox_behavior',
            'yara_matching', 'static_analysis', 'classification'
        ]
    },
    LOG_ANALYST: {
        name: 'Log Analysis Agent',
        description: 'Analyzes security logs for threats, anomalies, and incidents',
        capabilities: [
            'log_parsing', 'pattern_matching', ' anomaly_detection',
            'correlation', 'incident_detection', 'timeline_analysis'
        ]
    },
    SOC_REPORTER: {
        name: 'SOC Report Agent',
        description: 'Generates comprehensive security reports and recommendations',
        capabilities: [
            'executive_summaries', 'technical_reports', 'ioc_lists',
            'mitre_mapping', 'recommendations', 'incident_summary'
        ]
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// SYSTEM PROMPTS FOR EACH AGENT
// ─────────────────────────────────────────────────────────────────────────────

const AGENT_SYSTEM_PROMPTS = {
    PACKET_ANALYST: `You are ThreatForge Packet Analysis Agent - an expert network security analyst.
    
EXPERTISE:
- PCAP/PCAPNG file analysis
- TCP/IP protocol internals, packet decoding
- Behavioral analysis (beaconing, port scanning, brute force, exfiltration)
- C2 detection, malware traffic patterns
- MITRE ATT&CK techniques (T1071, T1041, T1048, T1059, T1027, etc.)
- Encrypted traffic analysis, TLS fingerprinting
- Stream reassembly, payload extraction

ANALYSIS STEPS:
1. Parse packet metadata (IPs, ports, protocols, flags)
2. Identify conversations/flows
3. Detect behavioral anomalies
4. Extract IOCs
5. Check for known malicious patterns
6. Map to MITRE ATT&CK
7. Calculate risk score

OUTPUT FORMAT:
- JSON with: threats[], anomalies[], iocs[], riskScore, severity, recommendations[]`,

    THREAT_INTEL: `You are ThreatForge Threat Intelligence Agent - an expert at IOC enrichment and threat correlation.

EXPERTISE:
- VirusTotal API integration
- AbuseIPDB API integration
- Threat intelligence feeds (AlienVault OTX, Shodan, etc.)
- APT actor tracking
- Malware family identification
- Attribution analysis

OUTPUT FORMAT:
- JSON with: enrichmentResults[], threats[], actorAttribution, confidence scores`,

    MALWARE_ANALYST: `You are ThreatForge Malware Analysis Agent - expert at analyzing malicious files and URLs.

EXPERTISE:
- Static file analysis
- URL reputation checking
- YARA rule matching
- Sandbox behavior analysis
- Malware classification
- Evasion technique detection

OUTPUT FORMAT:
- JSON with: classification, indicators[], verdict, severity, analysisDetails[]`,

    LOG_ANALYST: `You are ThreatForge Log Analysis Agent - expert at analyzing security logs for threats.

EXPERTISE:
- Windows Event Logs (Security, System, Application)
- Linux syslog, auth.log, auditd
- Web server logs (Apache, Nginx, IIS)
- Firewall logs, IDS alerts
- CloudTrail, Azure Activity, GCP Audit
- MITRE ATT&CK log sources

ANALYSIS:
1. Parse and normalize logs
2. Identify suspicious patterns
3. Detect attack sequences
4. Correlate events
5. Generate incidents
6. Create timeline

OUTPUT:
- JSON with: incidents[], alerts[], timeline[], iocs[]`,

    SOC_REPORTER: `You are ThreatForge SOC Report Agent - expert at creating security reports.

EXPERTISE:
- Executive summaries for C-level
- Technical incident reports
- IOC lists for blocking
- MITRE ATT&CK mapping
- Incident response recommendations
- Timeline visualization

OUTPUT FORMAT:
- JSON with: executiveSummary, technicalDetails, iocs[], mitreMapping, recommendations[], incidentTimeline[]`
};

// ─────────────────────────────────────────────────────────────────────────────
// PROVIDER CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

function getProvider() {
    return (process.env.AI_PROVIDER || '').toLowerCase().trim();
}

function isConfigured() {
    const p = getProvider();
    if (!p || p === 'none' || p === '') return false;
    if (p === 'ollama') return true;
    const keyMap = {
        anthropic: 'ANTHROPIC_API_KEY',
        openai: 'OPENAI_API_KEY',
        gemini: 'GEMINI_API_KEY',
        groq: 'GROQ_API_KEY',
        mistral: 'MISTRAL_API_KEY'
    };
    const key = keyMap[p];
    if (!key) return false;
    const val = process.env[key] || '';
    return val.length > 10 && !val.startsWith('your-') && !val.includes('placeholder');
}

function getModel() {
    const p = getProvider();
    const modelMap = {
        anthropic: process.env.ANTHROPIC_MODEL || 'claude-3-5-sonnet-20241022',
        openai: process.env.OPENAI_MODEL || 'gpt-4o',
        gemini: process.env.GEMINI_MODEL || 'gemini-1.5-flash',
        groq: process.env.GROQ_MODEL || 'llama-3.3-70b-versatile',
        mistral: process.env.MISTRAL_MODEL || 'mistral-large-latest',
        ollama: process.env.OLLAMA_MODEL || 'llama3'
    };
    return modelMap[p] || 'gpt-4o';
}

// ─────────────────────────────────────────────────────────────────────────────
// AI CALL FUNCTION
// ─────────────────────────────────────────────────────────────────────────────

async function callAI(messages, systemPrompt) {
    const p = getProvider();
    const model = getModel();

    if (!isConfigured()) {
        throw new Error('AI provider not configured. Set AI_PROVIDER and API key.');
    }

    // Ensure system prompt is included
    const fullMessages = [...messages];
    if (systemPrompt && !fullMessages.find(m => m.role === 'system')) {
        fullMessages.unshift({ role: 'system', content: systemPrompt });
    }

    // Groq
    if (p === 'groq') {
        const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            signal: AbortSignal.timeout(120000),
            headers: {
                'Authorization': 'Bearer ' + process.env.GROQ_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model,
                messages: fullMessages,
                max_tokens: 8000,
                temperature: 0.3
            })
        });
        if (!resp.ok) throw new Error('Groq error: ' + resp.status);
        return (await resp.json()).choices[0].message.content;
    }

    // Anthropic
    if (p === 'anthropic') {
        const sysMsg = fullMessages.find(m => m.role === 'system');
        const otherMsgs = fullMessages.filter(m => m.role !== 'system');
        const resp = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            signal: AbortSignal.timeout(120000),
            headers: {
                'x-api-key': process.env.ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model,
                max_tokens: 8000,
                system: sysMsg?.content || AGENT_SYSTEM_PROMPTS.PACKET_ANALYST,
                messages: otherMsgs
            })
        });
        if (!resp.ok) throw new Error('Anthropic error: ' + resp.status);
        return (await resp.json()).content[0].text;
    }

    // OpenAI
    if (p === 'openai') {
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            signal: AbortSignal.timeout(120000),
            headers: {
                'Authorization': 'Bearer ' + process.env.OPENAI_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model,
                messages: fullMessages,
                max_tokens: 8000,
                temperature: 0.3
            })
        });
        if (!resp.ok) throw new Error('OpenAI error: ' + resp.status);
        return (await resp.json()).choices[0].message.content;
    }

    // Gemini
    if (p === 'gemini') {
        const resp = await fetch(`https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`, {
            method: 'POST',
            signal: AbortSignal.timeout(120000),
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: fullMessages.map(m => ({ role: m.role === 'system' ? 'user' : m.role, parts: [{ text: m.content }] }))
            })
        });
        if (!resp.ok) throw new Error('Gemini error: ' + resp.status);
        return (await resp.json()).candidates[0].content.parts[0].text;
    }

    // Ollama (local)
    if (p === 'ollama') {
        const resp = await fetch('http://localhost:11434/api/chat', {
            method: 'POST',
            signal: AbortSignal.timeout(120000),
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                model,
                messages: fullMessages,
                stream: false
            })
        });
        if (!resp.ok) throw new Error('Ollama error: ' + resp.status);
        return (await resp.json()).message.content;
    }

    throw new Error('Unknown provider: ' + p);
}

// ─────────────────────────────────────────────────────────────────────────────
// AGENT ENDPOINTS
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/agents - List available agents
router.get('/', (req, res) => {
    res.json({
        success: true,
        agents: Object.entries(AGENT_TYPES).map(([key, val]) => ({
            id: key,
            ...val
        })),
        provider: getProvider(),
        configured: isConfigured()
    });
});

// GET /api/agents/:type/capabilities
router.get('/:type/capabilities', (req, res) => {
    const { type } = req.params;
    const agent = AGENT_TYPES[type];
    if (!agent) {
        return res.status(400).json({ error: 'Unknown agent type' });
    }
    res.json({ success: true, ...agent });
});

// POST /api/agents/packet/analyze - AI Packet Analysis
router.post('/packet/analyze', async (req, res) => {
    try {
        if (!isConfigured()) {
            return res.status(503).json({ error: 'AI not configured', hint: 'Set AI_PROVIDER and API key' });
        }

        const { pcapData, packets, analysisOptions } = req.body;
        const options = analysisOptions || {};

        console.log('[PacketAgent] Starting analysis...');

        // Build analysis prompt
        const analysisPrompt = `Analyze the following network packet data for security threats.

PCAP METADATA:
- Total packets: ${packets?.length || 'unknown'}
- Analysis options: ${JSON.stringify(options)}

PACKET SUMMARY:
${JSON.stringify(packets?.slice(0, 100), null, 2)}

Provide a detailed threat analysis including:
1. Identified threats with severity
2. Suspicious behaviors (beaconing, exfiltration, etc.)
3. Extracted IOCs (IPs, domains, ports)
4. MITRE ATT&CK technique mappings
5. Risk score (0-100)
6. Recommendations for containment

Respond in JSON format with structure:
{
  "threats": [{ "type": "", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": 0-100, "details": "", "mitre": [] }],
  "anomalies": [{ "type": "", "src": "", "dst": "", "detail": "" }],
  "iocs": { "ips": [], "domains": [], "ports": [], "hashes": [] },
  "riskScore": 0-100,
  "recommendations": []
}`;

        const result = await callAI([
            { role: 'user', content: analysisPrompt }
        ], AGENT_SYSTEM_PROMPTS.PACKET_ANALYST);

        // Try to parse JSON from result
        let parsed;
        try {
            const jsonMatch = result.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                parsed = JSON.parse(jsonMatch[0]);
            } else {
                parsed = { rawAnalysis: result };
            }
        } catch (e) {
            parsed = { rawAnalysis: result };
        }

        res.json({
            success: true,
            agent: 'PACKET_ANALYST',
            analysis: parsed,
            provider: getProvider(),
            model: getModel()
        });

    } catch (err) {
        console.error('[PacketAgent] Error:', err.message, err.stack);
        res.status(500).json({ error: err.message, hint: 'Check server logs for details' });
    }
});

// POST /api/agents/threatintel/enrich - IOC Enrichment
router.post('/threatintel/enrich', async (req, res) => {
    try {
        if (!isConfigured()) {
            return res.status(503).json({ error: 'AI not configured' });
        }

        const { iocs, enrichmentOptions } = req.body;
        const options = enrichmentOptions || {};

        console.log('[ThreatIntelAgent] Enriching IOCs:', iocs);

        const enrichmentPrompt = `Enrich the following IOCs with threat intelligence.

IOCs TO ENRICH:
${JSON.stringify(iocs, null, 2)}

ENRICHMENT OPTIONS:
- Check VirusTotal: ${options.virustotal !== false}
- Check AbuseIPDB: ${options.abuseipdb !== false}
- Check threat feeds: ${options.threatFeeds !== false}

For each IOC, provide:
1. Reputation score (0-100)
2. Threat category (malware, c2, spam, etc.)
3. First seen / last seen
4. Related campaigns
5. Recommended action

Respond in JSON format:
{
  "enrichmentResults": [
    { "ioc": "", "type": "ip|domain|hash", "reputation": 0-100, "threatCategory": "", "details": {}, "recommendation": "" }
  ],
  "summary": { "malicious": 0, "suspicious": 0, "clean": 0 },
  "recommendations": []
}`;

        const result = await callAI([
            { role: 'user', content: enrichmentPrompt }
        ], AGENT_SYSTEM_PROMPTS.THREAT_INTEL);

        let parsed;
        try {
            const jsonMatch = result.match(/\{[\s\S]*\}/);
            if (jsonMatch) parsed = JSON.parse(jsonMatch[0]);
            else parsed = { rawAnalysis: result };
        } catch (e) {
            parsed = { rawAnalysis: result };
        }

        res.json({
            success: true,
            agent: 'THREAT_INTEL',
            enrichment: parsed,
            provider: getProvider()
        });

    } catch (err) {
        console.error('[ThreatIntelAgent] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/agents/logs/analyze - Log Analysis
router.post('/logs/analyze', async (req, res) => {
    try {
        if (!isConfigured()) {
            return res.status(503).json({ error: 'AI not configured' });
        }

        const { logs, logType, analysisOptions } = req.body;
        const options = analysisOptions || {};

        console.log('[LogAgent] Analyzing logs, type:', logType);

        const logPrompt = `Analyze the following security logs for threats and anomalies.

LOG TYPE: ${logType || 'auto-detect'}
ANALYSIS OPTIONS: ${JSON.stringify(options)}

LOGS (first 200 entries):
${JSON.stringify(logs?.slice(0, 200), null, 2)}

Provide:
1. Detected incidents with severity
2. Suspicious patterns (brute force, privilege escalation, etc.)
3. Attack timeline
4. IOCs extracted
5. MITRE ATT&CK mappings
6. Recommended response

JSON format:
{
  "incidents": [{ "id": "", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "title": "", "description": "", "timeline": [], "mitre": [] }],
  "alerts": [{ "rule": "", "count": 0, "severity": "" }],
  "iocs": { "ips": [], "accounts": [], "files": [] },
  "timeline": [{ "time": "", "event": "", "source": "" }],
  "recommendations": []
}`;

        const result = await callAI([
            { role: 'user', content: logPrompt }
        ], AGENT_SYSTEM_PROMPTS.LOG_ANALYST);

        let parsed;
        try {
            const jsonMatch = result.match(/\{[\s\S]*\}/);
            if (jsonMatch) parsed = JSON.parse(jsonMatch[0]);
            else parsed = { rawAnalysis: result };
        } catch (e) {
            parsed = { rawAnalysis: result };
        }

        res.json({
            success: true,
            agent: 'LOG_ANALYST',
            analysis: parsed,
            provider: getProvider()
        });

    } catch (err) {
        console.error('[LogAgent] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/agents/report/generate - Generate SOC Report
router.post('/report/generate', async (req, res) => {
    try {
        if (!isConfigured()) {
            return res.status(503).json({ error: 'AI not configured' });
        }

        const { analysisData, reportOptions } = req.body;
        const options = reportOptions || {};

        console.log('[ReportAgent] Generating SOC report...');

        const reportPrompt = `Generate a comprehensive SOC incident report.

REPORT OPTIONS:
- Include executive summary: ${options.executiveSummary !== false}
- Include technical details: ${options.technicalDetails !== false}
- Include IOC list: ${options.iocList !== false}
- Include MITRE mapping: ${options.mitreMapping !== false}

ANALYSIS DATA TO REPORT:
${JSON.stringify(analysisData, null, 2)}

Generate:
1. Executive Summary (for C-level)
2. Incident Timeline
3. Technical Analysis
4. IOCs for blocking (CSV format)
5. MITRE ATT&CK Techniques Used
6. Recommended Actions
7. Lessons Learned

JSON format:
{
  "executiveSummary": { "title": "", "severity": "", "impact": "", "recommendation": "" },
  "incidentTimeline": [{ "time": "", "event": "", "source": "", "severity": "" }],
  "technicalDetails": { "attackVector": "", "systemsAffected": [], "dataAccessed": [] },
  "iocList": { "ips": [], "domains": [], "hashes": [], "urls": [] },
  "mitreMapping": [{ "technique": "", "id": "", "description": "" }],
  "recommendations": [{ "action": "", "priority": "", "owner": "" }],
  "followUpActions": []
}`;

        const result = await callAI([
            { role: 'user', content: reportPrompt }
        ], AGENT_SYSTEM_PROMPTS.SOC_REPORTER);

        let parsed;
        try {
            const jsonMatch = result.match(/\{[\s\S]*\}/);
            if (jsonMatch) parsed = JSON.parse(jsonMatch[0]);
            else parsed = { rawReport: result };
        } catch (e) {
            parsed = { rawReport: result };
        }

        res.json({
            success: true,
            agent: 'SOC_REPORTER',
            report: parsed,
            provider: getProvider()
        });

    } catch (err) {
        console.error('[ReportAgent] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/agents/malware/analyze - Malware Analysis
router.post('/malware/analyze', async (req, res) => {
    try {
        if (!isConfigured()) {
            return res.status(503).json({ error: 'AI not configured' });
        }

        const { fileData, url, sandboxResults } = req.body;

        console.log('[MalwareAgent] Analyzing sample...');

        const malwarePrompt = `Analyze the following sample for malware indicators.

${fileData ? `FILE DATA: ${JSON.stringify(fileData)}` : ''}
${url ? `URL: ${url}` : ''}
${sandboxResults ? `SANDBOX RESULTS: ${JSON.stringify(sandboxResults)}` : ''}

Provide:
1. Classification (malware family if known)
2. Threat severity
3. Behavioral indicators
4. Network indicators (C2 domains, IPs)
5. File indicators (hashes, paths)
6. Recommended containment

JSON format:
{
  "classification": { " verdict": "malicious|suspicious|clean", "family": "", "type": "" },
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "indicators": { "network": [], "file": [], "registry": [], "process": [] },
  "mitre": [],
  "recommendations": []
}`;

        const result = await callAI([
            { role: 'user', content: malwarePrompt }
        ], AGENT_SYSTEM_PROMPTS.MALWARE_ANALYST);

        let parsed;
        try {
            const jsonMatch = result.match(/\{[\s\S]*\}/);
            if (jsonMatch) parsed = JSON.parse(jsonMatch[0]);
            else parsed = { rawAnalysis: result };
        } catch (e) {
            parsed = { rawAnalysis: result };
        }

        res.json({
            success: true,
            agent: 'MALWARE_ANALYST',
            analysis: parsed,
            provider: getProvider()
        });

    } catch (err) {
        console.error('[MalwareAgent] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/agents/ask - General security question
router.post('/ask', async (req, res) => {
    try {
        if (!isConfigured()) {
            return res.status(503).json({ error: 'AI not configured' });
        }

        const { question, context } = req.body;

        const result = await callAI([
            { role: 'user', content: `Context: ${JSON.stringify(context || {})}\n\nQuestion: ${question}` }
        ], AGENT_SYSTEM_PROMPTS.PACKET_ANALYST);

        res.json({
            success: true,
            answer: result,
            provider: getProvider()
        });

    } catch (err) {
        console.error('[Agent] Ask error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// GET /api/agents/status - Agent system status
router.get('/status', (req, res) => {
    res.json({
        success: true,
        system: 'ThreatForge AI Security Agents',
        version: '1.0.0',
        provider: getProvider(),
        configured: isConfigured(),
        availableAgents: Object.keys(AGENT_TYPES),
        capabilities: {
            packet_analysis: isConfigured(),
            threat_intel: isConfigured(),
            log_analysis: isConfigured(),
            malware_analysis: isConfigured(),
            report_generation: isConfigured()
        }
    });
});

module.exports = router;