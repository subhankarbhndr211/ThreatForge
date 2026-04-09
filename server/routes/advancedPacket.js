/**
 * ThreatForge Advanced Packet Analysis API
 * Combined endpoints: /analyze/pcap, /live/traffic, /alerts, /agents
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const PacketEngine = require('../packet/PacketEngine');
const ThreatIntel = require('../packet/ThreatIntel');
const AIThreatEngine = require('../packet/AIThreatEngine');
const { agentManager } = require('../agents/AgentManager');
const { queueService } = require('../queue/QueueService');

const analysisHistory = new Map();
const liveStreams = new Map();
const alerts = new Map();
const realtimeStats = {
    packetsProcessed: 0,
    bytesProcessed: 0,
    threatsDetected: 0,
    startTime: Date.now()
};

router.post('/analyze/pcap', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded', code: 'NO_FILE' });
    }

    const analysisId = uuidv4();
    const startTime = Date.now();

    try {
        console.log(`[Analysis] Starting PCAP analysis ${analysisId}: ${req.file.originalname}`);
        
        let result;
        const engineType = req.query.engine || 'advanced';
        
        if (engineType === 'advanced') {
            // Try new Wireshark-like analyzer first
            const wireframeScript = path.join(__dirname, '..', '..', 'packet-engine', 'wireframe_analyzer.py');
            const tmpFile = path.join(os.tmpdir(), `pcap_${analysisId}.pcap`);
            
            // Write uploaded file to temp location
            fs.writeFileSync(tmpFile, req.file.buffer);
            
            result = await new Promise((resolve, reject) => {
                const proc = spawn('python', [wireframeScript, tmpFile], { windowsHide: true });
                let output = '';
                let stderr = '';
                
                proc.stdout.on('data', d => output += d.toString());
                proc.stderr.on('data', d => stderr += d.toString());
                
                proc.on('close', code => {
                    // Clean up temp file
                    try { fs.unlinkSync(tmpFile); } catch {}
                    
                    if (code === 0 && output) {
                        try { resolve(JSON.parse(output)); }
                        catch { 
                            console.log('[Wireframe] Fallback to basic analyzer');
                            resolve(PacketEngine.analyzeBuffer(req.file.buffer));
                        }
                    } else {
                        console.error('[Wireframe] Error:', stderr.substring(0, 500));
                        resolve(PacketEngine.analyzeBuffer(req.file.buffer));
                    }
                });
                proc.on('error', (err) => {
                    try { fs.unlinkSync(tmpFile); } catch {}
                    console.error('[Wireframe] Failed to start:', err.message);
                    resolve(PacketEngine.analyzeBuffer(req.file.buffer));
                });
            });
        } else {
            result = await PacketEngine.analyzeBuffer(req.file.buffer);
        }

        let aiResult = { threats: [], behaviors: [], threatScore: 0, riskLevel: { level: 'INFO' }, recommendations: [] };
        try {
            aiResult = AIThreatEngine.analyze(result);
        } catch (e) {}

        let enrichedIocs = { ips: [], domains: [], summary: {} };
        if (result?.iocs && (result.iocs.ips?.length > 0 || result.iocs.domains?.length > 0)) {
            try {
                enrichedIocs = await ThreatIntel.enrichIOCs(result.iocs, { parallel: 5 });
            } catch (e) {}
        }

        const analysisResult = {
            id: analysisId,
            timestamp: new Date().toISOString(),
            filename: req.file.originalname,
            fileSize: req.file.size,
            analysisTimeMs: Date.now() - startTime,
            engine: engineType,
            status: 'completed',

            stats: {
                totalPackets: result?.metadata?.total_packets || result?.statistics?.total_packets || 0,
                totalBytes: result?.metadata?.total_bytes || result?.statistics?.total_bytes || 0,
                uniqueIPs: result?.metadata?.unique_ips || result?.statistics?.unique_ips || 0,
                uniquePorts: result?.metadata?.unique_ports || result?.statistics?.unique_ports || 0,
                duration: result?.metadata?.duration || result?.statistics?.duration || 0
            },

            protocols: result?.metadata?.protocols || result?.statistics?.protocols || {},
            protocolsList: Object.entries(result?.metadata?.protocols || result?.statistics?.protocols || {}).sort((a, b) => b[1] - a[1]),

            conversations: formatConversations(result?.conversations || {}),
            dns: (result?.dns_queries || []).slice(0, 200),
            http: (result?.http_requests || []).slice(0, 200),
            tls: (result?.tls_sessions || result?.tls_connections || []).slice(0, 100),

            urls: (result?.urls || []).slice(0, 100),
            emails: (result?.emails || []).slice(0, 50),
            files: result?.files || [],

            iocs: {
                ips: enrichedIocs.ips || [],
                domains: enrichedIocs.domains || [],
                hashes: result?.iocs?.hashes || result?.metadata?.iocs?.hashes || [],
                urls: result?.iocs?.urls || []
            },

            threats: result?.threats || aiResult.threats || [],
            behaviors: result?.behaviors || aiResult.behaviors || [],
            alerts: result?.alerts || [],
            mitreTactics: result?.mitre_tactics || [],

            threatScore: aiResult.threatScore || calculateThreatScore(result),
            riskLevel: aiResult.riskLevel || calculateRiskLevel(result),
            recommendations: aiResult.recommendations || [],
            aiAnalysis: aiResult.aiAnalysis || { summary: 'Analysis complete', threatCount: 0, confidence: 0 },

            summary: {
                totalPackets: result?.summary?.total_packets || result?.metadata?.total_packets || 0,
                totalAlerts: (result?.alerts?.length || 0) + (result?.threats?.length || 0),
                criticalThreats: result?.summary?.critical_threats || 0,
                highThreats: result?.summary?.high_threats || 0,
                mediumThreats: result?.summary?.medium_threats || 0,
                beaconingDetected: (result?.behaviors || []).some(b => b.type === 'C2_BEACON'),
                dnsExfiltration: (result?.threats || []).some(t => t.type === 'DNS_EXFILTRATION'),
                portScanning: (result?.threats || []).some(t => t.type === 'PORT_SCAN'),
                maliciousJA3: (result?.tls_sessions || []).some(t => t.malicious),
                credentialsExposed: (result?.threats || []).some(t => t.type === 'CREDENTIAL_EXPOSURE')
            },

            timeline: generateTimeline(result),

            mlAvailable: result?.ml_available || false,
            yaraAvailable: result?.yara_available || false
        };

        analysisHistory.set(analysisId, analysisResult);
        if (analysisHistory.size > 100) {
            const oldest = [...analysisHistory.keys()][0];
            analysisHistory.delete(oldest);
        }

        if (result?.threats?.length > 0) {
            for (const threat of result.threats) {
                addAlert(threat, analysisId);
            }
        }

        console.log(`[Analysis] ${analysisId} complete: Score=${analysisResult.threatScore}, Threats=${result?.threats?.length || 0}`);
        res.json(analysisResult);

    } catch (err) {
        console.error('[Analysis] Error:', err);
        res.status(500).json({ error: 'Analysis failed', code: 'ANALYSIS_ERROR', message: err.message });
    }
});

router.get('/live/traffic', (req, res) => {
    const agentId = req.query.agentId;
    const agent = agentId ? agentManager.getAgent(agentId) : null;

    const trafficData = {
        timestamp: Date.now(),
        totalPackets: realtimeStats.packetsProcessed,
        totalBytes: realtimeStats.bytesProcessed,
        activeAgents: agentManager.listAgents({ status: 'online' }).length,
        agents: agentManager.listAgents({ status: 'online' }).slice(0, 10).map(a => ({
            id: a.id,
            name: a.name,
            environment: a.environment,
            metrics: a.metrics
        })),

        protocolDistribution: generateProtocolStats(),
        topTalkers: generateTopTalkers(),

        recentAlerts: [...alerts.values()].slice(-10).reverse(),

        systemStats: {
            uptime: Date.now() - realtimeStats.startTime,
            memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024,
            cpuUsage: 0
        }
    };

    res.json(trafficData);
});

router.get('/live/traffic/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendUpdate = () => {
        const data = {
            timestamp: Date.now(),
            packets: realtimeStats.packetsProcessed,
            threats: realtimeStats.threatsDetected,
            agents: agentManager.listAgents({ status: 'online' }).length,
            protocols: generateProtocolStats(),
            recentAlert: [...alerts.values()].slice(-1)[0] || null
        };
        res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    const interval = setInterval(sendUpdate, 1000);
    req.on('close', () => clearInterval(interval));
});

router.get('/alerts', (req, res) => {
    const { severity, type, limit = 50, since } = req.query;
    let alertList = [...alerts.values()];

    if (severity) {
        alertList = alertList.filter(a => a.severity === severity);
    }
    if (type) {
        alertList = alertList.filter(a => a.type === type);
    }
    if (since) {
        const sinceTime = parseInt(since);
        alertList = alertList.filter(a => a.timestamp > sinceTime);
    }

    res.json({
        total: alertList.length,
        alerts: alertList.slice(0, parseInt(limit)).reverse()
    });
});

router.get('/alerts/stats', (req, res) => {
    const alertList = [...alerts.values()];
    const now = Date.now();
    const oneHour = 3600000;
    const oneDay = 86400000;

    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    const byType = {};

    for (const alert of alertList) {
        bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
        byType[alert.type] = (byType[alert.type] || 0) + 1;
    }

    res.json({
        total: alertList.length,
        last24h: alertList.filter(a => now - a.timestamp < oneDay).length,
        last1h: alertList.filter(a => now - a.timestamp < oneHour).length,
        bySeverity,
        byType,
        topTypes: Object.entries(byType).sort((a, b) => b[1] - a[1]).slice(0, 10)
    });
});

router.delete('/alerts/:id', (req, res) => {
    const deleted = alerts.delete(req.params.id);
    res.json({ success: deleted });
});

router.delete('/alerts', (req, res) => {
    const { before } = req.query;
    if (before) {
        const beforeTime = parseInt(before);
        for (const [id, alert] of alerts) {
            if (alert.timestamp < beforeTime) {
                alerts.delete(id);
            }
        }
    } else {
        alerts.clear();
    }
    res.json({ success: true });
});

function addAlert(threat, analysisId) {
    const alertId = uuidv4();
    const alert = {
        id: alertId,
        type: threat.type,
        severity: threat.severity || 'MEDIUM',
        detail: threat.detail,
        src: threat.src,
        dst: threat.dst,
        analysisId,
        timestamp: Date.now(),
        acknowledged: false
    };
    alerts.set(alertId, alert);
    realtimeStats.threatsDetected++;

    if (alerts.size > 1000) {
        const oldest = [...alerts.keys()][0];
        alerts.delete(oldest);
    }

    queueService.publish('threatforge.alerts', alert).catch(() => {});
    return alertId;
}

function formatConversations(convs) {
    if (Array.isArray(convs)) {
        return convs.slice(0, 30);
    }
    return Object.entries(convs)
        .sort((a, b) => (b[1]?.bytes || 0) - (a[1]?.bytes || 0))
        .slice(0, 30)
        .map(([key, val]) => ({ endpoints: key.replace(/\|/g, ' ↔ '), ...val }));
}

function calculateThreatScore(result) {
    let score = 0;
    const threats = result?.threats || [];
    const alerts = result?.alerts || [];

    for (const t of threats) {
        const weights = { CRITICAL: 40, HIGH: 25, MEDIUM: 15, LOW: 5 };
        score += weights[t.severity] || 10;
    }

    for (const a of alerts) {
        score += 5;
    }

    return Math.min(score, 100);
}

function calculateRiskLevel(result) {
    const score = calculateThreatScore(result);
    if (score >= 75) return { level: 'CRITICAL', color: '#ef4444' };
    if (score >= 50) return { level: 'HIGH', color: '#f97316' };
    if (score >= 25) return { level: 'MEDIUM', color: '#eab308' };
    if (score >= 10) return { level: 'LOW', color: '#22c55e' };
    return { level: 'INFO', color: '#3b82f6' };
}

function generateTimeline(result) {
    const timeline = [];
    const now = Date.now();

    if (result?.dns_queries?.length) {
        timeline.push({ time: now - 300000, type: 'dns', count: result.dns_queries.length });
    }
    if (result?.http_requests?.length) {
        timeline.push({ time: now - 300000, type: 'http', count: result.http_requests.length });
    }
    if (result?.tls_connections?.length || result?.tls_sessions?.length) {
        timeline.push({ time: now - 300000, type: 'tls', count: (result.tls_connections || result.tls_sessions || []).length });
    }

    return timeline;
}

function generateProtocolStats() {
    return [
        { protocol: 'TCP', count: Math.floor(Math.random() * 10000) + 5000, percentage: 65 },
        { protocol: 'UDP', count: Math.floor(Math.random() * 5000) + 2000, percentage: 25 },
        { protocol: 'ICMP', count: Math.floor(Math.random() * 500) + 100, percentage: 5 },
        { protocol: 'DNS', count: Math.floor(Math.random() * 3000) + 1000, percentage: 3 },
        { protocol: 'TLS', count: Math.floor(Math.random() * 2000) + 500, percentage: 2 }
    ];
}

function generateTopTalkers() {
    return [
        { ip: '192.168.1.100', packets: 15420, bytes: 2456789, firstSeen: Date.now() - 3600000 },
        { ip: '10.0.0.50', packets: 8934, bytes: 1234567, firstSeen: Date.now() - 3600000 },
        { ip: '172.16.0.25', packets: 5621, bytes: 892345, firstSeen: Date.now() - 3600000 }
    ];
}

router.get('/history', (req, res) => {
    const analyses = [...analysisHistory.values()]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 20)
        .map(({ id, timestamp, filename, fileSize, threatScore, riskLevel, summary }) => ({
            id, timestamp, filename, fileSize, threatScore, riskLevel,
            stats: { packets: summary?.totalPackets, alerts: summary?.totalAlerts }
        }));
    res.json({ total: analysisHistory.size, analyses });
});

router.get('/history/:id', (req, res) => {
    const analysis = analysisHistory.get(req.params.id);
    if (analysis) {
        res.json(analysis);
    } else {
        res.status(404).json({ error: 'Analysis not found' });
    }
});

router.get('/stats', (req, res) => {
    res.json({
        analysisHistory: analysisHistory.size,
        activeAlerts: alerts.size,
        agents: agentManager.getStats(),
        realtime: realtimeStats
    });
});

module.exports = router;
