// packet.js — Enhanced Network Packet Analysis API
'use strict';
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });
const { spawn } = require('child_process');
const path = require('path');

const PacketEngine = require('../packet/PacketEngine');
const ThreatIntel = require('../packet/ThreatIntel');
const AIThreatEngine = require('../packet/AIThreatEngine');

const analysisHistory = new Map();
const activeAnalyses = new Map();
const liveMonitors = new Map();

router.post('/analyze', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded', code: 'NO_FILE' });
    }

    const analysisId = uuidv4();
    const startTime = Date.now();

    try {
        console.log(`[Packet] Starting analysis ${analysisId}: ${req.file.originalname} (${req.file.size} bytes)`);
        activeAnalyses.set(analysisId, { status: 'analyzing', progress: 0, startTime });

        const buffer = req.file.buffer;
        activeAnalyses.get(analysisId).progress = 10;

        let pcapResult;
        try {
            pcapResult = await PacketEngine.analyzeBuffer(buffer);
            if (!pcapResult || typeof pcapResult !== 'object') {
                throw new Error('Invalid analyzer response');
            }
        } catch (analyzeErr) {
            console.error('[Packet] Analysis error:', analyzeErr);
            return res.status(500).json({ 
                error: 'PCAP analysis failed', 
                code: 'ANALYSIS_ERROR',
                message: analyzeErr.message 
            });
        }
        
        activeAnalyses.get(analysisId).progress = 40;

        let aiResult;
        try {
            aiResult = AIThreatEngine.analyze(pcapResult);
        } catch (aiErr) {
            console.warn('[Packet] AI analysis error:', aiErr.message);
            aiResult = { threats: [], behaviors: [], threatScore: 0, riskLevel: { level: 'INFO', color: '#3b82f6' }, recommendations: [], aiAnalysis: { summary: 'AI analysis unavailable', threatCount: 0, behaviorCount: 0, confidence: 0 } };
        }
        activeAnalyses.get(analysisId).progress = 60;

        let enrichedIocs = { ips: [], domains: [], summary: {} };
        if (pcapResult.iocs && (pcapResult.iocs.ips?.length > 0 || pcapResult.iocs.domains?.length > 0)) {
            try {
                enrichedIocs = await ThreatIntel.enrichIOCs(pcapResult.iocs, { parallel: 3 });
                activeAnalyses.get(analysisId).progress = 80;
            } catch (err) {
                console.warn('[Packet] IOC enrichment failed:', err.message);
            }
        }

        const analysisResult = {
            id: analysisId,
            timestamp: new Date().toISOString(),
            filename: req.file.originalname,
            fileSize: req.file.size,
            analysisTimeMs: Date.now() - startTime,
            status: 'completed',

            stats: {
                totalPackets: pcapResult.statistics?.total_packets || 0,
                totalBytes: pcapResult.statistics?.total_bytes || 0,
                uniqueIPs: pcapResult.statistics?.unique_ips || 0,
                uniquePorts: pcapResult.statistics?.unique_ports || 0,
                duration: pcapResult.statistics?.duration || 0
            },

            statistics: pcapResult.statistics || {},
            summary: pcapResult.summary || {},

            ips: pcapResult.iocs?.ips || [],

            protocols: pcapResult.statistics?.protocols || {},

            conversations: Object.entries(pcapResult.conversations || {}).length > 0
                ? Object.entries(pcapResult.conversations)
                    .sort((a, b) => (b[1]?.bytes || 0) - (a[1]?.bytes || 0))
                    .slice(0, 30)
                    .map(([key, val]) => ({ endpoints: key.replace(/\|/g, ' ↔ '), ...val }))
                : [],

            dns: (pcapResult.dns_queries || []).slice(0, 100),
            http: (pcapResult.http_requests || []).slice(0, 100),
            tls: (pcapResult.tls_connections || []).slice(0, 50),

            urls: (pcapResult.urls || []).slice(0, 100),
            emails: (pcapResult.emails || []).slice(0, 50),

            suspicious: (pcapResult.alerts || []).map(a => ({
                type: a.type || 'UNKNOWN',
                severity: a.severity || 'LOW',
                detail: a.detail || '',
                src: a.src || '',
                dst: a.dst || ''
            })),

            iocs: {
                ips: enrichedIocs.ips || [],
                domains: enrichedIocs.domains || [],
                hashes: pcapResult.iocs?.hashes || [],
                credentials: pcapResult.credentials || []
            },

            threats: aiResult.threats || [],
            behaviors: aiResult.behaviors || [],
            threatScore: aiResult.threatScore || 0,
            riskLevel: aiResult.riskLevel || { level: 'INFO', color: '#3b82f6' },
            recommendations: aiResult.recommendations || [],
            aiAnalysis: aiResult.aiAnalysis || { summary: 'Analysis complete', threatCount: 0, behaviorCount: 0, confidence: 0 },

            alerts: pcapResult.alerts || [],
            ja3Signatures: pcapResult.ja3_signatures || {},

            meta: {
                engine: pcapResult._fallback ? 'JS_FALLBACK' : 'PYTHON_SCAPY',
                enriched: enrichedIocs.ips?.length > 0 || enrichedIocs.domains?.length > 0
            }
        };

        activeAnalyses.delete(analysisId);
        analysisHistory.set(analysisId, analysisResult);
        if (analysisHistory.size > 50) {
            const oldest = analysisHistory.keys().next().value;
            analysisHistory.delete(oldest);
        }

        console.log(`[Packet] Analysis ${analysisId} complete: Score=${aiResult.threatScore}, Threats=${aiResult.threats.length}`);

        res.json(analysisResult);
    } catch (err) {
        console.error('[Packet] Analysis failed:', err);
        activeAnalyses.delete(analysisId);
        res.status(500).json({ 
            error: 'Analysis failed', 
            code: 'ANALYSIS_ERROR',
            message: err.message 
        });
    }
});

router.post('/enrich', async (req, res) => {
    try {
        const { iocs } = req.body;
        if (!iocs) {
            return res.status(400).json({ error: 'No IOCs provided' });
        }
        const enriched = await ThreatIntel.enrichIOCs(iocs);
        res.json(enriched);
    } catch (err) {
        res.status(500).json({ error: 'Enrichment failed', message: err.message });
    }
});

router.get('/history', (req, res) => {
    const analyses = Array.from(analysisHistory.values())
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 20)
        .map(({ id, timestamp, filename, fileSize, threatScore, riskLevel, summary }) => ({
            id, timestamp, filename, fileSize, threatScore, riskLevel,
            stats: { packets: summary?.total_packets, alerts: summary?.total_alerts }
        }));
    res.json({ total: analysisHistory.size, analyses });
});

router.get('/analysis/:id', (req, res) => {
    const analysis = analysisHistory.get(req.params.id);
    if (!analysis) {
        return res.status(404).json({ error: 'Analysis not found', code: 'NOT_FOUND' });
    }
    res.json(analysis);
});

router.get('/status/:id', (req, res) => {
    const active = activeAnalyses.get(req.params.id);
    if (active) {
        res.json({ id: req.params.id, ...active });
    } else {
        const completed = analysisHistory.get(req.params.id);
        if (completed) {
            res.json({ id: req.params.id, status: 'completed', progress: 100 });
        } else {
            res.status(404).json({ error: 'Analysis not found' });
        }
    }
});

router.get('/intel/lookup/:type/:value', async (req, res) => {
    try {
        const { type, value } = req.params;
        let result;

        switch (type) {
            case 'ip':
                result = await ThreatIntel.enrichIP(value);
                break;
            case 'domain':
                result = await ThreatIntel.enrichDomain(value);
                break;
            case 'hash':
                result = await ThreatIntel.enrichHash(value);
                break;
            default:
                return res.status(400).json({ error: 'Invalid type' });
        }

        res.json(result);
    } catch (err) {
        res.status(500).json({ error: 'Lookup failed', message: err.message });
    }
});

router.get('/stats', (req, res) => {
    res.json({
        historySize: analysisHistory.size,
        activeAnalyses: activeAnalyses.size,
        engineCache: PacketEngine.getCacheStats()
    });
});

router.delete('/clear', (req, res) => {
    analysisHistory.clear();
    res.json({ message: 'History cleared' });
});

// ── LIVE MONITORING ROUTES ──────────────────────────────────────

router.get('/live/interfaces', async (req, res) => {
    try {
        const pyScript = path.join(__dirname, '..', '..', 'packet-engine', 'live_monitor.py');
        const result = await new Promise((resolve) => {
            const proc = spawn('python', ['-c', `
import sys
sys.path.insert(0, r'${path.dirname(pyScript).replace(/\\/g, '\\\\')}')
from live_monitor import list_interfaces
import json
print(json.dumps(list_interfaces()))
`], { windowsHide: true, timeout: 5000 });

            let output = '';
            proc.stdout.on('data', d => output += d.toString());
            proc.on('close', () => {
                try { resolve(JSON.parse(output)); }
                catch { resolve([{ name: 'Default', ip: '0.0.0.0' }]); }
            });
            proc.on('error', () => resolve([{ name: 'Default', ip: '0.0.0.0' }]));
        });
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.post('/live/start', async (req, res) => {
    const { interface: iface, bpf } = req.body;
    const monitorId = uuidv4();

    try {
        const pyScript = path.join(__dirname, '..', '..', 'packet-engine', 'live_monitor.py');
        const args = [pyScript];
        if (iface) args.push('--monitor', iface);
        if (bpf) args.push(bpf);

        const proc = spawn('python', args, {
            cwd: path.dirname(pyScript),
            windowsHide: true
        });

        let buffer = '';
        const snapshots = [];

        proc.stdout.on('data', (data) => {
            buffer += data.toString();
            let newline;
            while ((newline = buffer.indexOf('\n')) !== -1) {
                const line = buffer.slice(0, newline).trim();
                buffer = buffer.slice(newline + 1);
                if (line && line.startsWith('{')) {
                    try {
                        const snapshot = JSON.parse(line);
                        snapshots.push(snapshot);
                        if (snapshots.length > 100) snapshots.shift();
                        // Forward new_threats to any active SSE subscribers
                        const monitor = liveMonitors.get(monitorId);
                        if (monitor && monitor.sseClients) {
                            const payload = JSON.stringify(snapshot);
                            monitor.sseClients.forEach(res => {
                                try { res.write(`data: ${payload}\n\n`); } catch {}
                            });
                        }
                    } catch {}
                }
            }
        });

        proc.on('error', (err) => {
            console.error('[LiveMonitor] Error:', err.message);
        });

        liveMonitors.set(monitorId, {
            process: proc,
            snapshots,
            sseClients: new Set(),   // SSE response objects subscribed to this monitor
            startTime: Date.now(),
            interface: iface
        });

        res.json({ monitorId, status: 'started' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

router.post('/live/stop', (req, res) => {
    const { monitorId } = req.body;
    const monitor = liveMonitors.get(monitorId);

    if (monitor) {
        if (!monitor.process.killed) monitor.process.kill();
        // Close all SSE clients
        if (monitor.sseClients) {
            monitor.sseClients.forEach(r => { try { r.end(); } catch {} });
            monitor.sseClients.clear();
        }
        const final = monitor.snapshots[monitor.snapshots.length - 1] || {};
        liveMonitors.delete(monitorId);
        res.json({ status: 'stopped', finalStats: final.stats || {} });
    } else {
        res.json({ status: 'not_found' });
    }
});

router.get('/live/snapshot/:monitorId', (req, res) => {
    const monitor = liveMonitors.get(req.params.monitorId);
    if (monitor) {
        const latest = monitor.snapshots[monitor.snapshots.length - 1] || {};
        res.json({
            monitorId: req.params.monitorId,
            running: true,
            duration: (Date.now() - monitor.startTime) / 1000,
            snapshot: latest
        });
    } else {
        res.status(404).json({ error: 'Monitor not found' });
    }
});

router.get('/live/stream/:monitorId', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const monitor = liveMonitors.get(req.params.monitorId);
    if (!monitor) {
        res.write(`data: ${JSON.stringify({ error: 'Monitor not found' })}\n\n`);
        res.end();
        return;
    }

    // Send latest snapshot immediately
    const latest = monitor.snapshots[monitor.snapshots.length - 1];
    if (latest) res.write(`data: ${JSON.stringify(latest)}\n\n`);

    // Register as SSE subscriber — new snapshots pushed in real-time
    monitor.sseClients.add(res);

    req.on('close', () => {
        if (monitor.sseClients) monitor.sseClients.delete(res);
    });
});

module.exports = router;
