/**
 * ThreatForge Enterprise Packet Analysis API
 * Full protocol decoding, threat detection, IOC extraction
 */
'use strict';

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 200 * 1024 * 1024 } });
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const threatIntel = require('../packet/ThreatIntel');
const aiEngine = require('../packet/AIThreatEngine');

const analysisHistory = new Map();
const liveMonitors = new Map();

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DEEP PACKET ANALYSIS ENGINE
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

router.post('/analyze', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded', code: 'NO_FILE' });
    }

    const sessionId = uuidv4();
    const startTime = Date.now();

    try {
        console.log(`[DeepPacket] Analyzing ${req.file.originalname} (${req.file.size} bytes)`);

        // Try Python Scapy engine first
        let result = await analyzeWithPython(req.file.buffer);

        if (!result || result.error) {
            // Fallback to JavaScript parser
            console.log('[DeepPacket] Python unavailable, using JS fallback');
            result = analyzeWithJS(req.file.buffer);
        }

        // Enrich IOCs with threat intel
        if (result?.iocs && (result.iocs.ips?.length || result.iocs.domains?.length)) {
            try {
                const enriched = await threatIntel.enrichIOCs(result.iocs);
                result.enrichedIocs = enriched;
            } catch (e) {
                console.warn('[DeepPacket] Enrichment failed:', e.message);
            }
        }

        // Run AI threat analysis
        try {
            const aiAnalysis = aiEngine.analyze(result);
            result.aiAnalysis = aiAnalysis;
            
            // Merge AI threats with existing threats
            if (aiAnalysis.threats?.length > 0) {
                const existingTypes = new Set(result.threats.map(t => t.type));
                aiAnalysis.threats.forEach(t => {
                    if (!existingTypes.has(t.type)) {
                        result.threats.push(t);
                    }
                });
            }
            
            // Add AI behaviors
            if (aiAnalysis.behaviors?.length > 0) {
                result.behaviors = [...(result.behaviors || []), ...aiAnalysis.behaviors];
            }
        } catch (e) {
            console.warn('[DeepPacket] AI analysis failed:', e.message);
        }

        result.sessionId = sessionId;
        result.timestamp = new Date().toISOString();
        result.filename = req.file.originalname;
        result.fileSize = req.file.size;
        result.analysisTimeMs = Date.now() - startTime;

        // Generate risk assessment
        result.riskAssessment = calculateRiskAssessment(result);

        analysisHistory.set(sessionId, result);
        if (analysisHistory.size > 50) {
            const oldest = analysisHistory.keys().next().value;
            analysisHistory.delete(oldest);
        }

        console.log(`[DeepPacket] Complete: ${result.summary.total_threats} threats, ${result.summary.critical_threats} critical`);

        res.json(result);
    } catch (err) {
        console.error('[DeepPacket] Error:', err);
        res.status(500).json({ error: 'Analysis failed', message: err.message });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PYTHON ANALYSIS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async function analyzeWithPython(buffer) {
    return new Promise((resolve) => {
        const tempFile = path.join(__dirname, '../../packet-engine/temp_' + Date.now() + '.pcap');
        
        fs.writeFileSync(tempFile, buffer);
        
        const pyPath = path.join(__dirname, '../../packet-engine/deep_analyzer.py');
        const proc = spawn('python', [pyPath, tempFile], { timeout: 60000 });

        let stdout = '', stderr = '';
        
        proc.stdout.on('data', d => stdout += d.toString());
        proc.stderr.on('data', d => stderr += d.toString());
        
        proc.on('close', () => {
            try { fs.unlinkSync(tempFile); } catch {}
            
            if (proc.exitCode !== 0) {
                console.error('[Python] Error:', stderr.substring(0, 500));
                resolve({ error: 'Python analysis failed', details: stderr.substring(0, 200) });
                return;
            }
            
            try {
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (e) {
                console.error('[Python] Parse error:', e.message);
                resolve({ error: 'JSON parse failed' });
            }
        });
        
        proc.on('error', (e) => {
            try { fs.unlinkSync(tempFile); } catch {}
            resolve({ error: e.message });
        });
        
        setTimeout(() => {
            if (!proc.killed) {
                proc.kill();
                resolve({ error: 'Analysis timeout' });
            }
        }, 55000);
    });
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// JAVASCRIPT FALLBACK ANALYZER
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function analyzeWithJS(buffer) {
    const view = new DataView(buffer);
    const result = {
        metadata: { total_packets: 0, total_bytes: buffer.byteLength, unique_ips: new Set(), unique_ports: new Set(), protocols: {} },
        conversations: {},
        dns_queries: [],
        http_requests: [],
        tls_sessions: {},
        iocs: { ips: [], domains: [], urls: [], emails: [], hashes: [], credentials: [] },
        threats: [],
        behaviors: [],
        alerts: [],
        files: [],
        summary: {}
    };

    if (buffer.byteLength < 24) return { ...result, metadata: { ...result.metadata, unique_ips: 0, unique_ports: 0 } };

    const magic = view.getUint32(0, true);
    const le = magic === 0xa1b2c3d4;
    if (magic !== 0xa1b2c3d4 && magic !== 0xd4c3b2a1) return result;

    let offset = 24;

    while (offset + 16 <= buffer.byteLength) {
        const inclLen = view.getUint32(offset + 8, le);
        offset += 16;

        if (offset + inclLen > buffer.byteLength) break;

        const pktLen = Math.min(inclLen, 1500);
        const pkt = parsePacketJS(view, offset, pktLen, le);

        if (pkt) {
            result.metadata.total_packets++;
            result.metadata.total_bytes += inclLen;

            if (pkt.srcIp) result.metadata.unique_ips.add(pkt.srcIp);
            if (pkt.dstIp) result.metadata.unique_ips.add(pkt.dstIp);

            const proto = pkt.protocol || 'Unknown';
            result.metadata.protocols[proto] = (result.metadata.protocols[proto] || 0) + 1;

            if (pkt.srcIp && pkt.dstIp) {
                const key = [pkt.srcIp, pkt.dstIp].sort().join('|');
                if (!result.conversations[key]) {
                    result.conversations[key] = { src: pkt.srcIp, dst: pkt.dstIp, packets: 0, bytes: 0, protocols: new Set() };
                }
                result.conversations[key].packets++;
                result.conversations[key].bytes += inclLen;
                result.conversations[key].protocols.add(proto);
            }

            if (pkt.dns) {
                result.dns_queries.push({ query: pkt.dns.query, type: pkt.dns.type, src: pkt.srcIp });
                result.iocs.domains.push(pkt.dns.query);
            }

            if (pkt.http) {
                result.http_requests.push(pkt.http);
                if (pkt.http.url) result.iocs.urls.push(pkt.http.url);
                if (pkt.http.host) result.iocs.domains.push(pkt.http.host);
            }

            if (pkt.iocs) {
                pkt.iocs.ips?.forEach(ip => result.iocs.ips.push(ip));
                pkt.iocs.urls?.forEach(url => result.iocs.urls.push(url));
                pkt.iocs.emails?.forEach(email => result.iocs.emails.push(email));
                pkt.iocs.hashes?.forEach(h => result.iocs.hashes.push(h));
            }

            if (pkt.threats) {
                result.threats.push(...pkt.threats);
            }
        }

        offset += inclLen;
    }

    result.metadata.unique_ips = result.metadata.unique_ips.size;
    result.metadata.unique_ports = result.metadata.unique_ports.size;
    result.metadata.protocols = result.metadata.protocols;

    result.conversations = Object.entries(result.conversations).map(([k, v]) => ({
        src: v.src, dst: v.dst, packets: v.packets, bytes: v.bytes, protocols: [...v.protocols]
    })).sort((a, b) => b.bytes - a.bytes).slice(0, 50);

    result.iocs.ips = [...new Set(result.iocs.ips)];
    result.iocs.domains = [...new Set(result.iocs.domains)];
    result.iocs.urls = [...new Set(result.iocs.urls)];
    result.iocs.hashes = [...new Set(result.iocs.hashes)];

    result.summary = {
        total_threats: result.threats.length,
        critical_threats: result.threats.filter(t => t.severity === 'CRITICAL').length,
        high_threats: result.threats.filter(t => t.severity === 'HIGH').length,
        medium_threats: result.threats.filter(t => t.severity === 'MEDIUM').length,
        files_extracted: result.files.length,
        credentials_found: result.iocs.credentials?.length || 0,
        dns_queries: result.dns_queries.length,
        http_requests: result.http_requests.length,
        beaconing_detected: result.behaviors?.filter(b => b.type === 'C2_BEACON').length || 0
    };

    return result;
}

function parsePacketJS(view, offset, length, le) {
    if (length < 14) return null;

    const etherType = view.getUint16(offset + 12, !le);
    let protoOffset = offset + 14;
    let vlan = null;

    if (etherType === 0x8100) {
        vlan = view.getUint16(protoOffset, !le);
        protoOffset += 4;
    }

    if (etherType !== 0x0800 && etherType !== 0x86DD && etherType !== 0x0806) {
        return { protocol: `Ethertype:0x${etherType.toString(16)}` };
    }

    if (etherType === 0x0806) {
        const opcode = view.getUint16(protoOffset + 6, !le);
        return {
            protocol: 'ARP',
            srcIp: `${view.getUint8(protoOffset+14)}.${view.getUint8(protoOffset+15)}.${view.getUint8(protoOffset+16)}.${view.getUint8(protoOffset+17)}`,
            dstIp: `${view.getUint8(protoOffset+24)}.${view.getUint8(protoOffset+25)}.${view.getUint8(protoOffset+26)}.${view.getUint8(protoOffset+27)}`
        };
    }

    if (length < protoOffset - offset + 20) return null;

    const version = (view.getUint8(protoOffset) >> 4) & 0xF;
    if (version !== 4) return { protocol: 'IPv6' };

    const ihl = (view.getUint8(protoOffset) & 0xF) * 4;
    const proto = view.getUint8(protoOffset + 9);

    const srcIp = `${view.getUint8(protoOffset+12)}.${view.getUint8(protoOffset+13)}.${view.getUint8(protoOffset+14)}.${view.getUint8(protoOffset+15)}`;
    const dstIp = `${view.getUint8(protoOffset+16)}.${view.getUint8(protoOffset+17)}.${view.getUint8(protoOffset+18)}.${view.getUint8(protoOffset+19)}`;

    const transportOffset = protoOffset + ihl;
    const pkt = { srcIp, dstIp, protocol: `IP(${proto})`, iocs: { ips: [], urls: [], emails: [], hashes: [] } };

    if (proto === 6 && length > transportOffset - offset + 20) {
        const srcPort = view.getUint16(transportOffset, !le);
        const dstPort = view.getUint16(transportOffset + 2, !le);
        const flags = view.getUint8(transportOffset + 13);
        const tcpHeaderLen = ((view.getUint8(transportOffset + 12) >> 4) & 0xF) * 4;
        const payloadOffset = transportOffset + tcpHeaderLen;

        pkt.protocol = getProtocolName(dstPort, srcPort);
        pkt.srcPort = srcPort;
        pkt.dstPort = dstPort;
        pkt.tcpFlags = flags;

        if (!isPrivateIP(srcIp)) pkt.iocs.ips.push(srcIp);
        if (!isPrivateIP(dstIp)) pkt.iocs.ips.push(dstIp);

        if (dstPort === 53 || srcPort === 53) {
            pkt.protocol = 'DNS';
            const dnsResult = parseDNS(view, transportOffset + 8, length - (transportOffset + 8 - offset), le);
            if (dnsResult) pkt.dns = dnsResult;
        } else if (dstPort === 80 || srcPort === 80) {
            pkt.protocol = 'HTTP';
            const httpResult = parseHTTP(view, payloadOffset, length - (payloadOffset - offset), le);
            if (httpResult) {
                pkt.http = httpResult;
                if (httpResult.url) pkt.iocs.urls.push(httpResult.url);
                if (httpResult.host) pkt.iocs.ips.push(httpResult.host);
            }
        }

        if (flags & 0x04) {
            pkt.threats = [{ type: 'TCP_RST', severity: 'HIGH', src: srcIp, dst: dstIp }];
        }
    } else if (proto === 17 && length > transportOffset - offset + 8) {
        const srcPort = view.getUint16(transportOffset, !le);
        const dstPort = view.getUint16(transportOffset + 2, !le);

        pkt.protocol = getProtocolName(dstPort, srcPort);
        pkt.srcPort = srcPort;
        pkt.dstPort = dstPort;

        if (dstPort === 53 || srcPort === 53) {
            pkt.protocol = 'DNS';
            const dnsResult = parseDNS(view, transportOffset + 8, length - (transportOffset + 8 - offset), le);
            if (dnsResult) pkt.dns = dnsResult;
        }
    } else if (proto === 1) {
        pkt.protocol = 'ICMP';
    }

    return pkt;
}

function getProtocolName(dstPort, srcPort) {
    if (dstPort === 80 || srcPort === 80) return 'HTTP';
    if (dstPort === 443 || srcPort === 443) return 'HTTPS';
    if (dstPort === 22) return 'SSH';
    if (dstPort === 21) return 'FTP';
    if (dstPort === 25) return 'SMTP';
    if (dstPort === 53 || srcPort === 53) return 'DNS';
    if (dstPort === 3306) return 'MySQL';
    if (dstPort === 5432) return 'PostgreSQL';
    if (dstPort === 6379) return 'Redis';
    if (dstPort === 27017) return 'MongoDB';
    return 'TCP';
}

function parseDNS(view, offset, length, le) {
    if (length < 12) return null;

    try {
        const flags = view.getUint16(offset + 2, le);
        const questions = view.getUint16(offset + 4, le);

        if (questions > 0) {
            let pos = offset + 12;
            const labels = [];
            while (pos < offset + length && view.getUint8(pos) !== 0) {
                const len = view.getUint8(pos);
                if ((len & 0xC0) === 0xC0) { pos += 2; break; }
                let label = '';
                for (let i = 0; i < len; i++) label += String.fromCharCode(view.getUint8(pos + 1 + i));
                labels.push(label);
                pos += len + 1;
            }
            const qtype = view.getUint16(pos + 1, le);
            const types = {1: 'A', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA'};
            return { query: labels.join('.'), type: types[qtype] || `T${qtype}` };
        }
    } catch {}
    return null;
}

function parseHTTP(view, offset, length, le) {
    if (length < 10) return null;

    try {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(
            new Uint8Array(view.buffer, offset, Math.min(length, 2048))
        );

        const lines = text.split(/\r?\n/);
        if (!lines[0]) return null;

        const firstLine = lines[0];

        if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)/i.test(firstLine)) {
            const parts = firstLine.split(' ');
            const headers = {};
            for (let i = 1; i < lines.length && lines[i]; i++) {
                const colon = lines[i].indexOf(':');
                if (colon > 0) {
                    headers[lines[i].substring(0, colon).toLowerCase()] = lines[i].substring(colon + 1).trim();
                }
            }
            return {
                method: parts[0],
                path: parts[1],
                host: headers['host'],
                url: headers['host'] ? `http://${headers['host']}${parts[1]}` : parts[1],
                user_agent: headers['user-agent'],
                referer: headers['referer']
            };
        }

        if (/^HTTP\/\d\.\d/i.test(firstLine)) {
            const parts = firstLine.split(' ');
            return { status: parseInt(parts[1]), version: parts[0] };
        }
    } catch {}
    return null;
}

function isPrivateIP(ip) {
    if (!ip) return true;
    return ip.startsWith('10.') || ip.startsWith('192.168.') ||
           ip.startsWith('172.16') || ip.startsWith('172.17') ||
           ip.startsWith('172.18') || ip.startsWith('172.19') ||
           ip.startsWith('172.2') || ip.startsWith('172.30') ||
           ip.startsWith('172.31') || ip.startsWith('127.') ||
           ip === '0.0.0.0';
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// RISK ASSESSMENT
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function calculateRiskAssessment(result) {
    let score = 0;
    const factors = [];

    if (result.summary.critical_threats > 0) {
        score += result.summary.critical_threats * 25;
        factors.push(`${result.summary.critical_threats} CRITICAL threats`);
    }

    if (result.summary.high_threats > 0) {
        score += result.summary.high_threats * 15;
        factors.push(`${result.summary.high_threats} HIGH threats`);
    }

    if (result.iocs.credentials?.length > 0) {
        score += 30;
        factors.push('Exposed credentials detected');
    }

    if (result.summary.beaconing_detected > 0) {
        score += 35;
        factors.push('C2 beaconing detected');
    }

    if (result.files?.length > 0) {
        score += 15;
        factors.push(`${result.files.length} files extracted`);
    }

    const suspiciousDomains = result.iocs.domains.filter(d =>
        /bit\.ly|tinyurl|\.tk$|\.ml$|\.ga$|\.cf$|\.gq$/.test(d)
    );
    if (suspiciousDomains.length > 0) {
        score += 20;
        factors.push(`${suspiciousDomains.length} suspicious domains`);
    }

    score = Math.min(score, 100);

    return {
        score,
        level: score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'LOW' : 'INFO',
        factors,
        recommendation: score >= 60 ? 'IMMEDIATE INVESTIGATION REQUIRED' :
                        score >= 40 ? 'INVESTIGATE PROMPTLY' :
                        score >= 20 ? 'MONITOR CLOSELY' : 'NO ACTION REQUIRED'
    };
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// API ROUTES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

router.get('/session/:id', (req, res) => {
    const session = analysisHistory.get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json(session);
});

router.get('/history', (req, res) => {
    const sessions = Array.from(analysisHistory.values())
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 50)
        .map(s => ({
            sessionId: s.sessionId,
            timestamp: s.timestamp,
            filename: s.filename,
            threatScore: s.riskAssessment?.score || 0,
            riskLevel: s.riskAssessment?.level || 'INFO',
            totalPackets: s.metadata?.total_packets || 0,
            totalThreats: s.summary?.total_threats || 0
        }));
    res.json({ total: analysisHistory.size, sessions });
});

router.get('/stats', (req, res) => {
    const totals = { sessions: analysisHistory.size, threats: 0, critical: 0 };
    for (const s of analysisHistory.values()) {
        totals.threats += s.summary?.total_threats || 0;
        totals.critical += s.summary?.critical_threats || 0;
    }
    res.json(totals);
});

router.delete('/clear', (req, res) => {
    analysisHistory.clear();
    res.json({ message: 'History cleared' });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// LIVE MONITORING
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

router.get('/monitor/interfaces', async (req, res) => {
    try {
        const interfaces = await getNetworkInterfaces();
        res.json(interfaces);
    } catch (e) {
        res.json([{ name: 'any', ip: '0.0.0.0', description: 'All interfaces' }]);
    }
});

router.post('/monitor/start', async (req, res) => {
    const { interface: iface, bpf, duration, maxPackets } = req.body;
    const monitorId = `monitor_${Date.now()}`;
    
    try {
        const monitor = await startLiveMonitor(monitorId, iface, bpf, duration, maxPackets);
        liveMonitors.set(monitorId, monitor);
        res.json({ success: true, monitorId, stats: monitor.stats });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

router.post('/monitor/stop', (req, res) => {
    const { monitorId } = req.body;
    const monitor = liveMonitors.get(monitorId);
    
    if (monitor && monitor.process) {
        monitor.process.kill();
        liveMonitors.delete(monitorId);
        res.json({ success: true, duration: (Date.now() - monitor.startTime) / 1000 });
    } else {
        res.json({ success: false, error: 'Monitor not found' });
    }
});

router.get('/monitor/status/:monitorId', (req, res) => {
    const monitor = liveMonitors.get(req.params.monitorId);
    if (monitor) {
        res.json({
            running: true,
            duration: (Date.now() - monitor.startTime) / 1000,
            packets: monitor.stats.packets,
            bytes: monitor.stats.bytes,
            protocols: monitor.stats.protocols
        });
    } else {
        res.json({ running: false });
    }
});

router.get('/monitor/snapshots', (req, res) => {
    const snapshots = [];
    for (const [id, monitor] of liveMonitors) {
        snapshots.push({
            monitorId: id,
            duration: (Date.now() - monitor.startTime) / 1000,
            packets: monitor.stats.packets,
            topIPs: Object.entries(monitor.stats.topIPs || {}).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, count]) => ({ ip, count })),
            protocols: monitor.stats.protocols
        });
    }
    res.json(snapshots);
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// EXPORT FUNCTIONS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

router.get('/export/:sessionId/:format', (req, res) => {
    const session = analysisHistory.get(req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    
    const format = req.params.format.toLowerCase();
    
    switch (format) {
        case 'json':
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="analysis_${session.sessionId}.json"`);
            res.json(session);
            break;
            
        case 'csv':
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="analysis_${session.sessionId}.csv"`);
            res.send(exportToCSV(session));
            break;
            
        case 'ioc':
            res.setHeader('Content-Type', 'text/plain');
            res.setHeader('Content-Disposition', `attachment; filename="iocs_${session.sessionId}.txt"`);
            res.send(exportIOCs(session));
            break;
            
        default:
            res.status(400).json({ error: 'Unsupported format. Use: json, csv, or ioc' });
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// LIVE MONITOR IMPLEMENTATION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function getNetworkInterfaces() {
    return new Promise((resolve) => {
        const pyPath = path.join(__dirname, '../../packet-engine/live_monitor.py');
        const proc = spawn('python', ['-c', `
import sys
sys.path.insert(0, r'${path.dirname(pyPath).replace(/\\/g, '\\\\')}')
from live_monitor import list_interfaces
import json
print(json.dumps(list_interfaces()))
`], { windowsHide: true, timeout: 5000 });

        let output = '';
        proc.stdout.on('data', d => output += d.toString());
        proc.on('close', () => {
            try { resolve(JSON.parse(output)); }
            catch { resolve([{ name: 'any', ip: '0.0.0.0', description: 'All interfaces' }]); }
        });
        proc.on('error', () => resolve([{ name: 'any', ip: '0.0.0.0', description: 'All interfaces' }]));
    });
}

function startLiveMonitor(monitorId, iface, bpfFilter, duration, maxPackets) {
    return new Promise((resolve, reject) => {
        const pyPath = path.join(__dirname, '../../packet-engine/live_monitor.py');
        const args = [pyPath, '--monitor'];
        if (iface) args.push(iface);
        if (bpfFilter) args.push(bpfFilter);
        if (maxPackets) args.push('--max-packets', String(maxPackets));
        
        const proc = spawn('python', args, { cwd: path.dirname(pyPath), windowsHide: true });
        
        const monitor = {
            id: monitorId,
            process: proc,
            startTime: Date.now(),
            interface: iface,
            bpf: bpfFilter,
            stats: {
                packets: 0,
                bytes: 0,
                protocols: {},
                topIPs: {},
                threats: []
            }
        };
        
        let buffer = '';
        proc.stdout.on('data', (data) => {
            buffer += data.toString();
            let newline;
            while ((newline = buffer.indexOf('\n')) !== -1) {
                const line = buffer.slice(0, newline).trim();
                buffer = buffer.slice(newline + 1);
                if (line) {
                    try {
                        const packet = JSON.parse(line);
                        updateMonitorStats(monitor, packet);
                    } catch {}
                }
            }
        });
        
        proc.stderr.on('data', d => console.error('[Monitor]', d.toString()));
        proc.on('error', reject);
        proc.on('close', (code) => {
            if (code !== 0 && code !== null) {
                console.log(`[Monitor] Process exited with code ${code}`);
            }
        });
        
        if (duration) {
            setTimeout(() => {
                if (liveMonitors.has(monitorId)) {
                    proc.kill();
                    liveMonitors.delete(monitorId);
                }
            }, duration * 1000);
        }
        
        resolve(monitor);
    });
}

function updateMonitorStats(monitor, packet) {
    monitor.stats.packets++;
    monitor.stats.bytes += packet.length || 0;
    
    if (packet.protocol) {
        monitor.stats.protocols[packet.protocol] = (monitor.stats.protocols[packet.protocol] || 0) + 1;
    }
    
    if (packet.src) {
        monitor.stats.topIPs[packet.src] = (monitor.stats.topIPs[packet.src] || 0) + 1;
    }
    if (packet.dst) {
        monitor.stats.topIPs[packet.dst] = (monitor.stats.topIPs[packet.dst] || 0) + 1;
    }
    
    if (packet.threat) {
        monitor.stats.threats.push(packet.threat);
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// EXPORT HELPERS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function exportToCSV(session) {
    const lines = ['Type,Value,Severity,Context'];
    
    if (session.iocs?.ips) {
        session.iocs.ips.forEach(ip => {
            lines.push(`IP,"${ip}",,`);
        });
    }
    
    if (session.iocs?.domains) {
        session.iocs.domains.forEach(d => {
            lines.push(`Domain,"${d}",,`);
        });
    }
    
    if (session.iocs?.urls) {
        session.iocs.urls.forEach(u => {
            lines.push(`URL,"${u}",,`);
        });
    }
    
    if (session.threats) {
        session.threats.forEach(t => {
            lines.push(`Threat,"${t.type}",${t.severity},"${t.detail || ''}"`);
        });
    }
    
    return lines.join('\n');
}

function exportIOCs(session) {
    const lines = ['# IOCs Extracted from Packet Analysis', `# Session: ${session.sessionId}`, `# Generated: ${session.timestamp}`, ''];
    
    if (session.iocs?.ips?.length) {
        lines.push('# IP Addresses');
        session.iocs.ips.forEach(ip => lines.push(ip));
        lines.push('');
    }
    
    if (session.iocs?.domains?.length) {
        lines.push('# Domains');
        session.iocs.domains.forEach(d => lines.push(d));
        lines.push('');
    }
    
    if (session.iocs?.urls?.length) {
        lines.push('# URLs');
        session.iocs.urls.forEach(u => lines.push(u));
        lines.push('');
    }
    
    if (session.iocs?.hashes?.length) {
        lines.push('# File Hashes');
        session.iocs.hashes.forEach(h => lines.push(h));
        lines.push('');
    }
    
    if (session.iocs?.credentials?.length) {
        lines.push('# Credentials (FOUND IN TRAFFIC - INVESTIGATE IMMEDIATELY)');
        session.iocs.credentials.forEach(c => lines.push(c));
        lines.push('');
    }
    
    return lines.join('\n');
}

module.exports = router;
