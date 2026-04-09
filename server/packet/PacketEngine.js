/**
 * ThreatForge Packet Engine - Node.js Wrapper
 * Integrates Python Scapy engine with Express API
 */
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

class PacketEngine {
    constructor() {
        this.pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        this.enginePath = path.join(__dirname, '..', '..', 'packet-engine', 'packet_analyzer.py');
        this.analysisCache = new Map();
        this.maxCacheSize = 50;
    }
    
    analyzeBuffer(buffer) {
        return new Promise((resolve, reject) => {
            const tempFile = path.join(os.tmpdir(), `pkt_${Date.now()}.pcap`);
            
            fs.writeFile(tempFile, buffer, (err) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                console.log('[PacketEngine] Using path:', this.enginePath);
                
                const proc = spawn(this.pythonCmd, [this.enginePath, tempFile], {
                    cwd: path.dirname(this.enginePath),
                    windowsHide: true,
                    timeout: 30000
                });
                
                let stdout = '';
                let stderr = '';
                
                proc.stdout.on('data', (data) => { stdout += data.toString(); });
                proc.stderr.on('data', (data) => { stderr += data.toString(); });
                
                proc.on('error', (err) => {
                    console.error('[PacketEngine] Spawn error:', err.message);
                    fs.unlink(tempFile, () => {});
                    resolve(this._fallbackParse(buffer));
                });
                
                proc.on('close', (code) => {
                    fs.unlink(tempFile, () => {});
                    
                    if (code !== 0) {
                        console.error('[PacketEngine] Python exit code:', code, stderr.substring(0, 500));
                        resolve(this._fallbackParse(buffer));
                        return;
                    }
                    
                    try {
                        const result = JSON.parse(stdout);
                        console.log('[PacketEngine] Python success, packets:', result.statistics?.total_packets);
                        resolve(result);
                    } catch (e) {
                        console.error('[PacketEngine] JSON parse error:', e.message, 'Output:', stdout.substring(0, 200));
                        resolve(this._fallbackParse(buffer));
                    }
                });
                
                setTimeout(() => {
                    if (!proc.killed) {
                        console.warn('[PacketEngine] Python timeout, using fallback');
                        proc.kill();
                    }
                }, 25000);
            });
        });
    }
    
    analyzeFile(filePath) {
        return new Promise((resolve, reject) => {
            if (!fs.existsSync(filePath)) {
                reject(new Error('File not found'));
                return;
            }
            
            const proc = spawn(this.pythonCmd, [this.enginePath, filePath], {
                cwd: path.dirname(this.enginePath),
                windowsHide: true,
                timeout: 60000
            });
            
            let stdout = '';
            let stderr = '';
            
            proc.stdout.on('data', (data) => { stdout += data.toString(); });
            proc.stderr.on('data', (data) => { stderr += data.toString(); });
            
            proc.on('close', (code) => {
                if (code !== 0) {
                    console.error('[PacketEngine] Python error:', stderr);
                    reject(new Error(stderr));
                    return;
                }
                
                try {
                    const result = JSON.parse(stdout);
                    resolve(result);
                } catch (e) {
                    reject(e);
                }
            });
        });
    }
    
    _fallbackParse(buffer) {
        const result = {
            statistics: {
                total_packets: 0,
                total_bytes: buffer.length,
                protocols: {},
                unique_ips: 0,
                unique_ports: 0
            },
            conversations: {},
            dns_queries: [],
            http_requests: [],
            tls_connections: [],
            urls: [],
            emails: [],
            credentials: [],
            files: [],
            ja3_signatures: {},
            iocs: { ips: [], domains: [], urls: [], hashes: [], emails: [], credentials: [] },
            alerts: [],
            summary: {
                total_packets: 0,
                unique_ips: 0,
                unique_ports: 0,
                total_dns_queries: 0,
                total_http_requests: 0,
                total_tls_connections: 0,
                total_alerts: 0,
                critical_alerts: 0,
                high_alerts: 0,
                iocs_count: 0
            },
            _fallback: true
        };
        
        if (buffer.length < 24) return result;
        
        const magic = buffer.readUInt32LE(0);
        if (magic !== 0xa1b2c3d4 && magic !== 0xd4c3b2a1) return result;
        
        const isBigEndian = magic === 0xd4c3b2a1;
        const read32 = isBigEndian ? (o) => buffer.readUInt32BE(o) : (o) => buffer.readUInt32LE(o);
        const read16 = isBigEndian ? (o) => buffer.readUInt16BE(o) : (o) => buffer.readUInt16LE(o);
        
        let offset = 24;
        let firstTs = null;
        let lastTs = null;
        const ips = new Set();
        const ports = new Set();
        const conversations = {};
        
        while (offset + 16 <= buffer.length) {
            const tsSec = read32(offset);
            const tsUsec = read32(offset + 4);
            const inclLen = read32(offset + 8);
            const origLen = read32(offset + 12);
            offset += 16;
            
            if (offset + inclLen > buffer.length) break;
            
            const pktData = buffer.slice(offset, offset + inclLen);
            offset += inclLen;
            
            const ts = tsSec + tsUsec / 1e6;
            if (!firstTs) firstTs = ts;
            lastTs = ts;
            
            result.statistics.total_packets++;
            result.summary.total_packets++;
            
            if (pktData.length >= 14) {
                const etherType = pktData.readUInt16BE(12);
                const ipOffset = etherType === 0x8100 ? 18 : 14;
                
                if ((etherType === 0x0800 || etherType === 0x86DD) && pktData.length >= ipOffset + 20) {
                    if (etherType === 0x0800) {
                        const proto = pktData[ipOffset + 9];
                        const srcIp = `${pktData[ipOffset+12]}.${pktData[ipOffset+13]}.${pktData[ipOffset+14]}.${pktData[ipOffset+15]}`;
                        const dstIp = `${pktData[ipOffset+16]}.${pktData[ipOffset+17]}.${pktData[ipOffset+18]}.${pktData[ipOffset+19]}`;
                        
                        ips.add(srcIp);
                        ips.add(dstIp);
                        
                        const key = [srcIp, dstIp].sort().join('|');
                        if (!conversations[key]) {
                            conversations[key] = { packets: 0, bytes: 0, protocols: new Set() };
                        }
                        conversations[key].packets++;
                        conversations[key].bytes += origLen;
                        
                        const transportOffset = ipOffset + (pktData[ipOffset] & 0x0f) * 4;
                        
                        if (proto === 6 && pktData.length >= transportOffset + 20) {
                            const srcPort = pktData.readUInt16BE(transportOffset);
                            const dstPort = pktData.readUInt16BE(transportOffset + 2);
                            ports.add(srcPort);
                            ports.add(dstPort);
                            
                            let protoName = 'TCP';
                            const tcpHeaderLen = ((pktData[transportOffset + 12] >> 4) & 0xf) * 4;
                            const payload = pktData.slice(transportOffset + tcpHeaderLen);
                            
                            if (dstPort === 80 || srcPort === 80) protoName = 'HTTP';
                            else if (dstPort === 443 || srcPort === 443) protoName = 'HTTPS/TLS';
                            else if (dstPort === 53 || srcPort === 53) protoName = 'DNS';
                            else if (dstPort === 22) protoName = 'SSH';
                            else if (dstPort === 21) protoName = 'FTP';
                            else if (dstPort === 25) protoName = 'SMTP';
                            
                            conversations[key].protocols.add(protoName);
                            result.statistics.protocols[protoName] = (result.statistics.protocols[protoName] || 0) + 1;
                            
                            if (payload.length > 0) {
                                try {
                                    const text = payload.toString('utf-8', 0, Math.min(payload.length, 1024));
                                    
                                    const urlMatches = text.match(/https?:\/\/[^\s<>"{}|\\^`\[\]]+/g);
                                    if (urlMatches) {
                                        urlMatches.forEach(url => {
                                            result.urls.push({ url, ts });
                                            result.iocs.urls.push(url);
                                            result.summary.iocs_count++;
                                        });
                                    }
                                    
                                    const emailMatches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
                                    if (emailMatches) {
                                        emailMatches.forEach(email => {
                                            result.emails.push({ email, ts });
                                            result.iocs.emails.push(email);
                                        });
                                    }
                                    
                                    if (dstPort === 80 && text.includes('GET ')) {
                                        const match = text.match(/GET\s+(\S+)\s+HTTP/);
                                        if (match) {
                                            result.http_requests.push({
                                                method: 'GET',
                                                path: match[1],
                                                src: srcIp,
                                                timestamp: ts
                                            });
                                            result.summary.total_http_requests++;
                                        }
                                    }
                                    
                                } catch {}
                            }
                        }
                        else if (proto === 17 && pktData.length >= transportOffset + 8) {
                            const srcPort = pktData.readUInt16BE(transportOffset);
                            const dstPort = pktData.readUInt16BE(transportOffset + 2);
                            ports.add(srcPort);
                            ports.add(dstPort);
                            
                            if (dstPort === 53 || srcPort === 53) {
                                result.statistics.protocols['DNS']++;
                                const payload = pktData.slice(transportOffset + 8);
                                
                                if (payload.length > 12) {
                                    try {
                                        let pos = 12;
                                        const labels = [];
                                        while (pos < payload.length && payload[pos] !== 0) {
                                            const len = payload[pos++];
                                            if (len === 0) break;
                                            labels.push(payload.slice(pos, pos + len).toString('ascii'));
                                            pos += len;
                                        }
                                        if (labels.length > 0) {
                                            const query = labels.join('.');
                                            result.dns_queries.push({
                                                query,
                                                type: 'A',
                                                timestamp: ts,
                                                src: srcIp
                                            });
                                            result.iocs.domains.push(query);
                                            result.summary.total_dns_queries++;
                                        }
                                    } catch {}
                                }
                            }
                        }
                        else if (proto === 1) {
                            result.statistics.protocols['ICMP']++;
                        }
                    }
                }
                else if (etherType === 0x0806) {
                    result.statistics.protocols['ARP']++;
                }
            }
        }
        
        result.statistics.unique_ips = ips.size;
        result.statistics.unique_ports = ports.size;
        result.summary.unique_ips = ips.size;
        result.summary.unique_ports = ports.size;
        result.conversations = {};
        Object.entries(conversations).forEach(([key, val]) => {
            result.conversations[key] = {
                ...val,
                protocols: [...val.protocols]
            };
        });
        result.iocs.ips = [...ips];
        result.iocs.domains = [...new Set(result.iocs.domains)];
        result.iocs.urls = [...new Set(result.iocs.urls)];
        
        return result;
    }
    
    getCacheStats() {
        return {
            size: this.analysisCache.size,
            maxSize: this.maxCacheSize
        };
    }
}

module.exports = new PacketEngine();
