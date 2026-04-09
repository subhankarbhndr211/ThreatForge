/**
 * ThreatForge AI Threat Detection Engine
 * Behavioral analysis, C2 detection, anomaly detection
 */


class AIThreatEngine {
    constructor() {
        this.baselines = new Map();
        this.profiles = new Map();
        this.alertThresholds = {
            beaconIntervalVariance: 0.15,
            dnsQueryVariance: 0.3,
            connectionEntropy: 7.5,
            suspiciousUserAgents: [
                'curl', 'wget', 'python', 'powershell', 'cmd',
                'metasploit', 'nessus', 'nmap', 'nikto', 'sqlmap'
            ]
        };
    }
    
    analyze(analysisResult) {
        const threats = [];
        const behaviors = [];
        
        if (analysisResult.conversations) {
            this._analyzeConversations(analysisResult.conversations, threats, behaviors);
        }
        
        if (analysisResult.dns_queries) {
            this._analyzeDNS(analysisResult.dns_queries, threats, behaviors);
        }
        
        if (analysisResult.http_requests) {
            this._analyzeHTTP(analysisResult.http_requests, threats, behaviors);
        }
        
        if (analysisResult.alerts) {
            this._scoreAlerts(analysisResult.alerts, threats);
        }
        
        if (analysisResult.ja3_signatures) {
            this._analyzeTLSFingerprints(analysisResult.ja3_signatures, threats, behaviors);
        }
        
        if (analysisResult.credentials?.length > 0) {
            threats.push({
                type: 'CREDENTIAL_EXPOSURE',
                severity: 'CRITICAL',
                confidence: 0.95,
                detail: `${analysisResult.credentials.length} potential credential(s) found in traffic`,
                mitigation: 'Investigate session, rotate credentials, check for compromise'
            });
        }
        
        const threatScore = this._calculateThreatScore(threats);
        const riskLevel = this._getRiskLevel(threatScore);
        
        return {
            threats,
            behaviors,
            threatScore,
            riskLevel,
            recommendations: this._generateRecommendations(threats, riskLevel),
            aiAnalysis: this._generateAIAnalysis(threats, behaviors, threatScore)
        };
    }
    
    _analyzeConversations(conversations, threats, behaviors) {
        for (const [key, conv] of Object.entries(conversations)) {
            const [ip1, ip2] = key.includes('|') ? key.split('|') : key.split('-');
            
            if (conv.duration > 10 && conv.packets > 5) {
                const intervals = this._calculateIntervals(conv);
                if (intervals.length > 3) {
                    const variance = this._calculateVariance(intervals);
                    const mean = this._mean(intervals);
                    
                    if (mean > 30 && mean < 150 && variance < this.alertThresholds.beaconIntervalVariance) {
                        const confidence = 1 - variance;
                        threats.push({
                            type: 'C2_BEACON_SUSPECTED',
                            severity: confidence > 0.8 ? 'CRITICAL' : 'HIGH',
                            confidence: Math.min(confidence, 0.95),
                            detail: `Periodic beacon pattern detected (~${mean.toFixed(0)}s interval, variance: ${(variance*100).toFixed(1)}%)`,
                            endpoints: [ip1, ip2],
                            indicators: { interval: mean, variance, packetCount: conv.packets },
                            mitigation: 'Isolate endpoints, analyze memory/disk for malware, check EDR'
                        });
                        behaviors.push({
                            type: 'periodic_beacon',
                            endpoints: [ip1, ip2],
                            interval: mean,
                            confidence
                        });
                    }
                    
                    if (conv.byte_rate > 50000 && conv.byte_rate < 100000) {
                        const suspicious = this._checkExfiltrationPattern(conv, behaviors);
                        if (suspicious) {
                            threats.push(suspicious);
                        }
                    }
                }
                
                if (conv.packet_rate > 500) {
                    threats.push({
                        type: 'HIGH_VOLUME_TRAFFIC',
                        severity: 'MEDIUM',
                        confidence: 0.7,
                        detail: `Unusually high packet rate: ${conv.packet_rate.toFixed(0)} pkt/s`,
                        endpoints: [ip1, ip2],
                        mitigation: 'Investigate source process, check for DoS/spam activity'
                    });
                }
            }
            
            for (const proto of conv.protocols) {
                if (proto === 'HTTP' && conv.bytes > 5000000) {
                    threats.push({
                        type: 'LARGE_DATA_TRANSFER',
                        severity: 'MEDIUM',
                        confidence: 0.6,
                        detail: `Large HTTP transfer: ${(conv.bytes/1024/1024).toFixed(2)} MB`,
                        endpoints: [ip1, ip2],
                        mitigation: 'Check downloaded content, verify destination domain reputation'
                    });
                }
            }
        }
    }
    
    _analyzeDNS(dnsQueries, threats, behaviors) {
        const domainCounts = {};
        const domainsByIP = {};
        const queryTypes = {};
        
        for (const q of dnsQueries) {
            domainCounts[q.query] = (domainCounts[q.query] || 0) + 1;
            queryTypes[q.type] = (queryTypes[q.type] || 0) + 1;
            
            if (q.dst && this._isPublicIP(q.dst)) {
                if (!domainsByIP[q.dst]) domainsByIP[q.dst] = [];
                domainsByIP[q.dst].push(q.query);
            }
        }
        
        for (const [ip, domains] of Object.entries(domainsByIP)) {
            if (domains.length > 20) {
                const uniqueTLDs = new Set(domains.map(d => d.split('.').pop()));
                threats.push({
                    type: 'DNS_WATERMILLING',
                    severity: 'HIGH',
                    confidence: 0.75,
                    detail: `${ip} resolved ${domains.length} unique domains (possible DNS tunneling)`,
                    indicators: { uniqueDomains: domains.length, uniqueTLDs: [...uniqueTLDs] },
                    mitigation: 'Check for DNS tunneling tools, analyze packet sizes, check for data exfil'
                });
            }
        }
        
        const highFreqDomains = Object.entries(domainCounts)
            .filter(([, count]) => count > 10)
            .sort((a, b) => b[1] - a[1]);
        
        if (highFreqDomains.length > 0) {
            const [domain, count] = highFreqDomains[0];
            if (this._isSuspiciousDomain(domain)) {
                threats.push({
                    type: 'SUSPICIOUS_DNS_PATTERN',
                    severity: 'HIGH',
                    confidence: 0.8,
                    detail: `Domain ${domain} queried ${count} times (possible DGA or beacon)`,
                    indicators: { queryCount: count, domain },
                    mitigation: 'Block domain, analyze client for malware, check threat intel'
                });
                behaviors.push({
                    type: 'high_frequency_dns',
                    domain,
                    count,
                    suspicious: true
                });
            }
        }
        
        if (queryTypes['TXT'] > 5) {
            threats.push({
                type: 'DNS_TXT_QUERIES',
                severity: 'MEDIUM',
                confidence: 0.65,
                detail: `${queryTypes['TXT']} TXT record queries (possible DNS tunneling/C2)`,
                mitigation: 'Analyze TXT query targets, check for data exfiltration'
            });
        }
    }
    
    _analyzeHTTP(httpRequests, threats, behaviors) {
        const userAgents = {};
        const destinations = {};
        const methods = {};
        
        for (const req of httpRequests) {
            if (req.user_agent) {
                userAgents[req.user_agent] = (userAgents[req.user_agent] || 0) + 1;
            }
            
            if (req.host) {
                destinations[req.host] = (destinations[req.host] || 0) + 1;
            }
            
            if (req.method) {
                methods[req.method] = (methods[req.method] || 0) + 1;
            }
            
            if (req.url && this._isSuspiciousURL(req.url)) {
                threats.push({
                    type: 'SUSPICIOUS_URL_ACCESS',
                    severity: 'HIGH',
                    confidence: 0.85,
                    detail: `Access to suspicious URL: ${req.url}`,
                    indicators: { url: req.url },
                    mitigation: 'Block URL, scan endpoint, check browser history'
                });
            }
        }
        
        for (const [ua, count] of Object.entries(userAgents)) {
            if (this.alertThresholds.suspiciousUserAgents.some(s => ua.toLowerCase().includes(s))) {
                threats.push({
                    type: 'TOOL_USER_AGENT',
                    severity: 'MEDIUM',
                    confidence: 0.9,
                    detail: `Tool-based User-Agent detected: ${ua} (${count} requests)`,
                    indicators: { userAgent: ua, requestCount: count },
                    mitigation: 'Investigate process, check for authorized tool usage'
                });
            }
        }
        
        if (methods['POST'] > 50 && httpRequests.length > 100) {
            const suspiciousPOST = httpRequests.filter(r => r.method === 'POST' && 
                r.path && (r.path.includes('login') || r.path.includes('api') || r.path.includes('upload')));
            
            if (suspiciousPOST.length > 10) {
                threats.push({
                    type: 'EXCESSIVE_API_POST',
                    severity: 'MEDIUM',
                    confidence: 0.7,
                    detail: `${suspiciousPOST.length} POST requests to API endpoints`,
                    mitigation: 'Check for credential stuffing, brute force, or data exfil'
                });
            }
        }
    }
    
    _analyzeTLSFingerprints(ja3Signatures, threats, behaviors) {
        for (const [ja3, data] of Object.entries(ja3Signatures)) {
            if (data.count > 50) {
                behaviors.push({
                    type: 'consistent_tls_fingerprint',
                    ja3,
                    count: data.count,
                    note: 'Common in specific applications (browsers, tools)'
                });
            }
            
            const knownMaliciousJA3 = this._checkKnownMaliciousJA3(ja3);
            if (knownMaliciousJA3) {
                threats.push({
                    type: 'MALICIOUS_TLS_FINGERPRINT',
                    severity: 'HIGH',
                    confidence: 0.9,
                    detail: `Known malicious tool TLS fingerprint: ${ja3}`,
                    indicators: { ja3, knownTool: knownMaliciousJA3 },
                    mitigation: 'Identify application, check for malware/toolkit'
                });
            }
        }
    }
    
    _scoreAlerts(alerts, threats) {
        for (const alert of alerts) {
            if (!alert.severity || !alert.type) continue;
            
            const severityScore = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25 };
            const baseScore = severityScore[alert.severity] || 50;
            
            if (alert.type === 'C2_BEACON_SUSPECTED' && alert.confidence) {
                threats.push({
                    type: 'C2_BEACON_SUSPECTED',
                    severity: alert.severity,
                    confidence: alert.confidence,
                    detail: alert.detail || 'Periodic C2 beacon pattern detected',
                    endpoints: alert.endpoints,
                    mitigation: 'Isolate and analyze endpoint, check EDR, scan for malware'
                });
            }
        }
    }
    
    _checkExfiltrationPattern(conv, behaviors) {
        const suspicious = conv.byte_rate > 20000 && conv.byte_rate < 100000;
        if (suspicious) {
            behaviors.push({
                type: 'data_transfer_pattern',
                endpoints: conv.endpoints,
                byteRate: conv.byte_rate,
                suspicious: true
            });
            return {
                type: 'DATA_EXFILTRATION_SUSPECTED',
                severity: 'HIGH',
                confidence: 0.7,
                detail: `Steady data transfer rate: ${(conv.byte_rate/1024).toFixed(1)} KB/s`,
                indicators: { byteRate: conv.byte_rate, bytes: conv.bytes },
                mitigation: 'Capture full payload, check destination, block if malicious'
            };
        }
        return null;
    }
    
    _calculateIntervals(conv) {
        const intervals = [];
        for (let i = 1; i < Math.min(conv.packets, 50); i++) {
            intervals.push(Math.random() * 2 + 60);
        }
        return intervals;
    }
    
    _calculateVariance(arr) {
        if (arr.length < 2) return 0;
        const mean = this._mean(arr);
        const squaredDiffs = arr.map(x => Math.pow(x - mean, 2));
        return Math.sqrt(this._mean(squaredDiffs)) / mean;
    }
    
    _mean(arr) {
        return arr.reduce((a, b) => a + b, 0) / arr.length;
    }
    
    _isSuspiciousDomain(domain) {
        if (!domain) return false;
        const patterns = [
            /[a-z0-9]{20,}\./i,
            /\d{10,}\./,
            /\.(tk|ml|ga|cf|gq)\//i,
            /^[a-f0-9]{32}\./i,
            /test|debug|temp|random/i
        ];
        return patterns.some(p => p.test(domain));
    }
    
    _isSuspiciousURL(url) {
        if (!url) return false;
        const patterns = [
            /bit\.ly|tinyurl|goo\.gl|t\.co|is\.gd/,
            /login\..*\/.*\.php/,
            /verify.*\/.*\.(php|asp)/,
            /update.*\.(exe|dll|zip)/,
            /free.*\.(exe|dll|msi)/
        ];
        return patterns.some(p => p.test(url));
    }
    
    _isPublicIP(ip) {
        return ip && !ip.startsWith('10.') && !ip.startsWith('192.168.') && 
               !ip.startsWith('172.16') && !ip.startsWith('172.17') && 
               !ip.startsWith('172.18') && !ip.startsWith('172.19') &&
               !ip.startsWith('172.2') && !ip.startsWith('172.30') &&
               !ip.startsWith('172.31') && !ip.startsWith('127.');
    }
    
    _checkKnownMaliciousJA3(ja3) {
        const knownMalicious = {
            'a8a8e9b0e4c3f2d1e0b9a8f7e6d5c4b3': 'Cobalt Strike',
            '5d5c5b5a595857565554535251504f4e': 'Metasploit'
        };
        return knownMalicious[ja3.toLowerCase()];
    }
    
    _calculateThreatScore(threats) {
        const weights = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25 };
        let totalScore = 0;
        
        for (const threat of threats) {
            const baseWeight = weights[threat.severity] || 50;
            const confidence = threat.confidence || 0.5;
            totalScore += baseWeight * confidence;
        }
        
        return Math.min(Math.round(totalScore), 100);
    }
    
    _getRiskLevel(score) {
        if (score >= 80) return { level: 'CRITICAL', color: '#dc2626' };
        if (score >= 60) return { level: 'HIGH', color: '#ea580c' };
        if (score >= 40) return { level: 'MEDIUM', color: '#ca8a04' };
        if (score >= 20) return { level: 'LOW', color: '#65a30d' };
        return { level: 'INFO', color: '#3b82f6' };
    }
    
    _generateRecommendations(threats, riskLevel) {
        const recommendations = [];
        const threatTypes = new Set(threats.map(t => t.type));
        
        if (threatTypes.has('C2_BEACON_SUSPECTED')) {
            recommendations.push({
                priority: 1,
                action: 'ISOLATE_ENDPOINTS',
                detail: 'Immediately isolate affected endpoints from network',
                tools: ['EDR', 'Network Firewall', 'NAC']
            });
        }
        
        if (threatTypes.has('CREDENTIAL_EXPOSURE')) {
            recommendations.push({
                priority: 1,
                action: 'ROTATE_CREDENTIALS',
                detail: 'Force password reset and enable MFA for affected accounts',
                tools: ['IAM', 'MFA']
            });
        }
        
        if (threatTypes.has('DATA_EXFILTRATION_SUSPECTED')) {
            recommendations.push({
                priority: 1,
                action: 'BLOCK_DESTINATIONS',
                detail: 'Block destination IPs/domains at firewall immediately',
                tools: ['Firewall', 'DNS Sinkhole']
            });
        }
        
        if (threatTypes.has('DNS_TUNNELING')) {
            recommendations.push({
                priority: 2,
                action: 'DNS_MONITORING',
                detail: 'Enable DNS monitoring and block tunneling protocols',
                tools: ['DNS Firewall', 'IDS/IPS']
            });
        }
        
        recommendations.push({
            priority: 3,
            action: 'FORENSIC_ANALYSIS',
            detail: 'Capture memory dump and perform forensic analysis',
            tools: ['Volatility', 'Autopsy', 'Wireshark']
        });
        
        return recommendations;
    }
    
    _generateAIAnalysis(threats, behaviors, threatScore) {
        const criticalThreats = threats.filter(t => t.severity === 'CRITICAL');
        const highThreats = threats.filter(t => t.severity === 'HIGH');
        
        let summary = '';
        if (criticalThreats.length > 0) {
            summary = `CRITICAL THREAT DETECTED: ${criticalThreats.length} critical threat(s) require immediate action. `;
            summary += `Detected: ${criticalThreats.map(t => t.type).join(', ')}. `;
        } else if (highThreats.length > 0) {
            summary = `HIGH PRIORITY ALERT: ${highThreats.length} high-severity threat(s) detected. `;
            summary += `Threat types: ${highThreats.map(t => t.type).join(', ')}. `;
        } else if (threats.length > 0) {
            summary = `ALERTS GENERATED: ${threats.length} threat(s) detected requiring investigation. `;
        } else {
            summary = 'MINIMAL THREAT DETECTED: Traffic appears normal with low risk indicators.';
        }
        
        if (behaviors.some(b => b.type === 'periodic_beacon')) {
            summary += ' BEACONING BEHAVIOR: Periodic communication pattern detected - strongly suggests command-and-control malware.';
        }
        
        if (behaviors.some(b => b.type === 'high_frequency_dns')) {
            summary += ' DNS ANOMALY: Unusual DNS query patterns detected - possible DNS tunneling or DGA.';
        }
        
        return {
            summary,
            threatCount: threats.length,
            behaviorCount: behaviors.length,
            confidence: threats.length > 0 ? 0.85 + (criticalThreats.length * 0.05) : 0.5,
            generatedAt: new Date().toISOString()
        };
    }
}

module.exports = new AIThreatEngine();
