/**
 * ThreatForge Threat Intelligence Module
 * Enriches IOCs with VirusTotal, AbuseIPDB, ThreatFox, OTX
 */
const https = require('https');
const http = require('http');

class ThreatIntel {
    constructor() {
        this.cache = new Map();
        this.cacheTTL = 15 * 60 * 1000;
        this.rateLimits = { vt: 0, abuseipdb: 0, threatfox: 0, otx: 0 };
    }
    
    async enrichIOCs(iocs, options = {}) {
        const enriched = {
            ips: [],
            domains: [],
            urls: [],
            hashes: [],
            summary: { enriched: 0, malicious: 0, suspicious: 0, clean: 0 }
        };
        
        const parallel = options.parallel || 5;
        
        if (iocs.ips?.length) {
            const chunks = this._chunk(iocs.ips, parallel);
            for (const chunk of chunks) {
                const results = await Promise.all(chunk.map(ip => this.enrichIP(ip)));
                enriched.ips.push(...results);
            }
        }
        
        if (iocs.domains?.length) {
            const chunks = this._chunk(iocs.domains, parallel);
            for (const chunk of chunks) {
                const results = await Promise.all(chunk.map(domain => this.enrichDomain(domain)));
                enriched.domains.push(...results);
            }
        }
        
        if (iocs.hashes?.length) {
            const chunks = this._chunk(iocs.hashes, parallel);
            for (const chunk of chunks) {
                const results = await Promise.all(chunk.map(hash => this.enrichHash(hash)));
                enriched.urls.push(...results);
            }
        }
        
        return enriched;
    }
    
    async enrichIP(ip) {
        if (this._isPrivateIP(ip)) {
            return { ip, status: 'private', reputation: 'N/A', geo: this._getPrivateIPGeo(ip) };
        }
        
        const cacheKey = `ip:${ip}`;
        const cached = this._getCached(cacheKey);
        if (cached) return cached;
        
        const result = { ip, sources: {}, geo: {} };
        
        try {
            const geoData = await this._queryGeoIP(ip);
            result.geo = geoData;
        } catch {}
        
        if (process.env.ABUSEIPDB_KEY) {
            try {
                const abuseData = await this._queryAbuseIPDB(ip);
                result.sources.abuseipdb = abuseData;
                result.reputation = abuseData.abuseConfidenceScore > 50 ? 'malicious' : 
                                    abuseData.abuseConfidenceScore > 25 ? 'suspicious' : 'clean';
            } catch {}
        }
        
        if (process.env.VIRUSTOTAL_KEY) {
            try {
                const vtData = await this._queryVirusTotalIP(ip);
                result.sources.virustotal = vtData;
                if (vtData.last_analysis_stats) {
                    const stats = vtData.last_analysis_stats;
                    result.reputation = stats.malicious > 5 ? 'malicious' : 
                                        stats.malicious > 0 ? 'suspicious' : 'clean';
                }
                if (vtData.asn) result.asn = vtData.asn;
            } catch {}
        }
        
        if (process.env.OTX_KEY) {
            try {
                const otxData = await this._queryOTX(ip);
                result.sources.otx = otxData;
            } catch {}
        }
        
        result.status = result.reputation || 'unknown';
        this._setCached(cacheKey, result);
        return result;
    }
    
    _getPrivateIPGeo(ip) {
        if (ip.startsWith('10.')) return { city: 'Private', country: 'RFC1918', org: 'Private Network' };
        if (ip.startsWith('192.168.')) return { city: 'Private', country: 'RFC1918', org: 'Private Network' };
        if (ip.startsWith('172.')) return { city: 'Private', country: 'RFC1918', org: 'Private Network' };
        if (ip.startsWith('127.')) return { city: 'Localhost', country: 'RFC1122', org: 'Loopback' };
        return { city: 'Unknown', country: 'Unknown' };
    }
    
    async _queryGeoIP(ip) {
        const url = `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,region,regionName,org,isp,as,query`;
        const data = await this._httpGet(url);
        if (data.status === 'success') {
            return {
                city: data.city || 'Unknown',
                region: data.regionName || 'Unknown',
                country: data.country || 'Unknown',
                countryCode: data.countryCode || '',
                org: data.org || '',
                isp: data.isp || '',
                asn: data.as ? `AS${data.as}` : ''
            };
        }
        return {};
    }
    
    async enrichDomain(domain) {
        const cacheKey = `domain:${domain}`;
        const cached = this._getCached(cacheKey);
        if (cached) return cached;
        
        const result = { domain, sources: {} };
        
        if (process.env.VIRUSTOTAL_KEY) {
            try {
                const vtData = await this._queryVirusTotalDomain(domain);
                result.sources.virustotal = vtData;
                if (vtData.last_analysis_stats) {
                    const stats = vtData.last_analysis_stats;
                    result.reputation = stats.malicious > 5 ? 'malicious' : 
                                        stats.malicious > 0 ? 'suspicious' : 'clean';
                }
                if (vtData.registrar) result.registrar = vtData.registrar;
                if (vtData.creation_date) result.registered = vtData.creation_date;
            } catch {}
        }
        
        if (process.env.ABUSEIPDB_KEY && domain.match(/^\d+\.\d+\.\d+\.\d+$/)) {
            try {
                const abuseData = await this._queryAbuseIPDB(domain);
                result.sources.abuseipdb = abuseData;
            } catch {}
        }
        
        if (process.env.OTX_KEY) {
            try {
                const otxData = await this._queryOTXDomain(domain);
                result.sources.otx = otxData;
            } catch {}
        }
        
        result.status = result.reputation || 'unknown';
        this._setCached(cacheKey, result);
        return result;
    }
    
    async enrichHash(hash) {
        const cacheKey = `hash:${hash}`;
        const cached = this._getCached(cacheKey);
        if (cached) return cached;
        
        const result = { hash, sources: {} };
        
        if (process.env.VIRUSTOTAL_KEY) {
            try {
                const vtData = await this._queryVirusTotalHash(hash);
                result.sources.virustotal = vtData;
                if (vtData.last_analysis_stats) {
                    const stats = vtData.last_analysis_stats;
                    result.reputation = stats.malicious > 5 ? 'malicious' : 
                                        stats.malicious > 0 ? 'suspicious' : 'clean';
                }
                if (vtData.meaningful_name) result.name = vtData.meaningful_name;
                if (vtData.type_description) result.type = vtData.type_description;
            } catch {}
        }
        
        if (process.env.THREATFOX_KEY) {
            try {
                const tfData = await this._queryThreatFox(hash);
                result.sources.threatfox = tfData;
            } catch {}
        }
        
        result.status = result.reputation || 'unknown';
        this._setCached(cacheKey, result);
        return result;
    }
    
    async _queryAbuseIPDB(ip) {
        const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`;
        const data = await this._httpGet(url, {
            Key: process.env.ABUSEIPDB_KEY,
            Accept: 'application/json'
        });
        return data.data || {};
    }
    
    async _queryVirusTotalIP(ip) {
        const url = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;
        const data = await this._httpGet(url, {
            'x-apikey': process.env.VIRUSTOTAL_KEY
        });
        return data.data?.attributes || {};
    }
    
    async _queryVirusTotalDomain(domain) {
        const url = `https://www.virustotal.com/api/v3/domains/${domain}`;
        const data = await this._httpGet(url, {
            'x-apikey': process.env.VIRUSTOTAL_KEY
        });
        return data.data?.attributes || {};
    }
    
    async _queryVirusTotalHash(hash) {
        const url = `https://www.virustotal.com/api/v3/files/${hash}`;
        const data = await this._httpGet(url, {
            'x-apikey': process.env.VIRUSTOTAL_KEY
        });
        return data.data?.attributes || {};
    }
    
    async _queryOTX(ip) {
        const url = `https://otx.alienvault.com/api/v1/indicator/ipv4/${ip}/general`;
        const data = await this._httpGet(url, {
            'X-OTX-API-KEY': process.env.OTX_KEY
        });
        return data || {};
    }
    
    async _queryOTXDomain(domain) {
        const url = `https://otx.alienvault.com/api/v1/indicator/domain/${domain}/general`;
        const data = await this._httpGet(url, {
            'X-OTX-API-KEY': process.env.OTX_KEY
        });
        return data || {};
    }
    
    async _queryThreatFox(hash) {
        const body = JSON.stringify({ "query": "info", "hash": hash });
        const data = await this._httpPost(
            'https://threatfox-api.abuse.ch/api/v1/',
            body,
            { 'Content-Type': 'application/json', 'API-KEY': process.env.THREATFOX_KEY }
        );
        return data || {};
    }
    
    _httpGet(url, headers = {}) {
        return new Promise((resolve, reject) => {
            const lib = url.startsWith('https') ? https : http;
            const req = lib.get(url, { headers, signal: AbortSignal.timeout(5000) }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try { resolve(JSON.parse(data)); }
                    catch { resolve({}); }
                });
            });
            req.on('error', reject);
            req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
        });
    }
    
    _httpPost(url, body, headers = {}) {
        return new Promise((resolve, reject) => {
            const lib = url.startsWith('https') ? https : http;
            const req = lib.request(url, { method: 'POST', headers }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try { resolve(JSON.parse(data)); }
                    catch { resolve({}); }
                });
            });
            req.on('error', reject);
            req.write(body);
            req.end();
        });
    }
    
    _isPrivateIP(ip) {
        return ip.startsWith('10.') || 
               ip.startsWith('172.16') || ip.startsWith('172.17') || ip.startsWith('172.18') ||
               ip.startsWith('172.19') || ip.startsWith('172.20') || ip.startsWith('172.21') ||
               ip.startsWith('172.22') || ip.startsWith('172.23') || ip.startsWith('172.24') ||
               ip.startsWith('172.25') || ip.startsWith('172.26') || ip.startsWith('172.27') ||
               ip.startsWith('172.28') || ip.startsWith('172.29') || ip.startsWith('172.30') ||
               ip.startsWith('172.31') ||
               ip.startsWith('192.168.') ||
               ip.startsWith('127.') ||
               ip === '255.255.255.255' ||
               ip === '0.0.0.0';
    }
    
    _chunk(arr, size) {
        return arr.reduce((chunks, item, i) => {
            if (i % size === 0) chunks.push([]);
            chunks[chunks.length - 1].push(item);
            return chunks;
        }, []);
    }
    
    _getCached(key) {
        const entry = this.cache.get(key);
        if (entry && Date.now() - entry.time < this.cacheTTL) {
            return entry.data;
        }
        return null;
    }
    
    _setCached(key, data) {
        this.cache.set(key, { data, time: Date.now() });
        if (this.cache.size > 1000) {
            const oldest = [...this.cache.entries()].sort((a, b) => a[1].time - b[1].time)[0];
            this.cache.delete(oldest[0]);
        }
    }
}

module.exports = new ThreatIntel();
