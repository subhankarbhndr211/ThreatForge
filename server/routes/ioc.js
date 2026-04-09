'use strict';

/**
 * IOC Enrichment API
 * VirusTotal, AbuseIPDB, ThreatFox integration
 */

const express = require('express');
const router = express.Router();

// VT check
router.post('/vt/check', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'No IP provided' });
    
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return res.json({ error: 'VT API not configured', malicious: 0, suspicious: 0 });
    
    try {
        const resp = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: { 'x-apikey': apiKey }
        });
        const data = await resp.json();
        const attrs = data.data?.attributes || {};
        const stats = attrs.last_analysis_stats || {};
        res.json({
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.undetected || 0,
            communityScore: attrs.total_votes?.harmless || 0
        });
    } catch (e) {
        res.json({ error: e.message, malicious: 0, suspicious: 0 });
    }
});

// AbuseIPDB check
router.post('/abuseipdb/check', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'No IP provided' });
    
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    if (!apiKey) return res.json({ error: 'AbuseIPDB API not configured', score: 0 });
    
    try {
        const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
            headers: { 'Key': apiKey, 'Accept': 'application/json' }
        });
        const data = await resp.json();
        const d = data.data || {};
        res.json({
            score: d.abuseConfidenceScore || 0,
            country: d.countryCode || '',
            isp: d.isp || '',
            domain: d.domain || '',
            categories: d.categories || [],
            reportedAt: d.reportedAt
        });
    } catch (e) {
        res.json({ error: e.message, score: 0 });
    }
});

// Batch check
router.post('/batch-check', async (req, res) => {
    const { ips } = req.body;
    if (!ips || !Array.isArray(ips)) return res.status(400).json({ error: 'No IPs provided' });
    
    const results = [];
    for (const ip of ips) {
        let vt = { malicious: 0, suspicious: 0 }, abuse = { score: 0 };
        
        // VT
        try {
            const apiKey = process.env.VIRUSTOTAL_API_KEY;
            if (apiKey) {
                const resp = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
                    headers: { 'x-apikey': apiKey }
                });
                const data = await resp.json();
                const stats = data.data?.attributes?.last_analysis_stats || {};
                vt = { malicious: stats.malicious || 0, suspicious: stats.suspicious || 0 };
            }
        } catch (e) {}
        
        // AbuseIPDB
        try {
            const apiKey = process.env.ABUSEIPDB_API_KEY;
            if (apiKey) {
                const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
                    headers: { 'Key': apiKey, 'Accept': 'application/json' }
                });
                const data = await resp.json();
                abuse = { score: data.data?.abuseConfidenceScore || 0 };
            }
        } catch (e) {}
        
        results.push({ ip, vt, abuseipdb: abuse });
    }
    
    res.json({ results });
});

module.exports = router;