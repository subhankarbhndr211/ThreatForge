/**
 * Threat Monitor API Routes
 */

const express = require('express');
const router = express.Router();

// Mock data for demonstration
const mockThreats = [
    {
        id: 'threat1',
        source_type: 'darkweb',
        source_name: 'Exploit.in',
        title: 'Zero-day Windows Kernel RCE',
        content: 'New zero-day vulnerability in Windows kernel allowing remote code execution. Affects all Windows versions. Exploit available on underground forums.',
        author: 'xSSS',
        severity: 'CRITICAL',
        category: 'VULNERABILITY',
        first_seen: new Date().toISOString(),
        tags: '["0-day","RCE","Windows"]',
        iocs: '[{"type":"hash","value":"a1b2c3d4e5f6..."}]'
    },
    {
        id: 'threat2',
        source_type: 'darkweb',
        source_name: 'RAMP Forum',
        title: 'Initial Access Broker - Fortune 500',
        content: 'Selling access to major healthcare provider with 50k+ employee records. Price: $15,000. VPN and RDP access available.',
        author: 'access4sale',
        severity: 'HIGH',
        category: 'ACCESS_BROKER',
        first_seen: new Date(Date.now() - 3600000).toISOString(),
        tags: '["access","broker","healthcare"]',
        iocs: '[{"type":"ip","value":"185.130.5.133"}]'
    },
    {
        id: 'threat3',
        source_type: 'telegram',
        source_name: 'ThreatIntel Telegram',
        title: 'New LockBit 3.0 Campaign',
        content: 'LockBit 3.0 targeting healthcare sector. New IOCs released. C2 servers: 194.87.54.23, 185.225.17.45',
        author: '@ransomwarewatch',
        severity: 'CRITICAL',
        category: 'RANSOMWARE',
        first_seen: new Date(Date.now() - 7200000).toISOString(),
        tags: '["lockbit","ransomware","healthcare"]',
        iocs: '[{"type":"ip","value":"194.87.54.23"},{"type":"ip","value":"185.225.17.45"}]'
    },
    {
        id: 'threat4',
        source_type: 'github',
        source_name: 'vxunderground/MalwareSourceCode',
        title: 'New Mirai variant source code',
        content: 'Mirai variant targeting IoT devices with new exploits. Includes C2 infrastructure details.',
        author: 'malware_researcher',
        severity: 'HIGH',
        category: 'MALWARE',
        first_seen: new Date(Date.now() - 86400000).toISOString(),
        tags: '["mirai","iot","botnet"]',
        iocs: '[{"type":"hash","value":"b2c3d4e5f6g7..."}]'
    },
    {
        id: 'threat5',
        source_type: 'darkweb',
        source_name: 'XSS.is',
        title: 'CVE-2025-1234 Exploit Released',
        content: 'Public exploit for Apache Tomcat vulnerability. Pre-auth RCE in versions 9.0.0-9.0.80. PoC available.',
        author: 'exploitdev',
        severity: 'CRITICAL',
        category: 'EXPLOIT',
        first_seen: new Date(Date.now() - 1800000).toISOString(),
        tags: '["cve","tomcat","rce","exploit"]',
        iocs: '[{"type":"cve","value":"CVE-2025-1234"}]'
    }
];

// Get recent threats
router.get('/api/threats/recent', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const threats = mockThreats.slice(0, limit);
        res.json(threats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get threats by severity
router.get('/api/threats/severity/:severity', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const threats = mockThreats
            .filter(t => t.severity === req.params.severity.toUpperCase())
            .slice(0, limit);
        res.json(threats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get IOCs for a specific threat
router.get('/api/threats/:id/iocs', async (req, res) => {
    try {
        const threat = mockThreats.find(t => t.id === req.params.id);
        const iocs = threat ? JSON.parse(threat.iocs) : [];
        res.json(iocs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Search threats
router.get('/api/threats/search', async (req, res) => {
    try {
        const query = req.query.q?.toLowerCase() || '';
        if (!query || query.length < 3) {
            return res.json([]);
        }
        
        const threats = mockThreats.filter(t => 
            t.title.toLowerCase().includes(query) ||
            t.content.toLowerCase().includes(query) ||
            t.author.toLowerCase().includes(query) ||
            t.tags.toLowerCase().includes(query)
        );
        res.json(threats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get threat statistics
router.get('/api/threats/stats', async (req, res) => {
    try {
        const stats = {
            total: mockThreats.length,
            critical: mockThreats.filter(t => t.severity === 'CRITICAL').length,
            high: mockThreats.filter(t => t.severity === 'HIGH').length,
            medium: mockThreats.filter(t => t.severity === 'MEDIUM').length,
            low: mockThreats.filter(t => t.severity === 'LOW').length,
            source_types: [...new Set(mockThreats.map(t => t.source_type))].length,
            latest_threat: mockThreats[0]?.first_seen,
            ioc_count: mockThreats.reduce((acc, t) => acc + JSON.parse(t.iocs || '[]').length, 0)
        };
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Dark Web specific endpoint
router.get('/api/darkweb/feed', async (req, res) => {
    try {
        const darkwebThreats = mockThreats.filter(t => t.source_type === 'darkweb');
        
        const sources = [
            { name: 'Exploit.in', status: 'active', icon: '💀', posts: darkwebThreats.filter(t => t.source_name === 'Exploit.in').length },
            { name: 'RAMP Forum', status: 'active', icon: '🎯', posts: darkwebThreats.filter(t => t.source_name === 'RAMP Forum').length },
            { name: 'XSS.is', status: 'active', icon: '⚡', posts: darkwebThreats.filter(t => t.source_name === 'XSS.is').length },
            { name: 'Telegram Leaks', status: 'active', icon: '📱', posts: mockThreats.filter(t => t.source_type === 'telegram').length }
        ];

        const posts = darkwebThreats.map(t => ({
            id: t.id,
            source: t.source_name,
            title: t.title,
            author: t.author,
            time: formatTimeAgo(t.first_seen),
            price: extractPrice(t.content),
            tags: JSON.parse(t.tags || '[]'),
            severity: t.severity
        }));

        const stats = {
            zeroDays: mockThreats.filter(t => t.category === 'VULNERABILITY' && t.severity === 'CRITICAL').length,
            accessBrokers: mockThreats.filter(t => t.content.toLowerCase().includes('access')).length,
            exploits: mockThreats.filter(t => t.category === 'EXPLOIT' || t.tags.includes('exploit')).length,
            dataLeaks: mockThreats.filter(t => t.category === 'DATA_BREACH').length
        };

        res.json({ sources, posts, stats });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// OSINT Feed
router.get('/api/osint/feed', async (req, res) => {
    try {
        const threats = mockThreats;

        const sources = [
            { name: 'GitHub Security', icon: '🐙', status: 'active', items: threats.filter(t => t.source_type === 'github').length },
            { name: 'Telegram Intel', icon: '📱', status: 'active', items: threats.filter(t => t.source_type === 'telegram').length },
            { name: 'Dark Web', icon: '🌑', status: 'active', items: threats.filter(t => t.source_type === 'darkweb').length },
            { name: 'Paste Sites', icon: '📋', status: 'active', items: 0 }
        ];

        const items = threats.map(t => ({
            id: t.id,
            source: t.source_name,
            title: t.title,
            content: t.content.substring(0, 100) + '...',
            author: t.author,
            time: formatTimeAgo(t.first_seen),
            severity: t.severity,
            category: t.category,
            iocs: JSON.parse(t.iocs || '[]').length,
            tags: JSON.parse(t.tags || '[]')
        }));

        res.json({ sources, items });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// X/Twitter-like Feed
router.get('/api/xfeed', async (req, res) => {
    try {
        const threats = mockThreats;
        
        const tweets = threats.map((t, index) => ({
            id: `xt${index + 1}`,
            avatar: getAvatar(t.source_type),
            name: t.source_name,
            handle: `@${t.source_name.toLowerCase().replace(/[^a-z0-9]/g, '')}`,
            time: formatTimeAgo(t.first_seen),
            content: t.content,
            retweets: Math.floor(Math.random() * 1000) + 100,
            likes: Math.floor(Math.random() * 3000) + 200,
            quotes: Math.floor(Math.random() * 200) + 20,
            tags: JSON.parse(t.tags || '[]'),
            severity: t.severity,
            ioc_count: JSON.parse(t.iocs || '[]').length
        }));

        // Actor stats
        const actorStats = {
            apt29: { tweets: 2, new: 1 },
            lazarus: { tweets: 1, new: 0 },
            lockbit: { tweets: 1, new: 1 }
        };

        res.json({
            trackedAccounts: threats.length,
            tweets: tweets,
            actorStats: actorStats
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Helper functions
function formatTimeAgo(timestamp) {
    const now = new Date();
    const past = new Date(timestamp);
    const diffMs = now - past;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins} minutes ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    return `${diffDays} days ago`;
}

function getAvatar(sourceType) {
    const avatars = {
        telegram: '📱',
        darkweb: '🌑',
        github: '🐙',
        default: '📡'
    };
    return avatars[sourceType] || avatars.default;
}

function extractPrice(content) {
    const priceMatch = content.match(/\$\s?(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)/);
    return priceMatch ? priceMatch[0] : 'Negotiable';
}

module.exports = router;