/**
 * Threat Monitor API Routes
 */

const express = require('express');
const router = express.Router();
const threatMonitor = require('../services/threatMonitor');

// Get recent threats
router.get('/api/threats/recent', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const threats = await threatMonitor.getRecentThreats(limit);
        res.json(threats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get threats by severity
router.get('/api/threats/severity/:severity', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const threats = await threatMonitor.getThreatsBySeverity(req.params.severity, limit);
        res.json(threats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get IOCs for a specific threat
router.get('/api/threats/:id/iocs', async (req, res) => {
    try {
        const iocs = await threatMonitor.getIOCsForThreat(req.params.id);
        res.json(iocs);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Search threats
router.get('/api/threats/search', async (req, res) => {
    try {
        const query = req.query.q;
        if (!query || query.length < 3) {
            return res.json([]);
        }
        const threats = await threatMonitor.searchThreats(query);
        res.json(threats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get threat statistics
router.get('/api/threats/stats', async (req, res) => {
    try {
        const stats = await threatMonitor.getStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Dark Web specific endpoint
router.get('/api/darkweb/feed', async (req, res) => {
    try {
        const threats = await threatMonitor.getRecentThreats(100);
        const darkwebThreats = threats.filter(t => t.source_type === 'darkweb');
        
        const stats = await threatMonitor.getStats();
        
        res.json({
            sources: [
                { name: 'Exploit.in', status: 'active', icon: '💀', posts: darkwebThreats.filter(t => t.source_name === 'Exploit.in').length },
                { name: 'RAMP Forum', status: 'active', icon: '🎯', posts: darkwebThreats.filter(t => t.source_name === 'RAMP Forum').length },
                { name: 'XSS.is', status: 'active', icon: '⚡', posts: darkwebThreats.filter(t => t.source_name === 'XSS.is').length },
                { name: 'Telegram Leaks', status: 'active', icon: '📱', posts: threats.filter(t => t.source_type === 'telegram').length }
            ],
            posts: darkwebThreats.slice(0, 10).map(t => ({
                id: t.id,
                source: t.source_name,
                title: t.title,
                author: t.author,
                time: this.formatTimeAgo(t.first_seen),
                price: t.content.includes('$') ? this.extractPrice(t.content) : 'Unknown',
                tags: JSON.parse(t.tags || '[]'),
                severity: t.severity
            })),
            stats: {
                zeroDays: threats.filter(t => t.category === 'VULNERABILITY' && t.severity === 'CRITICAL').length,
                accessBrokers: threats.filter(t => t.content.toLowerCase().includes('access')).length,
                exploits: threats.filter(t => t.category === 'MALWARE' || t.tags.includes('exploit')).length,
                dataLeaks: threats.filter(t => t.category === 'DATA_BREACH').length
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// OSINT Feed
router.get('/api/osint/feed', async (req, res) => {
    try {
        const threats = await threatMonitor.getRecentThreats(100);
        
        res.json({
            sources: [
                { name: 'GitHub Security', icon: '🐙', status: 'active', items: threats.filter(t => t.source_type === 'github').length },
                { name: 'Telegram Intel', icon: '📱', status: 'active', items: threats.filter(t => t.source_type === 'telegram').length },
                { name: 'Dark Web', icon: '🌑', status: threatMonitor.darkweb.torEnabled ? 'active' : 'inactive', items: threats.filter(t => t.source_type === 'darkweb').length },
                { name: 'Paste Sites', icon: '📋', status: 'active', items: 0 }
            ],
            items: threats.slice(0, 20).map(t => ({
                id: t.id,
                source: t.source_name,
                title: t.title,
                content: t.content.substring(0, 100) + '...',
                author: t.author,
                time: this.formatTimeAgo(t.first_seen),
                severity: t.severity,
                category: t.category,
                iocs: JSON.parse(t.iocs || '[]').length,
                tags: JSON.parse(t.tags || '[]')
            }))
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// X/Twitter-like Feed (Threat Intelligence Social Feed)
router.get('/api/xfeed', async (req, res) => {
    try {
        const threats = await threatMonitor.getRecentThreats(50);
        
        // Create social media style feed
        const tweets = threats.map((t, index) => ({
            id: `xt${index}`,
            avatar: this.getAvatar(t.source_type),
            name: t.source_name,
            handle: `@${t.source_name.toLowerCase().replace(/\s+/g, '')}`,
            time: this.formatTimeAgo(t.first_seen),
            content: t.content.length > 200 ? t.content.substring(0, 200) + '...' : t.content,
            retweets: Math.floor(Math.random() * 1000) + 100,
            likes: Math.floor(Math.random() * 3000) + 200,
            quotes: Math.floor(Math.random() * 200) + 20,
            tags: JSON.parse(t.tags || '[]'),
            severity: t.severity,
            ioc_count: JSON.parse(t.iocs || '[]').length
        }));

        // Actor stats
        const actorStats = {};
        threats.forEach(t => {
            const tags = JSON.parse(t.tags || '[]');
            tags.forEach(tag => {
                if (tag.includes('apt')) {
                    actorStats[tag] = actorStats[tag] || { tweets: 0, new: 0 };
                    actorStats[tag].tweets++;
                }
            });
        });

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