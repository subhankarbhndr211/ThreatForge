const express = require('express');
const router = express.Router();
const pool = require('../config/db');
const axios = require('axios');

// Main feed endpoint
router.get('/', async (req, res) => {
    try {
        console.log('[FEED] Fetching threat intelligence...');
        
        // Try to get data from database first
        const dbFeed = await pool.query(`
            SELECT 
                id,
                'threat' as type,
                source,
                title,
                description as content,
                related_cves as cve,
                severity,
                created_at as first_seen
            FROM threat_feed
            ORDER BY created_at DESC
            LIMIT 50
        `);
        
        if (dbFeed.rows.length > 0) {
            console.log(`[FEED] Returning ${dbFeed.rows.length} items from database`);
            return res.json({ 
                items: dbFeed.rows,
                source: 'database'
            });
        }
        
        // If no database data, fetch from external APIs
        console.log('[FEED] No database data, fetching from external sources...');
        
        // Fetch from CISA KEV
        let kevItems = [];
        try {
            const kevRes = await axios.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
            if (kevRes.data && kevRes.data.vulnerabilities) {
                kevItems = kevRes.data.vulnerabilities.slice(0, 20).map(v => ({
                    type: 'cve',
                    source: 'CISA KEV',
                    severity: 'CRITICAL',
                    title: `${v.cveID} - ${v.vulnerabilityName || 'Known Exploited Vulnerability'}`,
                    value: v.cveID,
                    family: v.product,
                    first_seen: v.dateAdded,
                    icon: 'âš ï¸'
                }));
            }
        } catch (err) {
            console.log('[FEED] KEV fetch error:', err.message);
        }
        
        // Fetch from GitHub (if you have token)
        let githubItems = [];
        if (process.env.GITHUB_TOKEN) {
            try {
                const githubRes = await axios.get('https://api.github.com/search/repositories?q=exploit+PoC&sort=updated', {
                    headers: { 'Authorization': `Bearer ${process.env.GITHUB_TOKEN}` }
                });
                if (githubRes.data && githubRes.data.items) {
                    githubItems = githubRes.data.items.slice(0, 10).map(repo => ({
                        type: 'exploit',
                        source: 'GitHub',
                        severity: repo.stargazers_count > 50 ? 'CRITICAL' : 'HIGH',
                        title: `PoC: ${repo.name}`,
                        value: repo.html_url,
                        family: repo.language || 'Unknown',
                        first_seen: repo.created_at,
                        icon: 'ðŸ”“'
                    }));
                }
            } catch (err) {
                console.log('[FEED] GitHub fetch error:', err.message);
            }
        }
        
        // Combine all items
        const allItems = [...kevItems, ...githubItems];
        
        // If no items from APIs, return sample data
        if (allItems.length === 0) {
            console.log('[FEED] No data from APIs, returning samples');
            return res.json({
                items: [
                    {
                        type: 'cve',
                        source: 'CISA KEV',
                        severity: 'CRITICAL',
                        title: 'CVE-2024-3400 â€” PAN-OS RCE (KEV)',
                        value: 'CVE-2024-3400',
                        family: 'Palo Alto',
                        first_seen: new Date().toISOString(),
                        icon: 'âš ï¸'
                    },
                    {
                        type: 'malware',
                        source: 'MalwareBazaar',
                        severity: 'HIGH',
                        title: 'AgentTesla Infostealer',
                        value: 'a1b2c3d4...',
                        family: 'AgentTesla',
                        first_seen: new Date().toISOString(),
                        icon: 'â˜ ï¸'
                    },
                    {
                        type: 'ioc',
                        source: 'ThreatFox',
                        severity: 'CRITICAL',
                        title: 'Cobalt Strike C2 Beacon',
                        value: '185.220.101.45:4444',
                        family: 'CobaltStrike',
                        first_seen: new Date().toISOString(),
                        icon: 'ðŸŽ¯'
                    }
                ],
                source: 'sample'
            });
        }
        
        res.json({ items: allItems, source: 'external' });
        
    } catch (error) {
        console.error('[FEED] Error:', error.message);
        
        // Return sample data on error
        res.json({
            items: [
                {
                    type: 'cve',
                    source: 'CISA KEV',
                    severity: 'CRITICAL',
                    title: 'CVE-2024-3400 â€” PAN-OS RCE (KEV)',
                    value: 'CVE-2024-3400',
                    family: 'Palo Alto',
                    first_seen: new Date().toISOString(),
                    icon: 'âš ï¸'
                },
                {
                    type: 'malware',
                    source: 'MalwareBazaar',
                    severity: 'HIGH',
                    title: 'AgentTesla Infostealer',
                    value: 'a1b2c3d4...',
                    family: 'AgentTesla',
                    first_seen: new Date().toISOString(),
                    icon: 'â˜ ï¸'
                }
            ],
            source: 'sample'
        });
    }
});

// Status endpoint
router.get('/status', async (req, res) => {
    const sources = [
        { name: 'CISA KEV', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
        { name: 'GitHub', url: 'https://api.github.com' }
    ];
    
    const status = await Promise.all(
        sources.map(async source => {
            try {
                await axios.head(source.url, { timeout: 3000 });
                return { name: source.name, status: 'online' };
            } catch {
                return { name: source.name, status: 'offline' };
            }
        })
    );
    
    res.json({ sources: status, timestamp: new Date().toISOString() });
});
// Add this endpoint to your feed.js
router.get('/stats', async (req, res) => {
  try {
    // Try to get from database first
    if (pool) {
      const result = await pool.query(`
        SELECT 
          COUNT(*) as total,
          COUNT(CASE WHEN severity = 'CRITICAL' OR severity = 'CRIT' THEN 1 END) as critical,
          COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high,
          COUNT(CASE WHEN severity = 'MEDIUM' OR severity = 'MED' THEN 1 END) as medium,
          COUNT(CASE WHEN severity = 'LOW' THEN 1 END) as low,
          feed_type,
          COUNT(*) as type_count
        FROM threat_feed 
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY feed_type
      `);
      
      return res.json({
        total: result.rows.reduce((sum, row) => sum + parseInt(row.total), 0),
        critical: result.rows.reduce((sum, row) => sum + parseInt(row.critical || 0), 0),
        high: result.rows.reduce((sum, row) => sum + parseInt(row.high || 0), 0),
        medium: result.rows.reduce((sum, row) => sum + parseInt(row.medium || 0), 0),
        low: result.rows.reduce((sum, row) => sum + parseInt(row.low || 0), 0),
        byType: result.rows.reduce((acc, row) => {
          acc[row.feed_type] = parseInt(row.type_count);
          return acc;
        }, {})
      });
    }
  } catch (error) {
    console.error('Error getting feed stats:', error);
  }
  
  // Fallback stats
  res.json({
    total: 25,
    critical: 5,
    high: 8,
    medium: 7,
    low: 5,
    byType: {
      malware: 10,
      ioc: 8,
      cve: 4,
      url: 3
    }
  });
});

module.exports = router;
