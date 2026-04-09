// routes/cyberIntel.js
const express = require('express');
const router = express.Router();

// ===================================================
// CYBER INTEL FEED API - All-in-One Threat Intelligence
// ===================================================

// Memory cache for cyber intel data
const cyberIntelCache = {
  items: [],
  lastFetch: null,
  sourceStatus: {}
};

// Source configurations
const CYBER_SOURCES = [
  // X/Twitter via Nitter (privacy-friendly)
  { id: 'x_vxunderground', name: 'vxunderground', type: 'x', icon: '𝕏', url: 'https://nitter.poast.org/vxunderground/rss' },
  { id: 'x_gossithedog', name: 'GossiTheDog', type: 'x', icon: '𝕏', url: 'https://nitter.poast.org/GossiTheDog/rss' },
  { id: 'x_malwrhunter', name: 'malwrhunterteam', type: 'x', icon: '𝕏', url: 'https://nitter.poast.org/malwrhunterteam/rss' },
  { id: 'x_cvenew', name: 'CVEnew', type: 'x', icon: '𝕏', url: 'https://nitter.poast.org/CVEnew/rss' },
  { id: 'x_cisacyber', name: 'CISACyber', type: 'x', icon: '𝕏', url: 'https://nitter.poast.org/CISACyber/rss' },
  
  // GitHub - PoC exploits
  { id: 'github_poc', name: 'GitHub PoC', type: 'github', icon: '⚙️', url: 'https://api.github.com/search/repositories?q=CVE+poc+exploit&sort=updated&per_page=20' },
  
  // Reddit security communities
  { id: 'reddit_netsec', name: 'r/netsec', type: 'reddit', icon: '🔴', url: 'https://www.reddit.com/r/netsec/.rss' },
  { id: 'reddit_cybersecurity', name: 'r/cybersecurity', type: 'reddit', icon: '🔴', url: 'https://www.reddit.com/r/cybersecurity/new/.rss' },
  { id: 'reddit_malware', name: 'r/Malware', type: 'reddit', icon: '🔴', url: 'https://www.reddit.com/r/Malware/.rss' },
  
  // NVD Critical CVEs
  { id: 'nvd_critical', name: 'NVD Critical', type: 'nvd', icon: '🛡️', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&resultsPerPage=20' },
  { id: 'nvd_high', name: 'NVD High', type: 'nvd', icon: '🛡️', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH&resultsPerPage=15' },
  
  // CISA KEV
  { id: 'cisa_kev', name: 'CISA KEV', type: 'kev', icon: '🚨', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
  
  // Research blogs
  { id: 'research_krebs', name: 'Krebs on Security', type: 'research', icon: '🔍', url: 'https://krebsonsecurity.com/feed/' },
  { id: 'research_talos', name: 'Talos Intel', type: 'research', icon: '🦅', url: 'https://blog.talosintelligence.com/feeds/posts/default' },
  { id: 'research_sans', name: 'SANS ISC', type: 'research', icon: '📡', url: 'https://isc.sans.edu/rssfeed.xml' },
  { id: 'research_dfir', name: 'DFIR Report', type: 'research', icon: '📊', url: 'https://thedfirreport.com/feed/' },
  { id: 'research_attackerkb', name: 'AttackerKB', type: 'research', icon: '🎯', url: 'https://attackerkb.com/rss' },
  
  // Dark web sources
  { id: 'darkweb_ransomwatch', name: 'RansomWatch', type: 'darkweb', icon: '💀', url: 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json' },
  { 
    id: 'darkweb_threatfox', 
    name: 'ThreatFox', 
    type: 'darkweb', 
    icon: '☠️', 
    url: 'https://threatfox-api.abuse.ch/api/v1/',
    method: 'POST',
    body: { query: 'get_iocs', days: 1 }
  },
  
  // Security news
  { id: 'news_packetstorm', name: 'PacketStorm', type: 'news', icon: '⚡', url: 'https://rss.packetstormsecurity.com/files/tags/advisory/' },
  { id: 'news_hn', name: 'Hacker News Sec', type: 'news', icon: '🔶', url: 'https://hnrss.org/newest?q=security+CVE+exploit' },
  
  // Exploit-DB
  { id: 'exploitdb', name: 'Exploit-DB', type: 'exploit', icon: '💥', url: 'https://www.exploit-db.com/rss.xml' },
  
  // The Hacker News
  { id: 'thn', name: 'The Hacker News', type: 'news', icon: '📰', url: 'https://feeds.feedburner.com/TheHackersNews' },
  
  // Bleeping Computer
  { id: 'bleeping', name: 'Bleeping Computer', type: 'news', icon: '💻', url: 'https://www.bleepingcomputer.com/feed/' }
];

// Utility: Extract tags from text
function extractCyberTags(text) {
  const t = (text || '').toLowerCase();
  const tags = [];
  if (/cve-\d{4}-\d+/.test(t)) tags.push('CVE');
  if (/zero.?day|0.?day/.test(t)) tags.push('zero-day');
  if (/ransomware/.test(t)) tags.push('ransomware');
  if (/\bapt\b|\bapt\d{2}/.test(t)) tags.push('APT');
  if (/malware|trojan|rat\b|stealer/.test(t)) tags.push('malware');
  if (/exploit|exploitation/.test(t)) tags.push('exploit');
  if (/\bpoc\b|proof of concept/.test(t)) tags.push('PoC');
  if (/phishing/.test(t)) tags.push('phishing');
  if (/breach|leak|dump/.test(t)) tags.push('breach');
  if (/vulnerability|vuln/.test(t)) tags.push('vuln');
  if (/patch|update/.test(t)) tags.push('patch');
  if (/cobalt.?strike|beacon/.test(t)) tags.push('cobalt-strike');
  return tags;
}

// Utility: Parse RSS XML
function parseRSS(xmlText, sourceName, sourceType, sourceIcon) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  
  while ((match = itemRegex.exec(xmlText)) !== null) {
    const itemContent = match[1];
    
    const titleMatch = itemContent.match(/<title[^>]*>.*?<!\[CDATA\[(.*?)\]\]>.*?<\/title>/) || 
                       itemContent.match(/<title[^>]*>(.*?)<\/title>/);
    const title = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '').trim() : '';
    
    const linkMatch = itemContent.match(/<link[^>]*>(.*?)<\/link>/) || 
                      itemContent.match(/<link[^>]*href="([^"]+)"/);
    const link = linkMatch ? linkMatch[1].trim() : '';
    
    const descMatch = itemContent.match(/<description[^>]*>.*?<!\[CDATA\[(.*?)\]\]>.*?<\/description>/) || 
                      itemContent.match(/<description[^>]*>(.*?)<\/description>/);
    let desc = descMatch ? descMatch[1].replace(/<[^>]+>/g, '').trim() : '';
    desc = desc.substring(0, 250);
    
    const dateMatch = itemContent.match(/<pubDate[^>]*>(.*?)<\/pubDate>/) || 
                      itemContent.match(/<dc:date[^>]*>(.*?)<\/dc:date>/);
    const dateStr = dateMatch ? dateMatch[1].trim() : '';
    const timestamp = dateStr ? new Date(dateStr).getTime() : Date.now();
    
    const cveMatch = (title + desc).match(/CVE-\d{4}-\d+/i);
    const cve = cveMatch ? cveMatch[0].toUpperCase() : null;
    
    if (title) {
      items.push({
        id: Buffer.from(sourceName + title).toString('base64').substring(0, 20),
        title,
        link: link || '#',
        description: desc,
        timestamp,
        source: sourceName,
        type: sourceType,
        icon: sourceIcon,
        cve,
        tags: extractCyberTags(title + ' ' + desc),
        unread: true
      });
    }
  }
  return items;
}

// Fetch a single source
async function fetchCyberSource(source) {
  try {
    const startTime = Date.now();
    const fetchOptions = {
      timeout: 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    };
    
    let response;
    if (source.method === 'POST') {
      response = await fetch(source.url, {
        ...fetchOptions,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: typeof source.body === 'string' ? source.body : JSON.stringify(source.body)
      });
    } else {
      response = await fetch(source.url, fetchOptions);
    }
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    
    const contentType = response.headers.get('content-type') || '';
    let data;
    
    if (contentType.includes('json')) {
      data = await response.json();
    } else {
      const text = await response.text();
      
      // Handle different source types
      if (source.type === 'github') {
        // GitHub API response
        const items = [];
        if (data.items) {
          for (const repo of data.items.slice(0, 15)) {
            const cveMatch = (repo.name + ' ' + (repo.description || '')).match(/CVE-\d{4}-\d+/i);
            items.push({
              id: 'gh_' + repo.id,
              title: repo.full_name + (cveMatch ? ` [${cveMatch[0]}]` : ''),
              link: repo.html_url,
              description: (repo.description || '').substring(0, 150) + ` ⭐${repo.stargazers_count}`,
              timestamp: new Date(repo.pushed_at).getTime(),
              source: source.name,
              type: source.type,
              icon: source.icon,
              cve: cveMatch ? cveMatch[0].toUpperCase() : null,
              tags: extractCyberTags(repo.name + ' ' + (repo.description || '') + ' exploit poc'),
              unread: true
            });
          }
        }
        return { source: source.id, items, latency: Date.now() - startTime };
      } 
      else if (source.type === 'kev' && source.id === 'cisa_kev') {
        // CISA KEV JSON
        const items = [];
        if (data.vulnerabilities) {
          for (const vuln of data.vulnerabilities.slice(0, 20)) {
            items.push({
              id: 'kev_' + vuln.cveID.replace(/-/g, '_'),
              title: `${vuln.cveID} - ${vuln.vulnerabilityName || 'Known Exploited Vulnerability'}`,
              link: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
              description: `${vuln.shortDescription || ''} | Due: ${vuln.dueDate} | Action: ${vuln.requiredAction}`,
              timestamp: new Date(vuln.dateAdded).getTime(),
              source: source.name,
              type: source.type,
              icon: source.icon,
              cve: vuln.cveID,
              tags: ['CVE', 'exploited', vuln.knownRansomwareCampaignUse === 'Known' ? 'ransomware' : null].filter(Boolean),
              unread: true
            });
          }
        }
        return { source: source.id, items, latency: Date.now() - startTime };
      }
      else if (source.type === 'nvd') {
        // NVD JSON
        const items = [];
        if (data.vulnerabilities) {
          for (const vuln of data.vulnerabilities.slice(0, 15)) {
            const cve = vuln.cve;
            const descriptions = cve.descriptions || [];
            const desc = descriptions.find(d => d.lang === 'en')?.value || '';
            const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            
            items.push({
              id: 'nvd_' + cve.id.replace(/-/g, '_'),
              title: `${cve.id} - ${desc.substring(0, 80)}...`,
              link: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
              description: `CVSS: ${cvssV3?.baseScore || 'N/A'} | ${desc.substring(0, 200)}`,
              timestamp: new Date(cve.published).getTime(),
              source: source.name,
              type: source.type,
              icon: source.icon,
              cve: cve.id,
              tags: extractCyberTags(desc + ' cve'),
              unread: true
            });
          }
        }
        return { source: source.id, items, latency: Date.now() - startTime };
      }
      else {
        // RSS XML
        const items = parseRSS(text, source.name, source.type, source.icon);
        return { source: source.id, items, latency: Date.now() - startTime };
      }
    }
    
    return { source: source.id, items: [], latency: Date.now() - startTime };
  } catch (error) {
    console.error(`[CyberIntel] Error fetching ${source.id}:`, error.message);
    return { source: source.id, items: [], error: error.message, latency: 0 };
  }
}

// Fetch all cyber intel sources
async function fetchAllCyberIntel() {
  console.log('[CyberIntel] Fetching all sources...');
  const startTime = Date.now();
  
  const results = await Promise.allSettled(
    CYBER_SOURCES.map(source => fetchCyberSource(source))
  );
  
  let allItems = [];
  const sourceStatus = {};
  
  results.forEach((result, index) => {
    const source = CYBER_SOURCES[index];
    if (result.status === 'fulfilled' && result.value.items) {
      allItems.push(...result.value.items);
      sourceStatus[source.id] = {
        status: 'ok',
        items: result.value.items.length,
        latency: result.value.latency
      };
    } else {
      sourceStatus[source.id] = {
        status: 'error',
        error: result.reason?.message || 'Unknown error'
      };
    }
  });
  
  // Sort by timestamp (newest first)
  allItems.sort((a, b) => b.timestamp - a.timestamp);
  
  // Limit to 500 items
  allItems = allItems.slice(0, 500);
  
  cyberIntelCache.items = allItems;
  cyberIntelCache.lastFetch = new Date().toISOString();
  cyberIntelCache.sourceStatus = sourceStatus;
  
  console.log(`[CyberIntel] Fetched ${allItems.length} items in ${Date.now() - startTime}ms`);
  
  return {
    items: allItems,
    sourceStatus,
    fetchedAt: cyberIntelCache.lastFetch,
    total: allItems.length
  };
}

// ===================================================
// API ENDPOINTS
// ===================================================

// GET /api/cyber-intel - Get all cyber intelligence items
router.get('/', async (req, res) => {
  try {
    const { force = false, source, tag, search, limit = 100 } = req.query;
    
    // Return cached data if available and not forcing refresh
    if (!force && cyberIntelCache.items.length > 0 && cyberIntelCache.lastFetch) {
      const lastFetchTime = new Date(cyberIntelCache.lastFetch).getTime();
      const now = Date.now();
      
      // Cache for 5 minutes
      if (now - lastFetchTime < 5 * 60 * 1000) {
        let items = [...cyberIntelCache.items];
        
        // Apply filters
        if (source && source !== 'all') {
          items = items.filter(item => item.type === source);
        }
        
        if (tag) {
          items = items.filter(item => item.tags.includes(tag));
        }
        
        if (search) {
          const searchLower = search.toLowerCase();
          items = items.filter(item => 
            item.title.toLowerCase().includes(searchLower) ||
            (item.description || '').toLowerCase().includes(searchLower) ||
            (item.cve || '').toLowerCase().includes(searchLower) ||
            item.source.toLowerCase().includes(searchLower)
          );
        }
        
        // Apply limit
        items = items.slice(0, parseInt(limit));
        
        return res.json({
          items,
          total: cyberIntelCache.items.length,
          filtered: items.length,
          fetchedAt: cyberIntelCache.lastFetch,
          cached: true,
          sourceStatus: cyberIntelCache.sourceStatus
        });
      }
    }
    
    // Fetch fresh data
    const data = await fetchAllCyberIntel();
    
    let items = [...data.items];
    
    // Apply filters
    if (source && source !== 'all') {
      items = items.filter(item => item.type === source);
    }
    
    if (tag) {
      items = items.filter(item => item.tags.includes(tag));
    }
    
    if (search) {
      const searchLower = search.toLowerCase();
      items = items.filter(item => 
        item.title.toLowerCase().includes(searchLower) ||
        (item.description || '').toLowerCase().includes(searchLower) ||
        (item.cve || '').toLowerCase().includes(searchLower) ||
        item.source.toLowerCase().includes(searchLower)
      );
    }
    
    // Apply limit
    items = items.slice(0, parseInt(limit));
    
    res.json({
      items,
      total: data.items.length,
      filtered: items.length,
      fetchedAt: data.fetchedAt,
      cached: false,
      sourceStatus: data.sourceStatus
    });
    
  } catch (error) {
    console.error('[CyberIntel] Error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch cyber intelligence',
      items: cyberIntelCache.items.slice(0, 50) // Return cached items as fallback
    });
  }
});

// GET /api/cyber-intel/sources - Get source status
router.get('/sources', (req, res) => {
  res.json({
    sources: CYBER_SOURCES.map(s => ({
      id: s.id,
      name: s.name,
      type: s.type,
      icon: s.icon
    })),
    status: cyberIntelCache.sourceStatus || {},
    lastFetch: cyberIntelCache.lastFetch
  });
});

// GET /api/cyber-intel/tags - Get all unique tags
router.get('/tags', (req, res) => {
  const tagCounts = {};
  
  cyberIntelCache.items.forEach(item => {
    item.tags.forEach(tag => {
      tagCounts[tag] = (tagCounts[tag] || 0) + 1;
    });
  });
  
  res.json({
    tags: Object.keys(tagCounts).map(tag => ({
      name: tag,
      count: tagCounts[tag]
    })).sort((a, b) => b.count - a.count)
  });
});

// POST /api/cyber-intel/mark-read - Mark items as read
router.post('/mark-read', (req, res) => {
  const { itemIds } = req.body;
  
  if (!itemIds || !Array.isArray(itemIds)) {
    return res.status(400).json({ error: 'itemIds array required' });
  }
  
  // In a production app, you'd store this in a database per user
  // For now, we'll just return success
  
  res.json({ 
    success: true, 
    marked: itemIds.length 
  });
});

// GET /api/cyber-intel/stats - Get statistics
router.get('/stats', (req, res) => {
  const stats = {
    total: cyberIntelCache.items.length,
    byType: {},
    byTag: {},
    recent: {}
  };
  
  cyberIntelCache.items.forEach(item => {
    // Count by type
    stats.byType[item.type] = (stats.byType[item.type] || 0) + 1;
    
    // Count by tag
    item.tags.forEach(tag => {
      stats.byTag[tag] = (stats.byTag[tag] || 0) + 1;
    });
    
    // Last hour
    const hourAgo = Date.now() - 60 * 60 * 1000;
    if (item.timestamp > hourAgo) {
      stats.recent.lastHour = (stats.recent.lastHour || 0) + 1;
    }
    
    // Last 24 hours
    const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
    if (item.timestamp > dayAgo) {
      stats.recent.last24h = (stats.recent.last24h || 0) + 1;
    }
  });
  
  res.json({
    ...stats,
    lastFetch: cyberIntelCache.lastFetch,
    sources: Object.keys(cyberIntelCache.sourceStatus).length
  });
});

// Background refresh every 10 minutes
setInterval(async () => {
  console.log('[CyberIntel] Running background refresh...');
  await fetchAllCyberIntel();
}, 10 * 60 * 1000);

// Initial fetch on startup
setTimeout(() => {
  fetchAllCyberIntel().catch(err => {
    console.error('[CyberIntel] Initial fetch failed:', err.message);
  });
}, 5000);

module.exports = router;