const express = require('express');
const router = express.Router();

// Mock X (Twitter) feed data generator
function generateMockXFeedData() {
  return {
    tweets: [
      {
        id: 'x-' + Date.now(),
        author: '@ThreatIntelFeed',
        content: '🚨 BREAKING: CISA adds CVE-2026-12345 to KEV catalog - actively exploited in ransomware attacks targeting healthcare systems. This ZD affects Citrix ADC and NetScaler gateways. Patch immediately: https://www.cisa.gov/known-exploited-vulnerabilities-catalog #CVE #Ransomware #ZeroDay',
        timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
        engagement: { likes: 240, retweets: 89, replies: 12 },
        severity: 'CRITICAL',
        iocs: ['CVE-2026-12345'],
        mitre: ['T1190']
      },
      {
        id: 'x-' + (Date.now() - 30000),
        author: '@MalwareHunterTeam',
        content: '🔍 Analyzing new Stealer malware "VidarSPREAD" distributing via fake Adobe Flash Player updates. Uses Discord webhooks for data exfiltration. Sample analysis: https://www.hybrid-analysis.com/sample/vidorspread-2026 #Malware #Stealer #Discord',
        timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
        engagement: { likes: 180, retweets: 42, replies: 7 },
        severity: 'HIGH',
        iocs: [
          'adobe-flash-update[.]xyz',
          'discordapp.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz'
        ],
        mitre: ['T1566.002', 'T1048.003', 'T1071.001']
      },
      {
        id: 'x-' + (Date.now() - 60000),
        author: '@VulnWatch',
        content: '⚠️ New WordPress plugin vulnerability (CVE-2026-54321) allows unauthenticated RCE. Affects >500k sites using "SEO Ultimate" plugin. Update to v3.2.1+ immediately. #WordPress #Vulnerability #RCE',
        timestamp: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
        engagement: { likes: 320, retweets: 150, replies: 23 },
        severity: 'HIGH',
        iocs: ['CVE-2026-54321'],
        mitre: ['T1190', 'T1059.003']
      }
    ]
  };
}

// Main route handler
router.get('/api/xfeed', async (req, res) => {
  try {
    // TODO: Replace with real Twitter API implementation    // Example structure for future implementation:
    /*
    const bearerToken = process.env.TWITTER_BEARER_TOKEN;
    if (!bearerToken) {
      return res.status(500).json({ error: 'Twitter API bearer token not configured' });
    }
        const response = await fetch(
      'https://api.twitter.com/2/tweets/search/recent?query=threat%20actor%20OR%20malware%20OR%20ransomware%20lang:en&-is:retweet&max_results=10',
      {
        headers: { Authorization: `Bearer ${bearerToken}` },
        timeout: 5000
      }
    );
    
    if (!response.ok) throw new Error(`Twitter API error: ${response.status}`);
    const data = await response.json();
    
    // Transform Twitter API response to match our expected format
    const transformed = transformTwitterData(data);
    res.json(transformed);
    */
    
    // For now, return mock data
    const mockData = generateMockXFeedData();
    res.json(mockData);
    
    console.info('[XFeed] Served mock data - replace with real Twitter API when ready');
  } catch (error) {
    console.error('[XFeed] Error fetching data:', error.message);
    res.status(500).json({ 
      error: 'Failed to fetch X feed intelligence',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;