const express = require('express');
const router = express.Router();
const axios = require('axios');

// Status endpoint that frontend checks
// Status endpoint that frontend checks
router.get('/status', (req, res) => {
  // Check if VT_API_KEY exists and is not a placeholder
  const vtKey = process.env.VT_API_KEY || '';
  const vtConfigured = vtKey.length > 10 && 
                      !vtKey.startsWith('your-') && 
                      vtKey !== 'YOUR_VT_API_KEY_HERE' &&
                      vtKey !== '';

  // Check if ABUSEIPDB_KEY exists and is not a placeholder
  const abuseKey = process.env.ABUSEIPDB_KEY || '';
  const abuseConfigured = abuseKey.length > 10 && 
                         !abuseKey.startsWith('your-') && 
                         abuseKey !== 'YOUR_ABUSEIPDB_KEY_HERE' &&
                         abuseKey !== '';

  console.log('[Enrich] VT configured:', vtConfigured, 'Length:', vtKey.length);
  console.log('[Enrich] Abuse configured:', abuseConfigured, 'Length:', abuseKey.length);

  res.json({
    virusTotal: vtConfigured,
    abuseIPDB: abuseConfigured,

  });
});

// Domain enrichment
router.get('/domain', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  
  try {
    const result = { domain };
    
    // VirusTotal check
    if (process.env.VT_API_KEY && process.env.VT_API_KEY !== 'your-vt-key-here') {
      try {
        const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
          headers: { 'x-apikey': process.env.VT_API_KEY.trim() },
          timeout: 5000
        });
        
        if (vtResponse.data?.data?.attributes) {
          const stats = vtResponse.data.data.attributes.last_analysis_stats || {};
          result.virustotal = {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            total: Object.values(stats).reduce((a, b) => a + b, 0)
          };
        }
      } catch (vtError) {
        console.log('VT API error:', vtError.message);
      }
    }
    
    res.json(result);
  } catch (error) {
    console.error('Domain enrichment error:', error);
    res.status(500).json({ error: 'Enrichment failed' });
  }
});

// IP enrichment
router.get('/ip', async (req, res) => {
  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  
  try {
    const result = { ip };
    
    // VirusTotal check
    if (process.env.VT_API_KEY && process.env.VT_API_KEY !== 'your-vt-key-here') {
      try {
        const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
          headers: { 'x-apikey': process.env.VT_API_KEY.trim() },
          timeout: 5000
        });
        
        if (vtResponse.data?.data?.attributes) {
          const stats = vtResponse.data.data.attributes.last_analysis_stats || {};
          result.virustotal = {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            total: Object.values(stats).reduce((a, b) => a + b, 0)
          };
        }
      } catch (vtError) {
        console.log('VT API error:', vtError.message);
      }
    }
    
    // AbuseIPDB check
    if (process.env.ABUSEIPDB_KEY && process.env.ABUSEIPDB_KEY !== 'your-abuseipdb-key-here') {
      try {
        const abuseResponse = await axios.get('https://api.abuseipdb.com/api/v2/check', {
          params: { ipAddress: ip, maxAgeInDays: 90 },
          headers: { 
            'Key': process.env.ABUSEIPDB_KEY.trim(), 
            'Accept': 'application/json' 
          },
          timeout: 5000
        });
        
        if (abuseResponse.data?.data) {
          result.abuseipdb = {
            abuseScore: abuseResponse.data.data.abuseConfidenceScore,
            country: abuseResponse.data.data.countryCode,
            isp: abuseResponse.data.data.isp,
            totalReports: abuseResponse.data.data.totalReports
          };
        }
      } catch (abuseError) {
        console.log('AbuseIPDB error:', abuseError.message);
      }
    }
    
    res.json(result);
  } catch (error) {
    console.error('IP enrichment error:', error);
    res.status(500).json({ error: 'Enrichment failed' });
  }
});

// Hash enrichment
router.get('/hash', async (req, res) => {
  const { hash } = req.query;
  if (!hash) return res.status(400).json({ error: 'Hash required' });
  
  try {
    const result = { hash };
    
    if (process.env.VT_API_KEY && process.env.VT_API_KEY !== 'your-vt-key-here') {
      try {
        const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { 'x-apikey': process.env.VT_API_KEY.trim() },
          timeout: 5000
        });
        
        if (vtResponse.data?.data?.attributes) {
          const stats = vtResponse.data.data.attributes.last_analysis_stats || {};
          result.virustotal = {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            total: Object.values(stats).reduce((a, b) => a + b, 0)
          };
        }
      } catch (vtError) {
        console.log('VT API error:', vtError.message);
      }
    }
    
    res.json(result);
  } catch (error) {
    console.error('Hash enrichment error:', error);
    res.status(500).json({ error: 'Enrichment failed' });
  }
});


module.exports = router;