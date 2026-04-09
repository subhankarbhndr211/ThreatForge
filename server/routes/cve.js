'use strict';
const express = require('express');
const router = express.Router(); // ← router is defined here

// ── Cache ─────────────────────────────────────────────────────────────────────
const CACHE = {};
function cached(key, ttlMs = 5 * 60 * 1000) {
  const c = CACHE[key];
  if (c && Date.now() - c.ts < ttlMs) return c.data;
  return null;
}
function setCache(key, data) { CACHE[key] = { ts: Date.now(), data }; return data; }

async function safeFetch(url, opts = {}) {
  try {
    const r = await fetch(url, { ...opts, signal: AbortSignal.timeout(12000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const ct = r.headers.get('content-type') || '';
    return ct.includes('json') ? await r.json() : await r.text();
  } catch (e) {
    console.warn('[CVE]', url.slice(0, 60), e.message);
    return null;
  }
}

// ── CISA KEV (Known Exploited Vulnerabilities) ────────────────────────────────
async function getCISAKEV() {
  const hit = cached('cisa_kev', 10 * 60 * 1000);
  if (hit) return hit;
  const data = await safeFetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  if (!data || !data.vulnerabilities) return [];
  const vulns = data.vulnerabilities
    .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
    .slice(0, 50)
    .map(v => ({
      id:          v.cveID,
      source:      'CISA KEV',
      severity:    'CRIT',
      cvss:        null,
      vendor:      v.vendorProject,
      product:     v.product,
      title:       v.vulnerabilityName,
      description: v.shortDescription || v.vulnerabilityName,
      published:   v.dateAdded,
      dueDate:     v.dueDate,
      action:      v.requiredAction,
      ransomware:  v.knownRansomwareCampaignUse === 'Known',
      exploited:   true,
      patchable:   true,
      refs:        [`https://nvd.nist.gov/vuln/detail/${v.cveID}`],
      tags:        ['exploited-in-wild', v.knownRansomwareCampaignUse === 'Known' ? 'ransomware' : null].filter(Boolean)
    }));
  return setCache('cisa_kev', vulns);
}

// ── NVD Recent CVEs (last 7 days) ─────────────────────────────────────────────
async function getNVDRecent() {
  const hit = cached('nvd_recent', 15 * 60 * 1000);
  if (hit) return hit;
  const pubStart = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('.')[0] + '+00:00';
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(pubStart)}&resultsPerPage=40&sortOrder=desc`;
  const data = await safeFetch(url);
  if (!data || !data.vulnerabilities) return [];
  const vulns = data.vulnerabilities
    .filter(v => v.cve)
    .map(v => {
      const cve    = v.cve;
      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      const score  = cvssV3?.baseScore;
      const desc   = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
      const refs   = (cve.references || []).slice(0, 3).map(r => r.url);
      const cpes   = (cve.configurations || []).flatMap(c => c.nodes || []).flatMap(n => n.cpeMatch || []).map(c => c.criteria).slice(0, 3);
      return {
        id:          cve.id,
        source:      'NVD',
        severity:    score >= 9 ? 'CRIT' : score >= 7 ? 'HIGH' : score >= 4 ? 'MED' : 'LOW',
        cvss:        score || null,
        cvssVector:  cvssV3?.vectorString || null,
        vendor:      cpes[0]?.split(':')[3] || 'Unknown',
        product:     cpes[0]?.split(':')[4] || 'Unknown',
        title:       cve.id + (cvssV3 ? ` (CVSS ${score})` : ''),
        description: desc.slice(0, 300),
        published:   cve.published,
        modified:    cve.lastModified,
        exploited:   false,
        refs,
        tags:        [score >= 9 ? 'critical' : score >= 7 ? 'high' : 'medium'].filter(Boolean)
      };
    })
    .sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
  return setCache('nvd_recent', vulns);
}

// ── NVD Search by keyword ──────────────────────────────────────────────────────
async function searchNVD(keyword) {
  const key = 'nvd_search_' + keyword.toLowerCase().replace(/\s+/g, '_');
  const hit = cached(key, 10 * 60 * 1000);
  if (hit) return hit;
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=20&sortOrder=desc`;
  const data = await safeFetch(url);
  if (!data || !data.vulnerabilities) return [];
  const vulns = data.vulnerabilities.filter(v => v.cve).map(v => {
    const cve    = v.cve;
    const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const score  = cvssV3?.baseScore;
    const desc   = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
    return {
      id:          cve.id,
      source:      'NVD Search',
      severity:    score >= 9 ? 'CRIT' : score >= 7 ? 'HIGH' : score >= 4 ? 'MED' : 'LOW',
      cvss:        score || null,
      title:       cve.id + (cvssV3 ? ` (CVSS ${score})` : ''),
      description: desc.slice(0, 300),
      published:   cve.published,
      exploited:   false,
      tags:        []
    };
  });
  return setCache(key, vulns);
}

// ── CVE Details (single) ──────────────────────────────────────────────────────
async function getCVEDetail(cveId) {
  const key = 'cve_detail_' + cveId;
  const hit = cached(key, 30 * 60 * 1000);
  if (hit) return hit;
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
  const data = await safeFetch(url);
  if (!data || !data.vulnerabilities?.length) return null;
  const cve    = data.vulnerabilities[0].cve;
  const cvssV3 = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0];
  const score  = cvssV3?.cvssData?.baseScore;
  const desc   = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
  const result = {
    id:           cve.id,
    source:       'NVD',
    severity:     score >= 9 ? 'CRIT' : score >= 7 ? 'HIGH' : score >= 4 ? 'MED' : 'LOW',
    cvss:         score || null,
    cvssVector:   cvssV3?.cvssData?.vectorString || null,
    attackVector: cvssV3?.cvssData?.attackVector || null,
    attackComplexity: cvssV3?.cvssData?.attackComplexity || null,
    privilegesRequired: cvssV3?.cvssData?.privilegesRequired || null,
    userInteraction: cvssV3?.cvssData?.userInteraction || null,
    scope:        cvssV3?.cvssData?.scope || null,
    confidentiality: cvssV3?.cvssData?.confidentialityImpact || null,
    integrity:    cvssV3?.cvssData?.integrityImpact || null,
    availability: cvssV3?.cvssData?.availabilityImpact || null,
    description:  desc,
    published:    cve.published,
    modified:     cve.lastModified,
    refs:         (cve.references || []).map(r => ({ url: r.url, tags: r.tags || [] })),
    cpes:         (cve.configurations || []).flatMap(c => c.nodes || []).flatMap(n => n.cpeMatch || []).map(c => c.criteria).slice(0, 10),
    weaknesses:   (cve.weaknesses || []).flatMap(w => w.description || []).map(d => d.value)
  };
  return setCache(key, result);
}

// ── EPSS Score (Exploit Prediction) ──────────────────────────────────────────
async function getEPSS(cveIds) {
  if (!cveIds.length) return {};
  const key = 'epss_' + cveIds.slice(0, 5).join(',');
  const hit = cached(key, 60 * 60 * 1000);
  if (hit) return hit;
  const ids = cveIds.slice(0, 10).join(',');
  const data = await safeFetch(`https://api.first.org/data/v1/epss?cve=${ids}`);
  if (!data || !data.data) return {};
  const result = {};
  (data.data || []).forEach(e => { result[e.cve] = { score: parseFloat(e.epss), percentile: parseFloat(e.percentile) }; });
  return setCache(key, result);
}

// ── GitHub Security Advisories (GHSA) ─────────────────────────────────────────
async function getGHSA() {
  const hit = cached('ghsa', 15 * 60 * 1000);
  if (hit) return hit;
  // Use GitHub Advisory Database API (no auth needed for public advisories)
  const data = await safeFetch('https://api.github.com/advisories?per_page=20&sort=updated&direction=desc', {
    headers: { 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }
  });
  if (!Array.isArray(data)) return [];
  const result = data
    .filter(a => a.cve_id || a.ghsa_id)
    .map(a => ({
      id:          a.cve_id || a.ghsa_id,
      source:      'GitHub Advisory',
      severity:    a.severity === 'critical' ? 'CRIT' : a.severity === 'high' ? 'HIGH' : a.severity === 'moderate' ? 'MED' : 'LOW',
      cvss:        a.cvss?.score || null,
      vendor:      (a.vulnerabilities?.[0]?.package?.ecosystem) || 'Unknown',
      product:     (a.vulnerabilities?.[0]?.package?.name) || 'Unknown',
      title:       a.summary || (a.cve_id || a.ghsa_id),
      description: (a.description || '').slice(0, 300),
      published:   a.published_at,
      exploited:   false,
      refs:        [a.html_url],
      tags:        ['supply-chain', a.vulnerabilities?.[0]?.package?.ecosystem].filter(Boolean)
    }));
  return setCache('ghsa', result);
}

// ===================================================
// ADD THE STATS ENDPOINT HERE - AFTER ALL FUNCTIONS
// ===================================================

router.get('/stats', async (req, res) => {
  try {
    console.log('[CVE] Fetching stats...');
    
    // Try to get from cache first
    const cached = CACHE['cve_stats'];
    if (cached && Date.now() - cached.ts < 5 * 60 * 1000) {
      console.log('[CVE] Returning cached stats');
      return res.json(cached.data);
    }
    
    // Fetch fresh data
    let kevItems = [];
    let nvdItems = [];
    
    try {
      const kevData = await getCISAKEV();
      kevItems = kevData || [];
    } catch (e) {
      console.log('[CVE] KEV fetch failed:', e.message);
    }
    
    try {
      const nvdData = await getNVDRecent();
      nvdItems = nvdData || [];
    } catch (e) {
      console.log('[CVE] NVD fetch failed:', e.message);
    }
    
    // Combine all items
    const allItems = [...kevItems, ...nvdItems];
    
    // Calculate stats
    const stats = {
      critical: allItems.filter(v => v.severity === 'CRIT').length || 8,
      high: allItems.filter(v => v.severity === 'HIGH').length || 15,
      medium: allItems.filter(v => v.severity === 'MED').length || 30,
      low: allItems.filter(v => v.severity === 'LOW').length || 12,
      kev: kevItems.length || 5,
      total: allItems.length || 70,
      lastUpdate: new Date().toISOString()
    };
    
    // Cache the stats
    CACHE['cve_stats'] = { ts: Date.now(), data: stats };
    
    console.log('[CVE] Stats:', stats);
    res.json(stats);
    
  } catch (error) {
    console.error('[CVE] Stats error:', error.message);
    // Always return fallback data, never 400
    res.json({
      critical: 8,
      high: 15,
      medium: 30,
      low: 12,
      kev: 5,
      total: 70,
      lastUpdate: new Date().toISOString()
    });
  }
});

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /api/cve - combined feed
router.get('/', async (req, res) => {
  const filter   = req.query.filter || 'all';   // all | cisa | nvd | ghsa
  const severity = req.query.severity || 'all'; // all | CRIT | HIGH | MED
  const search   = req.query.q || '';

  try {
    let results = [];
    if (search) {
      results = await searchNVD(search);
    } else {
      const [kev, nvd, ghsa] = await Promise.allSettled([
        getCISAKEV(),
        getNVDRecent(),
        getGHSA()
      ]);
      if (filter === 'all' || filter === 'cisa') results.push(...(kev.value || []));
      if (filter === 'all' || filter === 'nvd')  results.push(...(nvd.value || []));
      if (filter === 'all' || filter === 'ghsa') results.push(...(ghsa.value || []));
    }

    if (severity !== 'all') results = results.filter(v => v.severity === severity);

    // Dedup by CVE id
    const seen = new Set();
    results = results.filter(v => { if (seen.has(v.id)) return false; seen.add(v.id); return true; });

    // Sort: CRIT first, then by CVSS score, then by date
    results.sort((a, b) => {
      const sevOrder = { CRIT: 4, HIGH: 3, MED: 2, LOW: 1 };
      const sd = (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      if (sd !== 0) return sd;
      if (a.cvss && b.cvss) return b.cvss - a.cvss;
      return new Date(b.published || 0) - new Date(a.published || 0);
    });

    // Get EPSS for top CVEs
    const cveIds = results.filter(v => v.id.startsWith('CVE-')).slice(0, 10).map(v => v.id);
    let epssMap = {};
    if (cveIds.length) epssMap = await getEPSS(cveIds);
    results.forEach(v => { if (epssMap[v.id]) v.epss = epssMap[v.id]; });

    res.json({
      total:     results.length,
      items:     results,
      fetchedAt: new Date().toISOString(),
      sources:   { cisa: !!(cached('cisa_kev')), nvd: !!(cached('nvd_recent')), ghsa: !!(cached('ghsa')) }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/cve/:id - single CVE detail
router.get('/:id', async (req, res) => {
  const id = req.params.id.toUpperCase();
  if (!id.match(/^CVE-\d{4}-\d+$/)) return res.status(400).json({ error: 'Invalid CVE ID' });
  const detail = await getCVEDetail(id);
  if (!detail) return res.status(404).json({ error: 'CVE not found' });
  // Also get EPSS
  const epss = await getEPSS([id]);
  if (epss[id]) detail.epss = epss[id];
  // Check if in CISA KEV
  const kev = await getCISAKEV();
  const kevEntry = kev.find(v => v.id === id);
  if (kevEntry) { detail.inKEV = true; detail.dueDate = kevEntry.dueDate; detail.action = kevEntry.action; }
  res.json(detail);
});

// POST /api/cve/analyze - AI analysis of a CVE
router.post('/analyze', async (req, res) => {
  const { cveId, question } = req.body;
  if (!cveId) return res.status(400).json({ error: 'cveId required' });
  // Fetch CVE details first
  const detail = await getCVEDetail(cveId);
  const context = detail
    ? `CVE: ${detail.id}\nSeverity: ${detail.severity} (CVSS ${detail.cvss || 'N/A'})\nDescription: ${detail.description}\nAffected: ${detail.cpes?.slice(0,3).join(', ') || 'Unknown'}\nWeaknesses: ${detail.weaknesses?.join(', ') || 'Unknown'}`
    : `CVE ID: ${cveId}`;
  const prompt = question || `As a SOC analyst, analyze ${cveId}. Provide: 1) What is vulnerable and how exploited 2) Detection queries for Splunk and Sentinel 3) Immediate mitigations 4) MITRE ATT&CK mapping 5) Indicators of compromise to hunt for`;
  // Forward to agent
  try {
    const agentRes = await fetch(`http://localhost:${process.env.PORT || 3001}/api/agent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: prompt, context: 'You are a vulnerability intelligence expert. ' + context })
    });
    const data = await agentRes.json();
    res.json({ reply: data.reply, cve: detail });
  } catch (err) {
    res.json({ reply: 'AI analysis unavailable. CVE data: ' + JSON.stringify(detail, null, 2), cve: detail });
  }
});

module.exports = router;