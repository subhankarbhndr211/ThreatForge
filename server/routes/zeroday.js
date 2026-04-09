'use strict';
const express = require('express');
const router  = express.Router();

// ─── Cache & State ─────────────────────────────────────────────────────────
const CACHE = {};
function cached(key, ttlMs) {
  const c = CACHE[key];
  if (c && Date.now() - c.ts < ttlMs) return c.data;
  return null;
}
function setCache(key, data) { CACHE[key] = { ts: Date.now(), data }; return data; }

// Global auto-refresh state
const STATE = {
  lastRefresh: null,
  refreshCount: 0,
  isRefreshing: false,
  autoRefreshInterval: null,
  sources: {}
};

// ─── AI caller ─────────────────────────────────────────────────────────────
async function callAI(messages, maxTokens = 3000) {
  const p = (process.env.AI_PROVIDER || '').toLowerCase().trim();
  if (!p || p === 'none') throw new Error('No AI provider');
  const keyMap = { groq:'GROQ_API_KEY', openai:'OPENAI_API_KEY', anthropic:'ANTHROPIC_API_KEY', gemini:'GEMINI_API_KEY', mistral:'MISTRAL_API_KEY' };
  const key = process.env[keyMap[p]] || '';
  if (!key || key.startsWith('your-')) throw new Error('API key not configured — edit .env');

  if (p === 'groq') {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method:'POST', signal:AbortSignal.timeout(90000),
      headers:{ Authorization:'Bearer '+key, 'Content-Type':'application/json' },
      body: JSON.stringify({ model:process.env.GROQ_MODEL||'llama-3.3-70b-versatile', messages, max_tokens:maxTokens, temperature:0.3 })
    });
    if (!r.ok) throw new Error('Groq '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).choices[0].message.content;
  }
  if (p === 'anthropic') {
    const sys  = messages.find(m=>m.role==='system');
    const msgs = messages.filter(m=>m.role!=='system');
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST', signal:AbortSignal.timeout(90000),
      headers:{ 'x-api-key':key, 'anthropic-version':'2023-06-01', 'Content-Type':'application/json' },
      body: JSON.stringify({ model:process.env.ANTHROPIC_MODEL||'claude-3-5-sonnet-20241022', max_tokens:maxTokens, system:sys?.content||'', messages:msgs })
    });
    if (!r.ok) throw new Error('Anthropic '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).content[0].text;
  }
  if (p === 'openai') {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method:'POST', signal:AbortSignal.timeout(90000),
      headers:{ Authorization:'Bearer '+key, 'Content-Type':'application/json' },
      body: JSON.stringify({ model:process.env.OPENAI_MODEL||'gpt-4o', messages, max_tokens:maxTokens, temperature:0.3 })
    });
    if (!r.ok) throw new Error('OpenAI '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).choices[0].message.content;
  }
  if (p === 'gemini') {
    const model = process.env.GEMINI_MODEL||'gemini-1.5-flash';
    const url   = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`;
    const msgs  = messages.filter(m=>m.role!=='system').map(m=>({ role:m.role==='assistant'?'model':'user', parts:[{text:m.content}] }));
    const r = await fetch(url, { method:'POST', signal:AbortSignal.timeout(90000), headers:{'Content-Type':'application/json'}, body:JSON.stringify({contents:msgs}) });
    if (!r.ok) throw new Error('Gemini '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).candidates[0].content.parts[0].text;
  }
  if (p === 'mistral') {
    const r = await fetch('https://api.mistral.ai/v1/chat/completions', {
      method:'POST', signal:AbortSignal.timeout(90000),
      headers:{ Authorization:'Bearer '+key, 'Content-Type':'application/json' },
      body: JSON.stringify({ model:process.env.MISTRAL_MODEL||'mistral-large-latest', messages, max_tokens:maxTokens, temperature:0.3 })
    });
    if (!r.ok) throw new Error('Mistral '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).choices[0].message.content;
  }
  throw new Error('Unknown provider: '+p);
}

// ─── Safe fetch helper ──────────────────────────────────────────────────────
async function safeFetch(url, opts = {}, ttl = 0) {
  if (ttl) { const h = cached('fetch_'+url, ttl); if (h) return h; }
  try {
    const r = await fetch(url, { ...opts, signal:AbortSignal.timeout(15000) });
    if (!r.ok) throw new Error('HTTP '+r.status);
    const ct = r.headers.get('content-type') || '';
    const data = ct.includes('json') ? await r.json() : await r.text();
    if (ttl) setCache('fetch_'+url, data);
    return data;
  } catch(e) { console.warn('[ZD fetch]', url.slice(0,60), e.message); return null; }
}

// ─── Parse RSS/XML helper ───────────────────────────────────────────────────
function parseRSS(xml, limit = 20) {
  if (!xml || typeof xml !== 'string') return [];
  const items = [];
  const blocks = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)];
  for (const m of blocks) {
    const b = m[1];
    const get = (tag) => {
      const m2 = b.match(new RegExp('<'+tag+'><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/'+tag+'>')) ||
                 b.match(new RegExp('<'+tag+'>([\\s\\S]*?)<\\/'+tag+'>'));
      return m2 ? m2[1].trim() : '';
    };
    const title  = get('title');
    const link   = get('link') || b.match(/<link\s*\/?>(.*?)<\/(link|\/link)>/)?.[1] || '';
    const desc   = get('description').replace(/<[^>]+>/g,'').slice(0,300);
    const date   = get('pubDate') || get('dc:date') || get('updated') || '';
    const cve    = (title+desc).match(/CVE-\d{4}-\d+/)?.[0] || null;
    if (title) { items.push({ title, link:link.trim(), description:desc, date, cve, rawDate: date ? new Date(date) : new Date() }); }
    if (items.length >= limit) break;
  }
  return items.sort((a,b) => b.rawDate - a.rawDate);
}

// ════════════════════════════════════════════════════════════════════════════
// DATA SOURCES — All free, no authentication required
// ════════════════════════════════════════════════════════════════════════════

// 1. Exploit-DB RSS
async function getExploitDB() {
  const xml = await safeFetch('https://www.exploit-db.com/rss.xml', {}, 10*60*1000);
  const items = parseRSS(xml, 25).map(i => ({ ...i, source:'Exploit-DB', type:'exploit' }));
  STATE.sources['Exploit-DB'] = { count:items.length, ok:items.length>0, ts:Date.now() };
  return items;
}

// 2. CISA KEV recent additions
async function getCISAKEV() {
  const data = await safeFetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {}, 10*60*1000);
  if (!data?.vulnerabilities) { STATE.sources['CISA-KEV'] = { ok:false, ts:Date.now() }; return []; }
  const cutoff = Date.now() - 30*24*60*60*1000; // 30 days
  const items = data.vulnerabilities
    .filter(v => new Date(v.dateAdded).getTime() > cutoff)
    .sort((a,b) => new Date(b.dateAdded) - new Date(a.dateAdded))
    .slice(0,20)
    .map(v => ({
      title:       v.cveID + ' — ' + v.vulnerabilityName,
      description: v.shortDescription || v.vulnerabilityName,
      link:        'https://nvd.nist.gov/vuln/detail/'+v.cveID,
      cve:         v.cveID,
      date:        v.dateAdded,
      rawDate:     new Date(v.dateAdded),
      vendor:      v.vendorProject,
      product:     v.product,
      dueDate:     v.dueDate,
      action:      v.requiredAction,
      ransomware:  v.knownRansomwareCampaignUse === 'Known',
      source:      'CISA-KEV',
      type:        'kev'
    }));
  STATE.sources['CISA-KEV'] = { count:items.length, ok:true, ts:Date.now() };
  return items;
}

// 3. NVD Recent Critical CVEs
async function getNVDCritical() {
  const pubStart = new Date(Date.now()-3*24*60*60*1000).toISOString().split('.')[0]+'+00:00';
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${encodeURIComponent(pubStart)}&cvssV3Severity=CRITICAL&resultsPerPage=20`;
  const data = await safeFetch(url, {}, 15*60*1000);
  if (!data?.vulnerabilities) { STATE.sources['NVD-Critical'] = { ok:false, ts:Date.now() }; return []; }
  const items = data.vulnerabilities.filter(v=>v.cve).map(v => {
    const cve   = v.cve;
    const cvss  = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const desc  = (cve.descriptions||[]).find(d=>d.lang==='en')?.value || '';
    return {
      title:       cve.id + (cvss ? ' (CVSS '+cvss.baseScore+')' : ''),
      description: desc.slice(0,300),
      link:        'https://nvd.nist.gov/vuln/detail/'+cve.id,
      cve:         cve.id,
      cvss:        cvss?.baseScore||null,
      date:        cve.published,
      rawDate:     new Date(cve.published),
      source:      'NVD-Critical',
      type:        'cve'
    };
  });
  STATE.sources['NVD-Critical'] = { count:items.length, ok:true, ts:Date.now() };
  return items;
}

// 4. PacketStorm Security Advisories RSS
async function getPacketStorm() {
  const xml = await safeFetch('https://rss.packetstormsecurity.com/files/tags/advisory/', {}, 10*60*1000);
  const items = parseRSS(xml, 20).map(i => ({ ...i, source:'PacketStorm', type:'advisory' }));
  STATE.sources['PacketStorm'] = { count:items.length, ok:items.length>0, ts:Date.now() };
  return items;
}

// 5. Rapid7 AttackerKB RSS
async function getAttackerKB() {
  const xml = await safeFetch('https://attackerkb.com/rss', {}, 15*60*1000);
  const items = parseRSS(xml, 15).map(i => ({ ...i, source:'AttackerKB', type:'research' }));
  STATE.sources['AttackerKB'] = { count:items.length, ok:items.length>0, ts:Date.now() };
  return items;
}

// 6. SANS Internet Storm Center - active diary
async function getSANS() {
  const xml = await safeFetch('https://isc.sans.edu/rssfeed.xml', {}, 15*60*1000);
  const items = parseRSS(xml, 10).map(i => ({ ...i, source:'SANS-ISC', type:'research' }));
  STATE.sources['SANS-ISC'] = { count:items.length, ok:items.length>0, ts:Date.now() };
  return items;
}

// 7. GitHub PoC Exploit tracker
async function getGitHubPoC() {
  const data = await safeFetch(
    'https://api.github.com/search/repositories?q=CVE+poc+exploit&sort=updated&per_page=20&type=repositories',
    { headers:{ Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28' } },
    15*60*1000
  );
  if (!data?.items) { STATE.sources['GitHub-PoC'] = { ok:false, ts:Date.now() }; return []; }
  const items = data.items
    .filter(r => r.name.match(/CVE-\d{4}-\d+/i) || (r.description||'').match(/CVE-\d{4}-\d+/i))
    .slice(0,15)
    .map(r => {
      const cve = (r.name.match(/CVE-\d{4}-\d+/i)||[r.description?.match(/CVE-\d{4}-\d+/i)?.[0]])[0];
      return {
        title:       r.full_name + (cve ? ' ['+cve+']' : ''),
        description: (r.description||'').slice(0,200) + ' ⭐'+r.stargazers_count,
        link:        r.html_url,
        cve:         cve||null,
        date:        r.pushed_at,
        rawDate:     new Date(r.pushed_at),
        stars:       r.stargazers_count,
        source:      'GitHub-PoC',
        type:        'poc'
      };
    });
  STATE.sources['GitHub-PoC'] = { count:items.length, ok:true, ts:Date.now() };
  return items;
}

// 8. ThreatFox IOC Feed (malware + C2)
async function getThreatFox() {
  const data = await safeFetch('https://threatfox-api.abuse.ch/api/v1/',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ query:'get_iocs', days:1 })
  }, 10*60*1000);
  if (!data?.data) { STATE.sources['ThreatFox'] = { ok:false, ts:Date.now() }; return []; }
  const items = (data.data||[]).slice(0,15).map(i => ({
    title:       i.ioc_type + ': ' + (i.malware||'Unknown C2') + ' — ' + i.ioc,
    description: 'Malware: '+(i.malware||'?')+' | Tags: '+(i.tags||[]).join(',')+' | Confidence: '+i.confidence_level+'%',
    link:        'https://threatfox.abuse.ch/ioc/'+i.id,
    cve:         null,
    date:        i.first_seen,
    rawDate:     new Date(i.first_seen),
    source:      'ThreatFox',
    type:        'ioc',
    ioc:         i.ioc,
    malware:     i.malware,
    confidence:  i.confidence_level
  }));
  STATE.sources['ThreatFox'] = { count:items.length, ok:true, ts:Date.now() };
  return items;
}

// 9. Full Disclosure Security Mailing List
async function getFullDisclosure() {
  const xml = await safeFetch('https://seclists.org/rss/fulldisclosure.rss', {}, 15*60*1000);
  const items = parseRSS(xml, 10).map(i => ({ ...i, source:'Full-Disclosure', type:'disclosure' }));
  STATE.sources['Full-Disclosure'] = { count:items.length, ok:items.length>0, ts:Date.now() };
  return items;
}

// 10. Vendor Security Advisories RSS feeds
async function getVendorAdvisories() {
  const feeds = [
    { url:'https://www.microsoft.com/en-us/msrc/msrc-blog-rss', name:'Microsoft-MSRC' },
    { url:'https://support.apple.com/en-us/100100/rss', name:'Apple-Security' },
    { url:'https://www.redhat.com/en/rss/blog/channel/security', name:'RedHat-Security' },
    { url:'https://ubuntu.com/security/notices/rss.xml', name:'Ubuntu-Security' },
    { url:'https://www.debian.org/security/dsa', name:'Debian-DSA' },
    { url:'https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml', name:'Cisco-Advisory' },
  ];
  const all = [];
  for (const feed of feeds) {
    const xml = await safeFetch(feed.url, {}, 20*60*1000);
    const items = parseRSS(xml, 5).map(i => ({ ...i, source:feed.name, type:'vendor-advisory' }));
    STATE.sources[feed.name] = { count:items.length, ok:items.length>0, ts:Date.now() };
    all.push(...items);
  }
  return all.sort((a,b) => b.rawDate - a.rawDate).slice(0,20);
}

// 11. X/Twitter Security Community via Nitter (no auth required)
async function getSecurityTwitter() {
  // Use Nitter RSS instances for key security researchers/accounts
  const accounts = [
    { handle:'vxunderground',    url:'https://nitter.poast.org/vxunderground/rss',    name:'vx-underground' },
    { handle:'GossiTheDog',      url:'https://nitter.poast.org/GossiTheDog/rss',      name:'Kevin-Beaumont' },
    { handle:'malwrhunterteam',  url:'https://nitter.poast.org/malwrhunterteam/rss',  name:'MalwareHunterTeam' },
    { handle:'threatintelctr',   url:'https://nitter.poast.org/threatintelctr/rss',   name:'ThreatIntelCenter' },
    { handle:'CVEnew',           url:'https://nitter.poast.org/CVEnew/rss',           name:'CVE-New-Bot' },
    { handle:'CISA_Cyber',       url:'https://nitter.poast.org/CISACyber/rss',        name:'CISA-Official' },
    { handle:'cyber__slava',     url:'https://nitter.poast.org/cyber__slava/rss',     name:'CyberSlava' },
  ];
  const all = [];
  for (const acct of accounts) {
    try {
      const xml = await safeFetch(acct.url, {}, 10*60*1000);
      const items = parseRSS(xml, 5).map(i => ({
        ...i,
        source: 'X/Twitter:'+acct.name,
        type:   'social',
        handle: acct.handle
      }));
      STATE.sources['X:'+acct.name] = { count:items.length, ok:items.length>0, ts:Date.now() };
      all.push(...items);
    } catch(e) {
      STATE.sources['X:'+acct.name] = { ok:false, error:e.message, ts:Date.now() };
    }
  }
  return all.sort((a,b) => b.rawDate - a.rawDate).slice(0,20);
}

// 12. Dark Web Monitoring via public intelligence feeds
// Note: Real dark web monitoring requires Tor + specialized APIs (Recorded Future, Flashpoint, etc.)
// These are the best FREE public alternatives that surface dark web activity:
async function getDarkWebIntel() {
  const sources = [];

  // DarkOwl/DarkFeed public advisories (RSS)
  const df = await safeFetch('https://www.darkowl.com/feed/', {}, 30*60*1000);
  if (df) {
    const items = parseRSS(df, 10).map(i => ({ ...i, source:'DarkOwl-Blog', type:'darkweb-intel' }));
    sources.push(...items);
    STATE.sources['DarkOwl'] = { count:items.length, ok:true, ts:Date.now() };
  }

  // SpyCloud blog (tracks dark web data breaches and credential theft)
  const sc = await safeFetch('https://spycloud.com/blog/feed/', {}, 30*60*1000);
  if (sc) {
    const items = parseRSS(sc, 8).map(i => ({ ...i, source:'SpyCloud', type:'darkweb-intel' }));
    sources.push(...items);
    STATE.sources['SpyCloud'] = { count:items.length, ok:true, ts:Date.now() };
  }

  // RansomWatch - tracks ransomware leak sites (monitors .onion sites)
  const rw = await safeFetch('https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json', {}, 15*60*1000);
  if (rw && Array.isArray(rw)) {
    const recent = rw
      .sort((a,b) => new Date(b.discovered||0) - new Date(a.discovered||0))
      .slice(0,20)
      .map(p => ({
        title:       '🔒 ' + (p.group_name||'Unknown Group') + ' leaked: ' + (p.post_title||'Victim Data'),
        description: 'Ransomware group ' + (p.group_name||'?') + ' published new victim data. Discovered: ' + (p.discovered||'unknown'),
        link:        'https://ransomwatch.telemetry.ltd',
        cve:         null,
        date:        p.discovered||new Date().toISOString(),
        rawDate:     new Date(p.discovered||Date.now()),
        source:      'RansomWatch',
        type:        'ransomware-leak',
        group:       p.group_name
      }));
    sources.push(...recent);
    STATE.sources['RansomWatch'] = { count:recent.length, ok:true, ts:Date.now() };
  }

  // HaveIBeenPwned breach notifications (public API, no key for notifications)
  const hibp = await safeFetch('https://haveibeenpwned.com/api/v3/latestbreach', {
    headers:{ 'hibp-api-key':'', 'User-Agent':'ThreatForge-SOC/4.0' }
  }, 30*60*1000);
  if (hibp?.Name) {
    sources.push({
      title:       '💧 Data Breach: ' + hibp.Name,
      description: hibp.Description?.replace(/<[^>]+>/g,'').slice(0,200) || 'New data breach reported',
      link:        'https://haveibeenpwned.com/PwnedWebsites#'+hibp.Name,
      cve:         null,
      date:        hibp.AddedDate,
      rawDate:     new Date(hibp.AddedDate),
      source:      'HIBP-Breach',
      type:        'breach',
      dataClasses: hibp.DataClasses
    });
    STATE.sources['HIBP'] = { ok:true, ts:Date.now() };
  }

  return sources.sort((a,b) => b.rawDate - a.rawDate);
}

// 13. Malware Bazaar recent samples
async function getMalwareBazaar() {
  const data = await safeFetch('https://mb-api.abuse.ch/api/v1/',{
    method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'query=get_recent&selector=time'
  }, 10*60*1000);
  if (!data?.data) { STATE.sources['MalwareBazaar'] = { ok:false, ts:Date.now() }; return []; }
  const items = (data.data||[]).slice(0,15).map(s => ({
    title:       '🦠 ' + (s.signature||s.file_type||'Unknown Malware') + ' — '+s.sha256_hash.slice(0,16)+'...',
    description: 'Family: '+(s.signature||'?')+' | Type: '+(s.file_type||'?')+' | Tags: '+(s.tags||[]).join(','),
    link:        'https://bazaar.abuse.ch/sample/'+s.sha256_hash,
    cve:         null,
    date:        s.first_seen,
    rawDate:     new Date(s.first_seen),
    source:      'MalwareBazaar',
    type:        'malware',
    hash:        s.sha256_hash,
    family:      s.signature
  }));
  STATE.sources['MalwareBazaar'] = { count:items.length, ok:true, ts:Date.now() };
  return items;
}

// ════════════════════════════════════════════════════════════════════════════
// SIGNAL AGGREGATOR
// ════════════════════════════════════════════════════════════════════════════
async function gatherAllSignals() {
  const results = await Promise.allSettled([
    getExploitDB(),
    getCISAKEV(),
    getNVDCritical(),
    getPacketStorm(),
    getAttackerKB(),
    getSANS(),
    getGitHubPoC(),
    getThreatFox(),
    getFullDisclosure(),
    getVendorAdvisories(),
    getSecurityTwitter(),
    getDarkWebIntel(),
    getMalwareBazaar()
  ]);
  return results.flatMap(r => r.value || []).sort((a,b) => b.rawDate - a.rawDate);
}

// ════════════════════════════════════════════════════════════════════════════
// AI SYNTHESIS — Turns raw signals into structured threat intelligence
// ════════════════════════════════════════════════════════════════════════════
async function synthesizeIntel(signals, productFilter = null) {
  const today    = new Date().toISOString().split('T')[0];
  const relevant = productFilter
    ? signals.filter(s => (s.title+s.description).toLowerCase().includes(productFilter.toLowerCase())).slice(0,30)
    : signals.slice(0,40);

  const signalText = relevant.map(s =>
    `[${s.source}] ${s.title}\n${s.description}\nCVE:${s.cve||'N/A'} | Date:${s.date||'?'}`
  ).join('\n---\n').slice(0,6000);

  const filterNote = productFilter ? `\nFOCUS: Filter results to "${productFilter}" related threats only.` : '';

  try {
    const reply = await callAI([
      {
        role:'system',
        content:`You are an elite threat intelligence analyst for a 24/7 SOC. Today is ${today}.
Analyze raw security signals from dark web monitoring, exploit databases, social media, and threat feeds.
Synthesize into actionable zero-day and emerging threat intelligence.${filterNote}

Output ONLY valid JSON matching this exact schema:
{
  "generatedAt": "${today}T${new Date().toTimeString().slice(0,8)}Z",
  "riskLevel": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "2-3 sentence executive summary for CISO",
  "productFilter": ${productFilter ? '"'+productFilter+'"' : 'null'},
  "threats": [
    {
      "id": "ZD-${Date.now()}-001",
      "title": "Threat title",
      "severity": "CRIT|HIGH|MED|LOW",
      "category": "RCE|LPE|AuthBypass|InfoDisclosure|DoS|SupplyChain|Ransomware|DataBreach|Malware",
      "affectedProducts": ["Product A", "Product B"],
      "affectedVersions": "e.g. < 2.4.1",
      "cve": "CVE-XXXX-XXXXX or null",
      "description": "Detailed technical description",
      "exploitStatus": "Actively-Exploited|Weaponized|PoC-Public|Theoretical|Dark-Web-Mention",
      "threatActors": ["known actor if any"],
      "darkWebActivity": "Dark web mentions or ransomware group activity if any",
      "iocs": ["pattern1","ip:port or domain","hash"],
      "detectionSplunk": "Complete Splunk SPL query",
      "detectionSentinel": "Complete KQL query",
      "mitre": "T1190",
      "mitigation": "Immediate action steps",
      "priority": 1,
      "sources": ["Source1","Source2"],
      "confidence": "HIGH|MEDIUM|LOW"
    }
  ],
  "huntingPriorities": ["Priority 1","Priority 2","Priority 3","Priority 4","Priority 5"],
  "emergingTTPs": ["TTP description 1","TTP description 2"],
  "darkWebSummary": "Summary of dark web activity observed in signals",
  "ransomwareActivity": "Current ransomware group activity summary"
}`
      },
      {
        role:'user',
        content:`Analyze these ${relevant.length} security signals and generate structured threat intelligence:\n\n${signalText}\n\nGenerate 6-10 actionable threat entries. Output ONLY the JSON.`
      }
    ], 4000);

    const clean  = reply.replace(/```json\n?|\n?```/g,'').trim();
    const parsed = JSON.parse(clean.includes('{') ? clean.slice(clean.indexOf('{')) : clean);
    parsed.aiGenerated = true;
    parsed.signalCount = signals.length;
    return parsed;

  } catch(err) {
    console.warn('[ZD] AI synthesis failed:', err.message);
    // Fallback: structure the raw signals without AI
    const kevItems = signals.filter(s => s.type === 'kev').slice(0,8);
    const exploits  = signals.filter(s => s.type === 'exploit').slice(0,4);
    const darkweb   = signals.filter(s => s.type === 'ransomware-leak' || s.type === 'darkweb-intel').slice(0,4);
    return {
      generatedAt:      new Date().toISOString(),
      riskLevel:        'HIGH',
      summary:          'Real-time signals from '+Object.keys(STATE.sources).length+' sources. AI synthesis unavailable ('+err.message+'). Raw signals displayed below.',
      aiGenerated:      false,
      aiError:          err.message,
      productFilter:    productFilter||null,
      signalCount:      signals.length,
      threats:          [...kevItems,...exploits].slice(0,8).map((s,i) => ({
        id:              'SIG-'+i,
        title:           s.title,
        severity:        s.type==='kev'?'CRIT':'HIGH',
        category:        s.type==='kev'?'KEV':'Exploit',
        affectedProducts:[s.vendor||'Unknown', s.product||'Unknown'],
        cve:             s.cve||null,
        description:     s.description||s.title,
        exploitStatus:   s.type==='kev'?'Actively-Exploited':'PoC-Public',
        threatActors:    s.ransomware?['Ransomware Groups']:[],
        darkWebActivity: '',
        iocs:            [],
        detectionSplunk:  s.cve?'index=* "'+s.cve+'" | stats count by host, src_ip | sort -count':'',
        detectionSentinel:s.cve?'SecurityEvent | where EventData has "'+s.cve+'" | summarize count() by Computer':'',
        mitre:           'T1190',
        mitigation:      s.action||'Apply patches immediately',
        priority:        i+1,
        sources:         [s.source],
        confidence:      'HIGH'
      })),
      huntingPriorities: [
        'Scan all internet-facing assets for CISA KEV vulnerabilities',
        'Hunt for exploitation patterns from recent Exploit-DB publications',
        'Monitor for ransomware precursors: BloodHound, Cobalt Strike, credential dumping',
        'Check for IOCs from ThreatFox in your SIEM',
        'Review vendor advisories for your specific technology stack'
      ],
      emergingTTPs:     ['Monitor new Exploit-DB publications for your product stack'],
      darkWebSummary:   darkweb.map(d=>d.title).join('; ') || 'No dark web signals collected',
      ransomwareActivity: darkweb.filter(d=>d.type==='ransomware-leak').map(d=>d.title).join('; ') || 'Monitoring ransomware leak sites'
    };
  }
}

// ════════════════════════════════════════════════════════════════════════════
// AUTO-REFRESH ENGINE — Runs 24/7 at configurable intervals
// ════════════════════════════════════════════════════════════════════════════
const REFRESH_INTERVAL_MS = 15 * 60 * 1000; // 15 minutes

async function runRefresh(force = false, productFilter = null) {
  if (STATE.isRefreshing && !force) return;
  STATE.isRefreshing = true;
  console.log('[ZD] 🔄 Refreshing zero-day intel... Sources:', Object.keys(STATE.sources).length || 'initial');
  try {
    const signals = await gatherAllSignals();
    setCache('raw_signals', signals);
    const intel = await synthesizeIntel(signals, productFilter);
    setCache('zeroday_intel', intel);
    STATE.lastRefresh  = new Date().toISOString();
    STATE.refreshCount += 1;
    console.log(`[ZD] ✅ Refresh #${STATE.refreshCount} complete. Signals: ${signals.length}, Sources: ${Object.keys(STATE.sources).length}`);
  } catch(err) {
    console.error('[ZD] ❌ Refresh failed:', err.message);
  } finally {
    STATE.isRefreshing = false;
  }
}

// Start auto-refresh on module load
function startAutoRefresh() {
  if (STATE.autoRefreshInterval) return;
  // First refresh after 5 seconds (let server start)
  setTimeout(() => runRefresh(true), 5000);
  // Then every 15 minutes
  STATE.autoRefreshInterval = setInterval(() => runRefresh(false), REFRESH_INTERVAL_MS);
  console.log('[ZD] ⏰ Auto-refresh started — every 15 minutes');
}
startAutoRefresh();

// ════════════════════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/zeroday — main intel feed
router.get('/', async (req, res) => {
  const force  = req.query.refresh === 'true';
  const product = req.query.product || null;
  if (force) await runRefresh(true, product);
  let intel = cached('zeroday_intel', 20*60*1000);
  if (!intel) {
    // First load — gather and synthesize
    await runRefresh(true, product);
    intel = cached('zeroday_intel', 60*60*1000);
  }
  if (!intel) return res.status(503).json({ error:'Intelligence not yet available', refreshing:STATE.isRefreshing });
  intel.nextRefreshIn = Math.max(0, REFRESH_INTERVAL_MS - (Date.now() - new Date(STATE.lastRefresh||0).getTime()));
  intel.autoRefreshActive = !!STATE.autoRefreshInterval;
  res.json(intel);
});

// GET /api/zeroday/signals — raw signals
router.get('/signals', async (req, res) => {
  const type    = req.query.type || 'all';
  const product = req.query.product || '';
  let signals   = cached('raw_signals', 20*60*1000) || [];
  if (type !== 'all') signals = signals.filter(s => s.type === type);
  if (product)        signals = signals.filter(s => (s.title+s.description).toLowerCase().includes(product.toLowerCase()));
  res.json({ total:signals.length, signals:signals.slice(0,100), fetchedAt:STATE.lastRefresh, sources:STATE.sources });
});

// GET /api/zeroday/search?q=product — product-specific search
router.get('/search', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.status(400).json({ error:'q param required' });
  const signals = cached('raw_signals', 60*60*1000) || [];
  const filtered = signals.filter(s =>
    (s.title+s.description+s.cve).toLowerCase().includes(q.toLowerCase())
  ).slice(0,50);
  let intel = null;
  if (filtered.length > 0) {
    try { intel = await synthesizeIntel(filtered, q); } catch(e) {}
  }
  res.json({ query:q, signalCount:filtered.length, signals:filtered, intel, fetchedAt:new Date().toISOString() });
});

// GET /api/zeroday/status — auto-refresh status
router.get('/status', (req, res) => {
  res.json({
    lastRefresh:        STATE.lastRefresh,
    refreshCount:       STATE.refreshCount,
    isRefreshing:       STATE.isRefreshing,
    autoRefreshActive:  !!STATE.autoRefreshInterval,
    refreshIntervalMin: REFRESH_INTERVAL_MS/60000,
    nextRefreshIn:      STATE.lastRefresh ? Math.max(0, REFRESH_INTERVAL_MS-(Date.now()-new Date(STATE.lastRefresh).getTime())) : 0,
    sourcesOnline:      Object.values(STATE.sources).filter(s=>s.ok).length,
    sourcesTotal:       Object.keys(STATE.sources).length,
    sources:            STATE.sources
  });
});

// POST /api/zeroday/product-watch — watch specific products
router.post('/product-watch', async (req, res) => {
  const { products } = req.body;
  if (!products?.length) return res.status(400).json({ error:'products array required' });
  const signals = cached('raw_signals', 60*60*1000) || [];
  const results = {};
  for (const p of products.slice(0,5)) {
    const filtered = signals.filter(s => (s.title+s.description).toLowerCase().includes(p.toLowerCase()));
    results[p] = filtered.slice(0,10);
  }
  res.json({ products, results, total:Object.values(results).reduce((s,a)=>s+a.length,0) });
});

module.exports = router;
