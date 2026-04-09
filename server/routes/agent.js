'use strict';
const express = require('express');
const router  = express.Router();

const SOC_SYSTEM = `You are ThreatForge AI Agent — an expert SOC analyst embedded in a security operations platform.

EXPERTISE: MITRE ATT&CK, Splunk SPL, Azure Sentinel KQL, QRadar AQL, Elastic EQL/KQL, Chronicle YARA-L, CrowdStrike FQL, Defender Advanced Hunting, SentinelOne DQL, Cortex XDR, threat actors (APT28/29, Lazarus, Scattered Spider, LockBit, Volt Typhoon), Windows/Linux/Cloud logs, AI/LLM security threats, incident response.

When writing queries: use code blocks with language labels (splunk, kql, etc). Be specific, practical, production-ready. Include MITRE ATT&CK mappings. Give tuning tips to reduce false positives.`;

function getProvider() {
  return (process.env.AI_PROVIDER || '').toLowerCase().trim();
}

function isConfigured() {
  const p = getProvider();
  if (p === 'ollama') return true;
  const keys = { anthropic:'ANTHROPIC_API_KEY', openai:'OPENAI_API_KEY', gemini:'GEMINI_API_KEY', groq:'GROQ_API_KEY', mistral:'MISTRAL_API_KEY' };
  const k = process.env[keys[p]] || '';
  return k.length > 10 && !k.includes('your-');
}

async function callAI(messages) {
  const p = getProvider();

  if (p === 'groq') {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method:'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization':'Bearer '+process.env.GROQ_API_KEY, 'Content-Type':'application/json' },
      body: JSON.stringify({ model: process.env.GROQ_MODEL||'llama-3.3-70b-versatile', messages, max_tokens:4000, temperature:0.3 })
    });
    if (!r.ok) throw new Error('Groq error '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'anthropic') {
    const sys = messages.find(m=>m.role==='system');
    const msgs = messages.filter(m=>m.role!=='system');
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST', signal: AbortSignal.timeout(60000),
      headers: { 'x-api-key':process.env.ANTHROPIC_API_KEY, 'anthropic-version':'2023-06-01', 'Content-Type':'application/json' },
      body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL||'claude-3-5-sonnet-20241022', max_tokens:4000, system: sys?.content||SOC_SYSTEM, messages: msgs })
    });
    if (!r.ok) throw new Error('Anthropic error '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).content[0].text;
  }

  if (p === 'openai') {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method:'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization':'Bearer '+process.env.OPENAI_API_KEY, 'Content-Type':'application/json' },
      body: JSON.stringify({ model: process.env.OPENAI_MODEL||'gpt-4o', messages, max_tokens:4000, temperature:0.3 })
    });
    if (!r.ok) throw new Error('OpenAI error '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'gemini') {
    const model = process.env.GEMINI_MODEL||'gemini-1.5-flash';
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;
    const userMsgs = messages.filter(m=>m.role!=='system');
    const contents = userMsgs.map(m=>({ role: m.role==='assistant'?'model':'user', parts:[{text:m.content}] }));
    const r = await fetch(url, {
      method:'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ contents, generationConfig:{ temperature:0.3, maxOutputTokens:4000 } })
    });
    if (!r.ok) throw new Error('Gemini error '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).candidates[0].content.parts[0].text;
  }

  if (p === 'mistral') {
    const r = await fetch('https://api.mistral.ai/v1/chat/completions', {
      method:'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization':'Bearer '+process.env.MISTRAL_API_KEY, 'Content-Type':'application/json' },
      body: JSON.stringify({ model: process.env.MISTRAL_MODEL||'mistral-large-latest', messages, max_tokens:4000, temperature:0.3 })
    });
    if (!r.ok) throw new Error('Mistral error '+r.status+': '+(await r.text()).slice(0,200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'ollama') {
    const url = (process.env.OLLAMA_URL||'http://localhost:11434')+'/api/chat';
    const r = await fetch(url, {
      method:'POST', signal: AbortSignal.timeout(120000),
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ model: process.env.OLLAMA_MODEL||'llama3', messages, stream:false, options:{temperature:0.3,num_predict:4000} })
    });
    if (!r.ok) throw new Error('Ollama error '+r.status+' — run: ollama serve');
    const d = await r.json();
    return d.message?.content || d.response || '';
  }

  throw new Error('Unknown provider: '+p);
}

// POST /api/agent
router.post('/', async (req, res) => {
  const { question, messages = [] } = req.body;
  if (!question || question.trim().length < 2)
    return res.status(400).json({ error: 'Provide a question.' });

  if (!isConfigured()) {
    return res.json({ reply: fallback(question), engine: 'fallback' });
  }

  try {
    const history = (messages || []).slice(-10);
    const fullMessages = [
      { role:'system', content: SOC_SYSTEM },
      ...history.filter(m => m.role !== 'system'),
      { role:'user', content: question.trim() }
    ];

    const reply = await callAI(fullMessages);
    const info  = getProvider();
    res.json({ reply, engine: info });
  } catch (err) {
    console.error('[Agent]', err.message);
    res.json({ reply: '⚠️ AI error: ' + err.message + '\n\n' + fallback(question), engine: 'error' });
  }
});

function fallback(q) {
  const ql = q.toLowerCase();
  if (ql.includes('apt29')) return '**APT29/Cozy Bear** — Russian SVR. Uses supply chain attacks, OAuth phishing, DCSync. Hunt: EventCode=4662 with replication rights from non-DCs.';
  if (ql.includes('kerberoast')) return '**Kerberoasting**: Look for EventCode=4769, EncryptionType=0x17 (RC4) from non-service accounts. Splunk: `index=* EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by src_user, Service_Name`';
  if (ql.includes('brute') || ql.includes('4625')) return '**Brute Force**: EventCode=4625 > 10 in 60s from same IP. `index=* EventCode=4625 | bucket _time span=60s | stats count by src_ip, _time | where count>10`';
  return 'Configure your AI provider in **.env** to get full responses.\n\n**Quick options:**\n- **Groq (free):** console.groq.com → set `AI_PROVIDER=groq` + `GROQ_API_KEY=`\n- **Ollama (free local):** ollama.com → `ollama pull llama3` → `AI_PROVIDER=ollama`\n- **Gemini (free tier):** aistudio.google.com → `AI_PROVIDER=gemini` + `GEMINI_API_KEY=`';
}

module.exports = router;
