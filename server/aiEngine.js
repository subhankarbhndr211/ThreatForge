'use strict';

/**
 * ThreatForge — Multi-Provider AI Engine
 * All providers use native Node.js fetch (Node 18+) — zero extra packages needed.
 */

let aiSettings = {
  provider: 'groq',
  apiKey: '',
  model: '',
  customUrl: ''
};

function setAISettings(settings) {
  if (settings) {
    aiSettings = { ...aiSettings, ...settings };
  }
}

function getEffectiveKey(provider) {
  if (aiSettings.apiKey && aiSettings.apiKey.length > 0) {
    return aiSettings.apiKey;
  }
  const keyMap = {
    anthropic: 'ANTHROPIC_API_KEY',
    openai: 'OPENAI_API_KEY',
    gemini: 'GEMINI_API_KEY',
    groq: 'GROQ_API_KEY',
    mistral: 'MISTRAL_API_KEY',
    deepseek: 'DEEPSEEK_API_KEY',
    cohere: 'COHERE_API_KEY',
    fireworks: 'FIREWORKS_API_KEY',
    together: 'TOGETHER_API_KEY',
    cloudflare: 'CLOUDFLARE_API_KEY',
    cerebras: 'CEREBRAS_API_KEY',
    azure: 'AZURE_OPENAI_KEY'
  };
  return process.env[keyMap[provider] || ''] || '';
}

function getEffectiveModel(provider) {
  if (aiSettings.model && aiSettings.model.length > 0) {
    return aiSettings.model;
  }
  const modelMap = {
    anthropic: 'ANTHROPIC_MODEL',
    openai: 'OPENAI_MODEL',
    gemini: 'GEMINI_MODEL',
    groq: 'GROQ_MODEL',
    mistral: 'MISTRAL_MODEL',
    ollama: 'OLLAMA_MODEL',
    deepseek: 'DEEPSEEK_MODEL',
    cohere: 'COHERE_MODEL',
    fireworks: 'FIREWORKS_MODEL',
    together: 'TOGETHER_MODEL',
    cloudflare: 'CLOUDFLARE_MODEL',
    cerebras: 'CEREBRAS_MODEL'
  };
  return process.env[modelMap[provider] || ''] || '';
}

function getEffectiveUrl(provider) {
  if (aiSettings.customUrl && aiSettings.customUrl.length > 0) {
    return aiSettings.customUrl;
  }
  return null;
}

const PLATFORM_INFO = {
  splunk:          { name: 'Splunk',               language: 'SPL',       type: 'SIEM', icon: '🔍' },
  elastic:         { name: 'Elastic SIEM',         language: 'KQL',       type: 'SIEM', icon: '⚡' },
  sentinel:        { name: 'Azure Sentinel',       language: 'KQL',       type: 'SIEM', icon: '☁️' },
  qradar:          { name: 'IBM QRadar',           language: 'AQL',       type: 'SIEM', icon: '🔷' },
  chronicle:       { name: 'Google Chronicle',     language: 'YARA-L',    type: 'SIEM', icon: '🌐' },
  arcsight:        { name: 'ArcSight',             language: 'CEL',       type: 'SIEM', icon: '🔺' },
  logrhythm:       { name: 'LogRhythm',            language: 'LQL',       type: 'SIEM', icon: '📊' },
  sumo:            { name: 'Sumo Logic',           language: 'SuQL',      type: 'SIEM', icon: '🎯' },
  crowdstrike:     { name: 'CrowdStrike',          language: 'FQL',       type: 'EDR',  icon: '🦅' },
  defender:        { name: 'MS Defender',          language: 'KQL',       type: 'EDR',  icon: '🛡️' },
  carbonblack:     { name: 'Carbon Black',         language: 'CBC',       type: 'EDR',  icon: '⬛' },
  sentinelone:     { name: 'SentinelOne',          language: 'DQL',       type: 'EDR',  icon: '💜' },
  cortex:          { name: 'Cortex XDR',           language: 'XQL',       type: 'EDR',  icon: '🔶' },
  elastic_edr:     { name: 'Elastic EDR',          language: 'EQL',       type: 'EDR',  icon: '⚡' },
  crowdstrike_edr: { name: 'CrowdStrike EDR',      language: 'EQL',       type: 'EDR',  icon: '🦅' },
  aws:             { name: 'AWS CloudTrail',        language: 'SQL',       type: 'Cloud', icon: '☁️' },
  azure:           { name: 'Azure Activity',       language: 'KQL',       type: 'Cloud', icon: '🌤' },
  gcp:             { name: 'GCP Audit',            language: 'SQL',       type: 'Cloud', icon: '🌀' },
  cloudflare:      { name: 'Cloudflare',           language: 'Logpull',   type: 'Cloud', icon: '🌐' },
  iis:             { name: 'IIS Logs',             language: 'W3C/Regex', type: 'Web',  icon: '🌍' },
  apache:          { name: 'Apache Access',        language: 'Regex',     type: 'Web',  icon: '🦊' },
  nginx:           { name: 'Nginx Access',         language: 'Regex',     type: 'Web',  icon: '🚀' },
  docker:          { name: 'Docker',               language: 'JSON/Log',  type: 'Container', icon: '🐳' },
  kubernetes:      { name: 'Kubernetes',           language: 'K8s',       type: 'Container', icon: '☸' },
  sqlserver:       { name: 'SQL Server',           language: 'SQL',       type: 'DB',   icon: '📊' },
  mysql:           { name: 'MySQL',                language: 'SQL',       type: 'DB',   icon: '🐬' },
  postgresql:      { name: 'PostgreSQL',           language: 'SQL/Log',   type: 'DB',   icon: '🐘' },
  sysmon:          { name: 'Sysmon',               language: 'EventLog',  type: 'Endpoint', icon: '🔧' },
  exchange:        { name: 'Exchange',             language: 'MessageLog',type: 'Email',icon: '📧' },
  iam:             { name: 'IAM Logs',             language: 'Auth',      type: 'Identity', icon: '🔐' },
  proxy:           { name: 'Proxy Logs',           language: 'Squid',     type: 'Network', icon: '🌐' },
  firewall:        { name: 'Firewall',             language: 'NetFlow',   type: 'Network', icon: '🔥' },
  network:         { name: 'Network Devices',      language: 'Syslog',    type: 'Network', icon: '🌐' },
  zeek:            { name: 'Zeek/Bro',             language: 'Zeek',      type: 'Network', icon: '🔍' },
  suricata:        { name: 'Suricata',             language: 'EVE-JSON',  type: 'IDS',  icon: '⚡' },
  correlation:     { name: 'Correlation Rules',    language: 'Universal', type: 'CORR', icon: '🔗' },
};

function getProvider() {
  return (aiSettings.provider && aiSettings.provider.length > 0 ? aiSettings.provider : process.env.AI_PROVIDER || 'groq').toLowerCase().trim();
}

function isConfigured() {
  const p = getProvider();
  if (!p || p === 'none' || p === '') return false;
  if (p === 'ollama') {
    return true;
  }
  const key = getEffectiveKey(p);
  return key && key.length > 10 && !key.startsWith('your-') && !key.includes('placeholder');
}

function getProviderInfo() {
  const p = getProvider();
  const model = getEffectiveModel(p);
  return { name: p || 'none', model: model || 'unknown' };
}

function buildPrompt(context, tools, severity) {
  const platformList = tools.map(t => {
    const p = PLATFORM_INFO[t];
    return p ? `${p.name} (${p.language})` : t;
  }).join(', ');

  return `You are an expert SOC analyst. Generate precise detection queries for the following threat scenario.

THREAT CONTEXT: ${context}
SEVERITY: ${severity}
TARGET PLATFORMS: ${platformList}

RULES:
- Generate ONE query per platform
- Each query must be production-ready and accurate for that platform's syntax
- Include MITRE ATT&CK technique IDs where applicable
- Add tuning notes to reduce false positives
- Be specific to the threat described

Respond with a JSON array (no markdown, just raw JSON):
[
  {
    "platform": "Platform Name",
    "language": "QUERY_LANGUAGE",
    "type": "Detection Type",
    "icon": "emoji",
    "description": "What this query detects",
    "query": "the actual query here",
    "mitre": ["T1234", "T1234.001"],
    "notes": ["tuning note 1", "tuning note 2"]
  }
]`;
}

function parseResponse(text, tools) {
  try {
    const cleaned = text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();
    const jsonStart = cleaned.indexOf('[');
    const jsonEnd   = cleaned.lastIndexOf(']');
    if (jsonStart === -1 || jsonEnd === -1) throw new Error('No JSON array found');
    const parsed = JSON.parse(cleaned.slice(jsonStart, jsonEnd + 1));
    if (!Array.isArray(parsed) || parsed.length === 0) throw new Error('Empty array');
    return parsed.map(q => ({
      platform:    String(q.platform || 'Unknown'),
      language:    String(q.language || 'Query'),
      type:        String(q.type     || 'Detection'),
      icon:        String(q.icon     || '🔍'),
      description: String(q.description || ''),
      query:       String(q.query    || '// No query generated'),
      mitre:       Array.isArray(q.mitre) ? q.mitre.map(String) : [],
      notes:       Array.isArray(q.notes) ? q.notes.map(String) : [],
    }));
  } catch (e) {
    console.warn('[AI] Failed to parse response:', e.message);
    return null;
  }
}

async function callProvider(prompt) {
  const p = getProvider();
  const apiKey = getEffectiveKey(p);
  const model = getEffectiveModel(p);
  const customUrl = getEffectiveUrl(p);
  const msgs = [{ role: 'user', content: prompt }];

  if (p === 'groq') {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'llama-3.3-70b-versatile', messages: msgs, max_tokens: 4096, temperature: 0.2 })
    });
    if (!r.ok) throw new Error('Groq HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'anthropic') {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'claude-3-5-sonnet-20241022', max_tokens: 4096, messages: msgs })
    });
    if (!r.ok) throw new Error('Anthropic HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).content[0].text;
  }

  if (p === 'openai') {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'gpt-4o', messages: msgs, max_tokens: 4096, temperature: 0.2 })
    });
    if (!r.ok) throw new Error('OpenAI HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'gemini') {
    const m = model || 'gemini-1.5-flash';
    const url = 'https://generativelanguage.googleapis.com/v1beta/models/' + m + ':generateContent?key=' + apiKey;
    const r = await fetch(url, {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ role: 'user', parts: [{ text: prompt }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 4096 } })
    });
    if (!r.ok) throw new Error('Gemini HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).candidates[0].content.parts[0].text;
  }

  if (p === 'mistral') {
    const r = await fetch('https://api.mistral.ai/v1/chat/completions', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'mistral-large-latest', messages: msgs, max_tokens: 4096, temperature: 0.2 })
    });
    if (!r.ok) throw new Error('Mistral HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'deepseek') {
    const r = await fetch('https://api.deepseek.com/v1/chat/completions', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'deepseek-chat', messages: msgs, max_tokens: 4096, temperature: 0.2 })
    });
    if (!r.ok) throw new Error('DeepSeek HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'cohere') {
    const r = await fetch('https://api.cohere.ai/v1/chat', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'command-r-plus', messages: msgs, max_tokens: 4096 })
    });
    if (!r.ok) throw new Error('Cohere HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).text;
  }

  if (p === 'fireworks') {
    const r = await fetch('https://api.fireworks.ai/v1/chat/completions', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'accounts/fireworks/models/llama-v3-70b-instruct', messages: msgs, max_tokens: 4096, temperature: 0.2 })
    });
    if (!r.ok) throw new Error('Fireworks HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'together') {
    const r = await fetch('https://api.together.xyz/v1/chat/completions', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'meta-llama/Llama-3.3-70B-Instruct-Turbo', messages: msgs, max_tokens: 4096, temperature: 0.2 })
    });
    if (!r.ok) throw new Error('Together AI HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'cloudflare') {
    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID || '';
    const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/run/@cf/meta/llama-3.1-70b-instruct`, {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: msgs })
    });
    if (!r.ok) throw new Error('Cloudflare AI HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    const data = await r.json();
    return data.result?.response || '';
  }

  if (p === 'cerebras') {
    const r = await fetch('https://api.cerebras.ai/v1/chat/completions', {
      method: 'POST', signal: AbortSignal.timeout(60000),
      headers: { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'llama-3.3-70b', messages: msgs, max_tokens: 4096, temperature: 0.2 })
    });
    if (!r.ok) throw new Error('Cerebras HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
    return (await r.json()).choices[0].message.content;
  }

  if (p === 'ollama') {
    const url = (customUrl || process.env.OLLAMA_URL || 'http://localhost:11434') + '/api/chat';
    const r = await fetch(url, {
      method: 'POST', signal: AbortSignal.timeout(120000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model || 'llama3', messages: msgs, stream: false })
    });
    if (!r.ok) throw new Error('Ollama HTTP ' + r.status + ' — is Ollama running? Run: ollama serve');
    const d = await r.json();
    return d.message?.content || d.response || '';
  }

  throw new Error('Unknown AI provider: ' + p);
}

async function generateWithAI(context, tools, severity) {
  const prompt = buildPrompt(context, tools, severity);
  const raw    = await callProvider(prompt);
  const parsed = parseResponse(raw, tools);

  if (!parsed) {
    // If AI response couldn't be parsed, throw so caller falls back to templates
    throw new Error('AI response could not be parsed as JSON');
  }
  return parsed;
}

module.exports = { generateWithAI, isConfigured, getProviderInfo, setAISettings, PLATFORM_INFO };
