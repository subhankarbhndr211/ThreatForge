'use strict';

const express = require('express');
const router  = express.Router();
const { generateWithAI, isConfigured, getProviderInfo, PLATFORM_INFO } = require('../aiEngine');
const { generateQueries } = require('../queryEngine');

// ALL tools that appear in the sidebar â€” must match index.html exactly
const VALID_TOOLS = [
  // SIEM
  'splunk','elastic','sentinel','qradar','chronicle','arcsight','logrhythm','sumo',
  // EDR
  'crowdstrike','defender','carbonblack','sentinelone','cortex','elastic_edr','crowdstrike_edr',
  // Cloud
  'aws','azure','gcp','cloudflare',
  // Web servers
  'iis','apache','nginx',
  // Containers
  'docker','kubernetes',
  // Databases
  'sqlserver','mysql','postgresql',
  // Identity / Other
  'sysmon','exchange','iam','proxy',
  // Network
  'firewall','network','zeek','suricata',
  // Cross-platform
  'correlation'
];

// POST /api/queries/generate
router.post('/generate', async (req, res) => {
  const { context, tools, severity = 'MED' } = req.body;

  if (!context || typeof context !== 'string' || context.trim().length < 5)
    return res.status(400).json({ error: 'Provide at least 5 characters of threat context.' });
  if (context.trim().length > 3000)
    return res.status(400).json({ error: 'Context too long. Max 3000 characters.' });
  if (!tools || !Array.isArray(tools) || tools.length === 0)
    return res.status(400).json({ error: 'Provide at least one tool.' });

  // Filter out invalid tools instead of rejecting â€” be permissive
  const validSelected = tools.filter(t => VALID_TOOLS.includes(t));
  const unknownTools  = tools.filter(t => !VALID_TOOLS.includes(t));
  if (validSelected.length === 0)
    return res.status(400).json({ error: 'No recognized tools selected. Choose from the sidebar.' });

  if (!['LOW','MED','HIGH','CRIT'].includes(severity))
    return res.status(400).json({ error: 'severity must be: LOW, MED, HIGH, or CRIT' });

  try {
    let queries, engine;
    const warn = unknownTools.length > 0 ? 'Unrecognized tools skipped: ' + unknownTools.join(', ') : null;

    if (isConfigured()) {
      const info = getProviderInfo();
      console.log('[Query] AI provider:', info.name, '| model:', info.model, '| tools:', validSelected.join(','));
      try {
        queries = await generateWithAI(context.trim(), validSelected, severity);
        engine  = info.name + ' (' + info.model + ')';
      } catch (aiErr) {
        console.warn('[Query] AI failed, falling back to templates:', aiErr.message);
        queries = generateQueries(context.trim(), validSelected, severity);
        engine  = 'template-fallback';
        return res.json({
          requestId:    Date.now().toString(36) + Math.random().toString(36).slice(2),
          generatedAt:  new Date().toISOString(),
          severity, engine, aiEnabled: false,
          warning: 'AI error (' + info.name + '): ' + aiErr.message + ' â€” using templates',
          totalQueries: queries.length, queries
        });
      }
    } else {
      console.log('[Query] Template mode');
      queries = generateQueries(context.trim(), validSelected, severity);
      engine  = 'template';
    }

    return res.json({
      requestId:    Date.now().toString(36) + Math.random().toString(36).slice(2),
      generatedAt:  new Date().toISOString(),
      severity, engine,
      aiEnabled:    isConfigured(),
      totalQueries: queries.length,
      warning:      warn,
      queries
    });

  } catch (err) {
    console.error('[Query] Fatal error:', err.message);
    // Last-resort fallback
    try {
      const queries = generateQueries(context.trim(), validSelected, severity);
      return res.json({
        requestId:    Date.now().toString(36) + Math.random().toString(36).slice(2),
        generatedAt:  new Date().toISOString(),
        severity, engine: 'template-fallback', aiEnabled: false,
        warning: 'Error: ' + err.message,
        totalQueries: queries.length, queries
      });
    } catch (e2) {
      return res.status(500).json({ error: 'Generation failed: ' + err.message });
    }
  }
});

// GET /api/queries/tools
router.get('/tools', (req, res) => {
  res.json({ total: VALID_TOOLS.length, tools: PLATFORM_INFO, aiEnabled: isConfigured() });
});

// GET /api/queries/status
router.get('/status', (req, res) => {
  const info = getProviderInfo();
  res.json({
    aiEnabled: isConfigured(),
    provider:  info.name,
    model:     info.model,
    engine:    isConfigured() ? info.name : 'template',
    message:   isConfigured()
      ? 'AI active â€” ' + info.name + ' (' + info.model + ')'
      : 'Template mode â€” set AI_PROVIDER and API key in .env to enable AI'
  });
});

module.exports = router;


