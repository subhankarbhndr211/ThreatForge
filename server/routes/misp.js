'use strict';
const express = require('express');
const router  = express.Router();

function mispConfigured() {
  return process.env.MISP_URL && process.env.MISP_API_KEY &&
    process.env.MISP_URL !== 'https://your-misp-instance.com';
}

async function mispFetch(path, method = 'GET', body = null) {
  const url  = process.env.MISP_URL.replace(/\/$/, '') + path;
  const opts = {
    method,
    headers: {
      'Authorization': process.env.MISP_API_KEY,
      'Accept':        'application/json',
      'Content-Type':  'application/json'
    },
    signal: AbortSignal.timeout(10000)
  };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error('MISP HTTP ' + r.status);
  return r.json();
}

// GET /api/misp/status
router.get('/status', (req, res) => {
  res.json({ configured: mispConfigured(), url: process.env.MISP_URL || null });
});

// GET /api/misp/events — recent events
router.get('/events', async (req, res) => {
  if (!mispConfigured()) return res.json({ configured: false, events: [], message: 'Add MISP_URL and MISP_API_KEY to .env' });
  try {
    const data = await mispFetch('/events/restSearch', 'POST', {
      returnFormat: 'json', limit: 20, published: true,
      timestamp: Math.floor(Date.now()/1000) - 7*24*3600 // last 7 days
    });
    const events = (data.response || []).map(e => ({
      id:          e.Event?.id,
      uuid:        e.Event?.uuid,
      title:       e.Event?.info,
      date:        e.Event?.date,
      threatLevel: e.Event?.threat_level_id,
      orgName:     e.Event?.Orgc?.name,
      attributeCount: e.Event?.attribute_count,
      tags:        (e.Event?.Tag || []).map(t => t.name)
    }));
    res.json({ configured: true, events });
  } catch (err) {
    res.json({ configured: true, error: err.message, events: [] });
  }
});

// POST /api/misp/search — search IOC
router.post('/search', async (req, res) => {
  if (!mispConfigured()) return res.json({ configured: false, results: [] });
  const { ioc } = req.body;
  if (!ioc) return res.status(400).json({ error: 'Provide IOC value' });
  try {
    const data = await mispFetch('/attributes/restSearch', 'POST', {
      returnFormat: 'json', value: ioc, limit: 20
    });
    const results = (data.response?.Attribute || []).map(a => ({
      type:       a.type,
      value:      a.value,
      category:   a.category,
      eventId:    a.event_id,
      timestamp:  a.timestamp,
      comment:    a.comment,
      toIds:      a.to_ids
    }));
    res.json({ configured: true, ioc, results, found: results.length > 0 });
  } catch (err) {
    res.json({ configured: true, error: err.message, results: [] });
  }
});

// GET /api/misp/feeds — available feeds
router.get('/feeds', async (req, res) => {
  if (!mispConfigured()) return res.json({ configured: false, feeds: [] });
  try {
    const data = await mispFetch('/feeds');
    const feeds = (data || []).map(f => ({
      id: f.Feed?.id, name: f.Feed?.name,
      url: f.Feed?.url, enabled: f.Feed?.enabled,
      provider: f.Feed?.provider
    }));
    res.json({ configured: true, feeds });
  } catch (err) {
    res.json({ configured: true, error: err.message, feeds: [] });
  }
});

module.exports = router;
