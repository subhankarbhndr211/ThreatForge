const express = require('express');
const router = express.Router();
const axios = require('axios');

// Dashboard statistics endpoint
router.get('/stats', async (req, res) => {
  try {
    // Fetch real data from various sources
    const [cveResponse, feedResponse, actorsCount] = await Promise.allSettled([
      // Get critical CVEs count
      fetch('http://localhost:3001/api/cve?severity=CRIT').then(r => r.json()),
      // Get live feed items
      fetch('http://localhost:3001/api/feed').then(r => r.json()),
      // Count actors (from your actors data)
      Promise.resolve(15) // This should come from your database/actors file
    ]);

    const stats = {
      criticalAlerts: 0,
      trackedActors: 15,
      mitreTechniques: 50,
      queryTemplates: 40,
      recentThreats: []
    };

    // Update from CVE data if available
    if (cveResponse.status === 'fulfilled' && cveResponse.value.items) {
      stats.criticalAlerts = cveResponse.value.items.length;
    }

    // Update from feed data if available
    if (feedResponse.status === 'fulfilled' && feedResponse.value.items) {
      stats.recentThreats = feedResponse.value.items
        .filter(item => item.severity === 'CRIT' || item.severity === 'HIGH')
        .slice(0, 5);
    }

    res.json(stats);

  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// Recent threats endpoint
router.get('/threats', async (req, res) => {
  try {
    const feedResponse = await fetch('http://localhost:3001/api/feed')
      .then(r => r.json())
      .catch(() => ({ items: [] }));

    const threats = (feedResponse.items || [])
      .filter(item => item.severity === 'CRIT' || item.severity === 'HIGH')
      .slice(0, 5)
      .map(item => ({
        id: item.id,
        title: item.title,
        severity: item.severity,
        source: item.source,
        family: item.family,
        date: item.firstSeen
      }));

    res.json(threats);

  } catch (error) {
    console.error('Dashboard threats error:', error);
    res.status(500).json({ error: 'Failed to fetch threats' });
  }
});

module.exports = router;