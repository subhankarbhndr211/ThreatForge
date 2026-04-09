const express = require('express');
const router = express.Router();

// Import your data models
const Actor = require('./actors');  // This will be the array of actors
// const CVE = require('./cve');   // Uncomment when you have these files
// const Threat = require('./threat'); // Uncomment when you have these files

router.get('/api/search', async (req, res) => {
  try {
    const query = req.query.q;
    if (!query || query.length < 2) {
      return res.json([]);
    }
    
    const results = [];
    const searchTerm = query.toLowerCase();
    
    // Search actors (works with your array data)
    const allActors = Actor.actors || Actor; // Handle different export patterns
    const actorResults = (Array.isArray(allActors) ? allActors : [])
      .filter(actor => {
        return (
          (actor.name && actor.name.toLowerCase().includes(searchTerm)) ||
          (actor.aliases && actor.aliases.some(alias => 
            alias.toLowerCase().includes(searchTerm)
          )) ||
          (actor.origin && actor.origin.toLowerCase().includes(searchTerm))
        );
      })
      .slice(0, 5); // Limit to 5 results
    
    actorResults.forEach(a => {
      results.push({
        type: 'actor',
        id: a.id,
        title: a.name,
        subtitle: `${a.origin || ''} • ${a.sponsor || ''}`,
        icon: a.icon || '🎭'
      });
    });
    
    // Search CVEs - Uncomment when you have cve.js
    /*
    const CVE = require('./cve');
    const allCVEs = CVE.cves || CVE;
    if (Array.isArray(allCVEs)) {
      const cveResults = allCVEs
        .filter(c => 
          (c.id && c.id.toLowerCase().includes(searchTerm)) ||
          (c.title && c.title.toLowerCase().includes(searchTerm)) ||
          (c.description && c.description.toLowerCase().includes(searchTerm))
        )
        .slice(0, 5);
      
      cveResults.forEach(c => {
        results.push({
          type: 'cve',
          id: c.id,
          title: c.title || c.id,
          subtitle: `${c.source || 'NVD'} • CVSS: ${c.cvss || '?'}`,
          icon: '🛡️'
        });
      });
    }
    */
    
    // Search threats - Uncomment when you have threat.js
    /*
    const Threat = require('./threat');
    const allThreats = Threat.threats || Threat;
    if (Array.isArray(allThreats)) {
      const threatResults = allThreats
        .filter(t => 
          (t.title && t.title.toLowerCase().includes(searchTerm)) ||
          (t.description && t.description.toLowerCase().includes(searchTerm))
        )
        .slice(0, 5);
      
      threatResults.forEach(t => {
        results.push({
          type: 'threat',
          id: t.id,
          title: t.title,
          subtitle: `${t.source || 'Threat Intel'} • Severity: ${t.severity || 'MED'}`,
          icon: '⚠️'
        });
      });
    }
    */
    
    res.json(results);
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed', details: error.message });
  }
});

module.exports = router;