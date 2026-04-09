const axios = require('axios');
const pool = require('../config/db'); // Use the same pool as everything else

async function fetchLatestCVEs() {
  try {
    console.log('Fetching CVEs from NVD...');
    
    // Make sure pool is working
    if (!pool) {
      console.error('Database pool not initialized');
      return;
    }
    
    const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
      params: { resultsPerPage: 50 }
    });
    
    const vulnerabilities = response.data.vulnerabilities || [];
    
    for (const item of vulnerabilities) {
      const cve = item.cve;
      const cveId = cve.id;
      const description = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
      const publishedDate = cve.published;
      const lastModified = cve.lastModified;
      
      // Get CVSS score
      let cvssScore = 0;
      let severity = 'UNKNOWN';
      
      if (cve.metrics?.cvssMetricV31?.[0]) {
        cvssScore = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
        severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity;
      } else if (cve.metrics?.cvssMetricV30?.[0]) {
        cvssScore = cve.metrics.cvssMetricV30[0].cvssData.baseScore;
        severity = cve.metrics.cvssMetricV30[0].cvssData.baseSeverity;
      } else if (cve.metrics?.cvssMetricV2?.[0]) {
        cvssScore = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
        severity = cve.metrics.cvssMetricV2[0].baseSeverity || 'UNKNOWN';
      }
      
      // Insert into database
      try {
        await pool.query(`
          INSERT INTO cves (
            cve_id, description, cvss_score, severity, 
            published_date, last_modified, exploit_available,
            risk_score, risk_level
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
          ON CONFLICT (cve_id) DO UPDATE SET
            description = EXCLUDED.description,
            cvss_score = EXCLUDED.cvss_score,
            severity = EXCLUDED.severity,
            last_modified = EXCLUDED.last_modified
        `, [
          cveId, description, cvssScore, severity,
          publishedDate, lastModified, false,
          0, 'LOW'
        ]);
      } catch (dbErr) {
        console.error(`Error inserting ${cveId}:`, dbErr.message);
      }
    }
    
    console.log(`CVE ingestion complete. Processed ${vulnerabilities.length} CVEs`);
    
  } catch (error) {
    console.error('CVE ingestion error:', error.message);
  }
}

module.exports = { fetchLatestCVEs };