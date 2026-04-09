const express = require('express');
const router = express.Router();
const pool = require('../config/db'); 

async function runExploitMonitor() {
    try {
        console.log('[EXP] ðŸ” Checking GitHub for weaponized CVEs...');
        
        // Get recent CVEs to check
        const recentCVEs = await pool.query(`
            SELECT cve_id FROM cves 
            ORDER BY published_date DESC 
            LIMIT 20
        `);
        
        const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
        const headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ThreatForge-SOC'
        };
        
        if (GITHUB_TOKEN) {
            headers['Authorization'] = `Bearer ${GITHUB_TOKEN}`;
        }
        
        for (const cve of recentCVEs.rows) {
            try {
                const cveId = cve.cve_id;
                
                // Search GitHub for exploits
                const url = `https://api.github.com/search/repositories?q=${cveId}+exploit+PoC&sort=stars`;
                
                const response = await fetch(url, { headers });
                
                if (!response.ok) continue;
                
                const data = await response.json();
                const items = data.items || [];
                
                for (const repo of items.slice(0, 3)) {
                    // Check if already exists
                    const exists = await pool.query(
                        'SELECT 1 FROM exploit_intel WHERE exploit_url = $1',
                        [repo.html_url]
                    );
                    
                    if (exists.rows.length > 0) continue;
                    
                    // Insert new exploit
                    await pool.query(`
                        INSERT INTO exploit_intel 
                        (cve_id, source, exploit_url, repo_name, stars, description, detected_at)
                        VALUES ($1, $2, $3, $4, $5, $6, NOW())
                    `, [
                        cveId,
                        'github',
                        repo.html_url,
                        repo.full_name,
                        repo.stargazers_count || 0,
                        repo.description || 'No description'
                    ]);
                    
                    console.log(`[EXP] Found exploit for ${cveId}: ${repo.full_name} (${repo.stargazers_count} â­)`);
                    
                    // Add to threat feed
                    await pool.query(`
                        INSERT INTO threat_feed 
                        (source, title, description, related_cves, feed_type, severity, url)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                    `, [
                        'GitHub Exploit',
                        `PoC Available: ${cveId}`,
                        `Exploit repository: ${repo.full_name} (${repo.stargazers_count} stars)`,
                        [cveId],
                        'exploit',
                        repo.stargazers_count > 50 ? 'CRITICAL' : 'HIGH',
                        repo.html_url
                    ]);
                }
                
                // Rate limit avoidance
                await new Promise(resolve => setTimeout(resolve, 1000));
                
            } catch (err) {
                console.error(`[EXP] Error checking ${cve.cve_id}:`, err.message);
            }
        }
        
        console.log('[EXP] âœ… Exploit scan complete');
        
    } catch (err) {
        console.error('[EXP] Error:', err.message);
    }
}

module.exports = runExploitMonitor;
