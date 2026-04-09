const pool = require('../config/db');

async function runFeedEngine() {
    try {
        console.log('[FEED] 📊 Generating unified threat feed...');
        
        // Create threat_feed table if it doesn't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS threat_feed (
                id SERIAL PRIMARY KEY,
                source VARCHAR(100),
                title TEXT,
                description TEXT,
                content TEXT,
                related_products TEXT[],
                related_cves TEXT[],
                related_actors TEXT[],
                feed_type VARCHAR(50),
                severity VARCHAR(20),
                confidence_score INT,
                url TEXT,
                tags TEXT[],
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Clear old feed entries (keep last 7 days)
        await pool.query(`
            DELETE FROM threat_feed 
            WHERE created_at < NOW() - INTERVAL '7 days'
        `);
        
        let totalAdded = 0;
        
        // 1. Add high-risk CVEs to feed
        const highRiskCVEs = await pool.query(`
            SELECT cve_id, description, risk_score, risk_level, cvss_score
            FROM cves
            WHERE risk_score >= 50 OR risk_level = 'CRITICAL'
            ORDER BY risk_score DESC
            LIMIT 20
        `);
        
        for (const cve of highRiskCVEs.rows) {
            await pool.query(`
                INSERT INTO threat_feed 
                (source, title, description, related_cves, feed_type, severity, confidence_score)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
            `, [
                'CVE Intelligence',
                `High Risk: ${cve.cve_id}`,
                cve.description || 'No description',
                [cve.cve_id],
                'cve',
                cve.risk_level || 'MEDIUM',
                cve.risk_score || 50
            ]);
            totalAdded++;
        }
        
        // 2. Add KEV entries to feed
        const kevEntries = await pool.query(`
            SELECT cve_id, short_description, vendor_project, product
            FROM kev_catalog
            ORDER BY date_added DESC
            LIMIT 20
        `);
        
        for (const kev of kevEntries.rows) {
            await pool.query(`
                INSERT INTO threat_feed 
                (source, title, description, related_cves, feed_type, severity, related_products)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
            `, [
                'CISA KEV',
                `Known Exploited: ${kev.cve_id}`,
                kev.short_description || 'Actively exploited vulnerability',
                [kev.cve_id],
                'kev',
                'CRITICAL',
                [kev.product, kev.vendor_project].filter(Boolean)
            ]);
            totalAdded++;
        }
        
        // 3. Add exploits to feed
        const exploits = await pool.query(`
            SELECT cve_id, repo_name, stars, description, exploit_url
            FROM exploit_intel
            ORDER BY detected_at DESC
            LIMIT 20
        `);
        
        for (const exp of exploits.rows) {
            await pool.query(`
                INSERT INTO threat_feed 
                (source, title, description, related_cves, feed_type, severity, url)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
            `, [
                'Exploit Monitor',
                `Exploit Available: ${exp.cve_id || 'Unknown'}`,
                exp.description || `GitHub repository: ${exp.repo_name} (${exp.stars} stars)`,
                exp.cve_id ? [exp.cve_id] : [],
                'exploit',
                exp.stars > 50 ? 'CRITICAL' : 'HIGH',
                exp.exploit_url
            ]);
            totalAdded++;
        }
        
        console.log(`[FEED] ✅ Generated ${totalAdded} feed entries`);
        
    } catch (err) {
        console.error('[FEED] Error:', err.message);
    }
}

module.exports = runFeedEngine;