const pool = require('../config/db');

async function runRiskEngine() {
    try {
        console.log('[RISK] 📊 Calculating risk scores...');
        
        // Check if cves table exists
        const tableCheck = await pool.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'cves'
            );
        `);
        
        if (!tableCheck.rows[0].exists) {
            console.log('[RISK] ⚠️ cves table does not exist yet, skipping risk calculation');
            return;
        }
        
        // Update CVEs with risk scores based on multiple factors
        await pool.query(`
            UPDATE cves 
            SET risk_score = (
                COALESCE(cvss_score, 0) * 10 +
                CASE 
                    WHEN EXISTS (SELECT 1 FROM kev_catalog WHERE cve_id = cves.cve_id) THEN 30
                    WHEN EXISTS (SELECT 1 FROM exploit_intel WHERE cve_id = cves.cve_id) THEN 25
                    ELSE 0
                END +
                CASE 
                    WHEN severity = 'CRITICAL' THEN 40
                    WHEN severity = 'HIGH' THEN 30
                    WHEN severity = 'MEDIUM' THEN 20
                    ELSE 10
                END
            ),
            risk_level = CASE
                WHEN risk_score >= 80 THEN 'CRITICAL'
                WHEN risk_score >= 60 THEN 'HIGH'
                WHEN risk_score >= 40 THEN 'MEDIUM'
                ELSE 'LOW'
            END
            WHERE risk_score IS DISTINCT FROM (
                COALESCE(cvss_score, 0) * 10 +
                CASE 
                    WHEN EXISTS (SELECT 1 FROM kev_catalog WHERE cve_id = cves.cve_id) THEN 30
                    WHEN EXISTS (SELECT 1 FROM exploit_intel WHERE cve_id = cves.cve_id) THEN 25
                    ELSE 0
                END +
                CASE 
                    WHEN severity = 'CRITICAL' THEN 40
                    WHEN severity = 'HIGH' THEN 30
                    WHEN severity = 'MEDIUM' THEN 20
                    ELSE 10
                END
            )
        `);
        
        console.log('[RISK] ✅ Risk calculation complete');
        
    } catch (err) {
        console.error('[RISK] Error:', err.message);
    }
}

module.exports = runRiskEngine;