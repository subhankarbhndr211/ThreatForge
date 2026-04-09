'use strict';
const express = require('express');
const router = express.Router();
const pool = require('../config/db');  // FIXED: was '../config/db'

// Search threats by product name
router.get('/', async (req, res) => {
    const { q } = req.query;
    
    if (!q || q.length < 3) {
        return res.status(400).json({ error: 'Search query must be at least 3 characters' });
    }
    
    try {
        // Search in CVEs
        const cveResults = await pool.query(`
            SELECT 
                cve_id as id,
                description,
                'cve' as type,
                risk_level as severity,
                cvss_score as score,
                published_date as date,
                description as summary
            FROM cves
            WHERE description ILIKE $1
            ORDER BY 
                CASE 
                    WHEN risk_level = 'CRITICAL' THEN 1
                    WHEN risk_level = 'HIGH' THEN 2
                    WHEN risk_level = 'MEDIUM' THEN 3
                    ELSE 4
                END,
                published_date DESC
            LIMIT 20
        `, [`%${q}%`]);
        
        // Search in KEV catalog
        const kevResults = await pool.query(`
            SELECT 
                cve_id as id,
                product || ' - ' || vendor_project as title,
                short_description as description,
                'kev' as type,
                'CRITICAL' as severity,
                date_added as date
            FROM kev_catalog
            WHERE product ILIKE $1 OR vendor_project ILIKE $1
            ORDER BY date_added DESC
            LIMIT 20
        `, [`%${q}%`]);
        
        // Search in threat actors
        const actorResults = await pool.query(`
            SELECT 
                id,
                actor_name as name,
                description,
                'actor' as type,
                origin_country,
                created_at as date
            FROM threat_actors
            WHERE actor_name ILIKE $1 OR description ILIKE $1
            ORDER BY created_at DESC
            LIMIT 20
        `, [`%${q}%`]);
        
        // Search in campaigns
        const campaignResults = await pool.query(`
            SELECT 
                id,
                campaign_name as name,
                description,
                'campaign' as type,
                target_sector,
                region,
                start_date as date
            FROM campaigns
            WHERE campaign_name ILIKE $1 OR description ILIKE $1 OR target_sector ILIKE $1
            ORDER BY start_date DESC
            LIMIT 20
        `, [`%${q}%`]);
        
        // Search in threat feed
        const feedResults = await pool.query(`
            SELECT 
                id,
                title,
                description,
                feed_type as type,
                severity,
                created_at as date,
                related_products,
                related_cves,
                related_actors
            FROM threat_feed
            WHERE title ILIKE $1 OR description ILIKE $1 OR $1 = ANY(tags)
            ORDER BY 
                CASE 
                    WHEN severity = 'CRITICAL' THEN 1
                    WHEN severity = 'HIGH' THEN 2
                    ELSE 3
                END,
                created_at DESC
            LIMIT 20
        `, [`%${q}%`]);
        
        res.json({
            query: q,
            total: cveResults.rows.length + kevResults.rows.length + 
                   actorResults.rows.length + campaignResults.rows.length + 
                   feedResults.rows.length,
            results: {
                cves: cveResults.rows,
                kev: kevResults.rows,
                actors: actorResults.rows,
                campaigns: campaignResults.rows,
                threats: feedResults.rows
            }
        });
        
    } catch (err) {
        console.error('Product search error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get threat summary for a specific product
router.get('/:product', async (req, res) => {
    const { product } = req.params;
    
    try {
        // Get all threats related to this product
        const [cves, kev, exploits, feed] = await Promise.all([
            pool.query(`
                SELECT cve_id, description, risk_level, cvss_score
                FROM cves
                WHERE description ILIKE $1
                ORDER BY risk_score DESC NULLS LAST
                LIMIT 10
            `, [`%${product}%`]),
            
            pool.query(`
                SELECT cve_id, product, vendor_project, short_description
                FROM kev_catalog
                WHERE product ILIKE $1 OR vendor_project ILIKE $1
                ORDER BY date_added DESC
                LIMIT 10
            `, [`%${product}%`]),
            
            pool.query(`
                SELECT * FROM exploit_intel
                WHERE cve_id IN (
                    SELECT cve_id FROM cves WHERE description ILIKE $1
                )
                ORDER BY stars DESC
                LIMIT 10
            `, [`%${product}%`]),
            
            pool.query(`
                SELECT * FROM threat_feed
                WHERE $1 = ANY(related_products)
                ORDER BY created_at DESC
                LIMIT 10
            `, [product])
        ]);
        
        // Calculate risk score for this product
        const riskScore = (
            (cves.rows.filter(c => c.risk_level === 'CRITICAL').length * 10) +
            (cves.rows.filter(c => c.risk_level === 'HIGH').length * 5) +
            (kev.rows.length * 8) +
            (exploits.rows.length * 6)
        );
        
        res.json({
            product,
            riskScore: Math.min(riskScore, 100),
            summary: {
                criticalCVEs: cves.rows.filter(c => c.risk_level === 'CRITICAL').length,
                highCVEs: cves.rows.filter(c => c.risk_level === 'HIGH').length,
                kevCount: kev.rows.length,
                exploitCount: exploits.rows.length,
                totalThreats: cves.rows.length + kev.rows.length + exploits.rows.length
            },
            data: {
                cves: cves.rows,
                kev: kev.rows,
                exploits: exploits.rows,
                feed: feed.rows
            }
        });
        
    } catch (err) {
        console.error('Product detail error:', err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
