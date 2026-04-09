const express = require('express');
const router = express.Router();
const pool = require('../config/db');

// Get newsfeed with filters
router.get('/', async (req, res) => {
    const { 
        source_type, 
        severity, 
        category,
        search,
        limit = 50,
        offset = 0 
    } = req.query;
    
    try {
        let query = `
            SELECT * FROM newsfeed_entries
            WHERE 1=1
        `;
        const params = [];
        let paramIndex = 1;
        
        if (source_type) {
            params.push(source_type);
            query += ` AND source_type = $${paramIndex++}`;
        }
        
        if (severity) {
            const severities = severity.split(',');
            params.push(severities);
            query += ` AND severity = ANY($${paramIndex++})`;
        }
        
        if (category) {
            params.push(category);
            query += ` AND $${paramIndex++} = ANY(categories)`;
        }
        
        if (search) {
            params.push(`%${search}%`);
            query += ` AND (title ILIKE $${paramIndex++} OR content ILIKE $${paramIndex-1})`;
        }
        
        query += ` ORDER BY 
            CASE severity 
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                ELSE 4
            END,
            published_at DESC
            LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
        
        params.push(limit, offset);
        
        const result = await pool.query(query, params);
        
        // Get total count
        const countResult = await pool.query('SELECT COUNT(*) FROM newsfeed_entries');
        
        res.json({
            total: parseInt(countResult.rows[0].count),
            offset: parseInt(offset),
            limit: parseInt(limit),
            items: result.rows
        });
        
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get single entry
router.get('/:id', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM newsfeed_entries WHERE id = $1',
            [req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Entry not found' });
        }
        
        res.json(result.rows[0]);
        
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get entries by CVE
router.get('/cve/:cve_id', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM newsfeed_entries 
             WHERE $1 = ANY(related_cves)
             ORDER BY published_at DESC`,
            [req.params.cve_id]
        );
        
        res.json(result.rows);
        
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get sources
router.get('/sources/list', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM newsfeed_sources WHERE is_active = true ORDER BY source_name'
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Mark as read/saved
router.patch('/:id', async (req, res) => {
    const { is_read, is_saved } = req.body;
    
    try {
        await pool.query(
            'UPDATE newsfeed_entries SET is_read = $1, is_saved = $2 WHERE id = $3',
            [is_read, is_saved, req.params.id]
        );
        
        res.json({ success: true });
        
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;