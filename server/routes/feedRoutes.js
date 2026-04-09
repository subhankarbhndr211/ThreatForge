'use strict';
const express = require('express');
const router = express.Router();
const pool = require('../config/db');

// Get unified threat feed
router.get('/', async (req, res) => {
    const { type, severity, limit = 50 } = req.query;
    
    try {
        let query = `SELECT * FROM threat_feed WHERE 1=1`;
        const params = [];
        
        if (type) {
            params.push(type);
            query += ` AND feed_type = $${params.length}`;
        }
        
        if (severity) {
            params.push(severity);
            query += ` AND severity = $${params.length}`;
        }
        
        query += ` ORDER BY created_at DESC LIMIT $${params.length + 1}`;
        params.push(limit);
        
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get feed by type
router.get('/type/:type', async (req, res) => {
    const { type } = req.params;
    const { limit = 50 } = req.query;
    
    try {
        const result = await pool.query(
            `SELECT * FROM threat_feed WHERE feed_type = $1 ORDER BY created_at DESC LIMIT $2`,
            [type, limit]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Get feed stats
router.get('/stats', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT feed_type, severity, COUNT(*) as count, MAX(created_at) as latest
            FROM threat_feed WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY feed_type, severity ORDER BY feed_type, severity
        `);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;