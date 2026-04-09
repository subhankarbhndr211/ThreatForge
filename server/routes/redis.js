const express = require('express');
const router = express.Router();
const redis = require('redis');

let redisClient = null;
let redisConnected = false;

// Initialize Redis connection
(async () => {
    try {
        const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
        redisClient = redis.createClient({ url: redisUrl });
        
        redisClient.on('error', (err) => {
            console.log('[REDIS] Connection error:', err.message);
            redisConnected = false;
        });
        
        redisClient.on('connect', () => {
            console.log('[REDIS] Connected successfully');
            redisConnected = true;
        });
        
        await redisClient.connect();
    } catch (err) {
        console.log('[REDIS] Failed to connect:', err.message);
        redisConnected = false;
    }
})();

// Redis status endpoint
router.get('/status', async (req, res) => {
    try {
        if (!redisClient || !redisConnected) {
            return res.json({
                connected: false,
                message: 'Redis not connected'
            });
        }
        
        // Get Redis info
        const info = await redisClient.info();
        const stats = {
            keys: await redisClient.dbsize(),
            memory: 'unknown',
            hitRate: 'unknown'
        };
        
        // Parse memory info
        const memMatch = info.match(/used_memory_human:(.+)/);
        if (memMatch) stats.memory = memMatch[1].trim();
        
        // Parse hit rate
        const hitsMatch = info.match(/keyspace_hits:(\d+)/);
        const missesMatch = info.match(/keyspace_misses:(\d+)/);
        if (hitsMatch && missesMatch) {
            const hits = parseInt(hitsMatch[1]);
            const misses = parseInt(missesMatch[1]);
            const total = hits + misses;
            stats.hitRate = total > 0 ? Math.round((hits / total) * 100) + '%' : '0%';
        }
        
        res.json({
            connected: true,
            stats
        });
    } catch (error) {
        res.json({
            connected: false,
            error: error.message
        });
    }
});

// Cache endpoints
router.post('/clear', async (req, res) => {
    try {
        if (!redisClient || !redisConnected) {
            return res.status(503).json({ error: 'Redis not connected' });
        }
        
        await redisClient.flushAll();
        res.json({ success: true, message: 'All cache cleared' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

router.post('/clear', async (req, res) => {
    try {
        const { pattern } = req.query;
        if (!pattern) {
            return res.status(400).json({ error: 'Pattern required' });
        }
        
        if (!redisClient || !redisConnected) {
            return res.status(503).json({ error: 'Redis not connected' });
        }
        
        const keys = await redisClient.keys(pattern);
        if (keys.length > 0) {
            await redisClient.del(keys);
        }
        
        res.json({ success: true, message: `Cleared ${keys.length} keys matching ${pattern}` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;