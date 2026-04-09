// server/routes/metrics.js
const express = require('express');
const router = express.Router();
const os = require('os');

// Get system metrics
router.get('/', (req, res) => {
  try {
    const metrics = {
      system: {
        uptime: process.uptime(),
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        memory: {
          total: os.totalmem(),
          free: os.freemem(),
          usage: ((1 - os.freemem() / os.totalmem()) * 100).toFixed(2) + '%'
        },
        loadavg: os.loadavg()
      },
      process: {
        pid: process.pid,
        version: process.version,
        memory: process.memoryUsage(),
        cpu: process.cpuUsage()
      },
      timestamp: new Date().toISOString()
    };
    
    res.json({
      success: true,
      data: metrics
    });
  } catch (error) {
    console.error('Error fetching metrics:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get application metrics
router.get('/app', (req, res) => {
  try {
    const metrics = {
      requests: global.requestCount || 0,
      errors: global.errorCount || 0,
      activeConnections: global.activeConnections || 0,
      uptime: process.uptime()
    };
    
    res.json({
      success: true,
      data: metrics
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;