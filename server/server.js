require('dotenv').config();
process.env.TZ = 'Asia/Kolkata';

// Verify timezone is set
console.log('🕐 Server Timezone:', Intl.DateTimeFormat().resolvedOptions().timeZone);
console.log('🕐 Current Time:', new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }));

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const rateLimit = require('express-rate-limit');
const cron = require("node-cron");

// Route imports - SINGLE declaration for each
const logsRoutes = require('./routes/logs');
const mitreRoutes = require('./routes/mitre');
const actorsRoutes = require('./routes/actors');
const cveRoutes = require('./routes/cve');
const threatsRoutes = require('./routes/threats');
const siemRoutes = require('./routes/siem');
const packetRouter = require('./routes/packet');
const phishingRoutes = require('./routes/phishing');  // Only declare ONCE
const deeppacketRoutes = require('./routes/deeppacket');
const ultraPacketRoutes = require('./routes/ultraPacket');
const threatRoutes = require('./routes/threat');

const app = express();
const PORT = process.env.PORT || 3001;

// Import services - USING CORRECT FILE NAMES
const { fetchLatestCVEs } = require('./services/cveIngestion');
const runFeedEngine = require('./services/feedEngine');
const fetchKEV = require('./services/kevIngest');
const runRiskEngine = require('./services/riskEngine');
const runExploitMonitor = require('./services/exploitMonitor');
const securityAgentRoutes = require('./routes/securityAgent');
const settingsRoutes = require('./routes/settings');

// Import routes with error handling
let productSearchRoutes, feedRoutes, knowledgeRoutes, redisRoutes, cacheRoutes, metricsRoutes;

try {
  productSearchRoutes = require('./routes/productSearch');
  console.log('✅ Loaded: productSearch routes');
} catch (err) {
  console.error('❌ Failed to load productSearch routes:', err.message);
  productSearchRoutes = express.Router();
  productSearchRoutes.get('/', (req, res) => res.json({ error: 'Route not implemented' }));
}

try {
  feedRoutes = require('./routes/feed');
  console.log('✅ Loaded: feed routes');
} catch (err) {
  console.error('❌ Failed to load feed routes:', err.message);
  feedRoutes = express.Router();
  feedRoutes.get('/', (req, res) => res.json({ error: 'Route not implemented' }));
}

try {
  knowledgeRoutes = require('./routes/knowledge');
  console.log('✅ Loaded: knowledge routes');
} catch (err) {
  console.error('❌ Failed to load knowledge routes:', err.message);
  knowledgeRoutes = express.Router();
  knowledgeRoutes.get('/', (req, res) => res.json({ error: 'Route not implemented' }));
}

try {
  redisRoutes = require('./routes/redis');
  console.log('✅ Loaded: redis routes');
} catch (err) {
  console.error('❌ Failed to load redis routes:', err.message);
  redisRoutes = express.Router();
  redisRoutes.get('/', (req, res) => res.json({ error: 'Route not implemented' }));
}

try {
  cacheRoutes = require('./routes/cache');
  console.log('✅ Loaded: cache routes');
} catch (err) {
  console.error('❌ Failed to load cache routes:', err.message);
  cacheRoutes = express.Router();
  cacheRoutes.get('/', (req, res) => res.json({ error: 'Route not implemented' }));
}

try {
  metricsRoutes = require('./routes/metrics');
  console.log('✅ Loaded: metrics routes');
} catch (err) {
  console.error('❌ Failed to load metrics routes:', err.message);
  // Create a simple metrics router as fallback
  metricsRoutes = express.Router();
  metricsRoutes.get('/', (req, res) => {
    res.json({
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      timestamp: new Date().toISOString()
    });
  });
}

// Schedule CVE updates every 10 minutes
cron.schedule("*/10 * * * *", async () => {
  console.log('Running scheduled CVE update...');
  try {
    await fetchLatestCVEs();
  } catch (err) {
    console.error('CVE update error:', err.message);
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable for development
}));

// CORS
app.use(cors({ 
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { error: 'Rate limit hit' },
  skip: (req) => req.path === '/health' // Skip health check endpoints
}));

// Compression and parsing
app.use(compression());
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, '..', 'public')));

// API Routes with error handling for each
const routeModules = {
  '/api/ai': './routes/ai',
  '/api/queries': './routes/queries',
  '/api/ti': './routes/ti',
  '/api/feed': './routes/feed',
  '/api/cve': './routes/cve',
  '/api/zeroday': './routes/zeroday',
  '/api/knowledge': './routes/knowledge',
  '/api/enrich': './routes/enrich',
  '/api/logs': './routes/logs',
  '/api/threats': './routes/threats',
  '/api/actors': './routes/actors',
  '/api/mitre': './routes/mitre',
  '/api/aisec': './routes/aisec',
  '/api/agent': './routes/agent',
  '/api/misp': './routes/misp',
  '/api/dashboard': './routes/dashboard',
  '/api/threat': './routes/threat'
};

Object.entries(routeModules).forEach(([path, modulePath]) => {
  try {
    const router = require(modulePath);
    app.use(path, router);
    console.log(`✅ Mounted: ${path}`);
  } catch (err) {
    console.error(`❌ Failed to mount ${path}:`, err.message);
    // Create a simple error router as fallback
    const fallbackRouter = express.Router();
    fallbackRouter.all('*', (req, res) => {
      res.status(503).json({ 
        error: 'Service temporarily unavailable',
        message: err.message,
        path: req.path
      });
    });
    app.use(path, fallbackRouter);
  }
});

// Add SSE endpoint for refresh countdown
app.get('/api/refresh-countdown', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });
  
  let seconds = 30;
  
  const interval = setInterval(() => {
    seconds--;
    if (seconds < 0) seconds = 30;
    
    res.write(`data: ${JSON.stringify({ seconds })}\n\n`);
    
    // Flush if supported
    if (res.flush) {
      res.flush();
    }
  }, 1000);
  
  req.on('close', () => {
    clearInterval(interval);
    res.end();
  });
});

// New routes - EACH ROUTE REGISTERED ONCE
app.use('/api/search', productSearchRoutes);
app.use('/api/feed/new', feedRoutes);
app.use('/api/knowledge-base', knowledgeRoutes);
app.use('/api/redis', redisRoutes);
app.use('/api/cache', cacheRoutes);
app.use('/api/metrics', metricsRoutes);
app.use('/api/phishing', phishingRoutes);  // Only ONCE
app.use('/api/packet', packetRouter);
app.use('/api/deeppacket', deeppacketRoutes);
app.use('/api/packet/ultra', ultraPacketRoutes);
app.use('/api/ioc', require('./routes/ioc'));
app.use('/api/threat', threatRoutes);

// Advanced Packet Analysis Routes
let advancedPacketRoutes, agentRoutes, awsRoutes, azureRoutes;
try {
  advancedPacketRoutes = require('./routes/advancedPacket');
  console.log('✅ Loaded: advancedPacket routes');
} catch (err) {
  console.error('❌ Failed to load advancedPacket routes:', err.message);
  advancedPacketRoutes = express.Router();
}

try {
  agentRoutes = require('./agents/AgentManager');
  console.log('✅ Loaded: agent routes');
} catch (err) {
  console.error('❌ Failed to load agent routes:', err.message);
  agentRoutes = { router: express.Router() };
}

try {
  awsRoutes = require('../cloud-integrations/aws-integration');
  console.log('✅ Loaded: AWS integration routes');
} catch (err) {
  console.error('❌ Failed to load AWS routes:', err.message);
  awsRoutes = { router: express.Router() };
}

try {
  azureRoutes = require('../cloud-integrations/azure-integration');
  console.log('✅ Loaded: Azure integration routes');
} catch (err) {
  console.error('❌ Failed to load Azure routes:', err.message);
  azureRoutes = { router: express.Router() };
}

app.use('/api/analyze', advancedPacketRoutes);
app.use('/api/agents', agentRoutes.router ? agentRoutes.router : agentRoutes);
app.use('/api/ai-agent', securityAgentRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/aws', awsRoutes.router ? awsRoutes.router : awsRoutes);
app.use('/api/azure', azureRoutes.router ? azureRoutes.router : azureRoutes);

// Core routes
app.use('/api/logs', logsRoutes);
app.use('/api/mitre', mitreRoutes);
app.use('/api/actors', actorsRoutes);
app.use('/api/cve', cveRoutes);
app.use('/api/threats', threatsRoutes);
app.use('/api/siem', siemRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  const provider = (process.env.AI_PROVIDER || '').toLowerCase().trim();
  const keyMap = {
    groq: 'GROQ_API_KEY',
    openai: 'OPENAI_API_KEY',
    anthropic: 'ANTHROPIC_API_KEY',
    gemini: 'GEMINI_API_KEY',
    mistral: 'MISTRAL_API_KEY'
  };
  const envKey = keyMap[provider] || '';
  const keyVal = process.env[envKey] || '';
  const keyOk = keyVal.length > 10 && !keyVal.startsWith('your-');

  res.json({
    status: 'online',
    port: PORT,
    uptime: process.uptime(),
    aiProvider: provider || 'none',
    aiKeyEnvVar: envKey || 'N/A',
    aiKeySet: keyOk,
    aiKeyPreview: keyOk ? keyVal.slice(0, 8) + '...' : 'NOT SET or still placeholder',
    vtEnabled: !!(process.env.VT_API_KEY && !process.env.VT_API_KEY.startsWith('your-')),
    abuseEnabled: !!(process.env.ABUSEIPDB_KEY && !process.env.ABUSEIPDB_KEY.startsWith('your-')),
    mispEnabled: !!(process.env.MISP_URL && process.env.MISP_API_KEY && !String(process.env.MISP_URL).includes('your-misp') && !String(process.env.MISP_API_KEY).startsWith('your-')),
    nodeVersion: process.version,
    platform: process.platform
  });
});

// Nginx health check
app.get('/nginx/health', (req, res) => {
    const proxied = !!(req.headers['x-forwarded-for'] || req.headers['x-real-ip']);
    res.json({
        proxied,
        headers: {
            'x-forwarded-for': req.headers['x-forwarded-for'] || null,
            'x-real-ip': req.headers['x-real-ip'] || null,
            'host': req.headers['host']
        }
    });
});

// Serve static pages
app.get('/threat', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'threat.html'));
});

app.get('/packet-analyzer', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'packet-analyzer.html'));
});

app.get('/packet-pro', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'packet-pro.html'));
});

app.get('/ultra-packet', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'ultra-packet.html'));
});

// Serve index.html for all other routes (SPA support)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    error: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    timestamp: new Date().toISOString()
  });
});

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found', path: req.originalUrl });
});

// Run services on startup with error handling
console.log('Starting background services...');

const runService = async (service, name) => {
  try {
    await service();
    console.log(`✅ ${name} started successfully`);
  } catch (err) {
    console.error(`❌ ${name} error:`, err.message);
  }
};

// Run services
runService(fetchLatestCVEs, 'CVE fetch');
runService(fetchKEV, 'KEV fetch');
runService(runExploitMonitor, 'Exploit monitor');
runService(runRiskEngine, 'Risk engine');
runService(runFeedEngine, 'Feed engine');

// Schedule them to run periodically
cron.schedule('0 */6 * * *', () => {
  console.log('Running scheduled KEV update...');
  runService(fetchKEV, 'KEV fetch');
}); // Every 6 hours

cron.schedule('*/30 * * * *', () => {
  console.log('Running scheduled exploit monitor...');
  runService(runExploitMonitor, 'Exploit monitor');
}); // Every 30 minutes

cron.schedule('*/15 * * * *', () => {
  console.log('Running scheduled risk engine...');
  runService(runRiskEngine, 'Risk engine');
}); // Every 15 minutes

cron.schedule('*/10 * * * *', () => {
  console.log('Running scheduled feed engine...');
  runService(runFeedEngine, 'Feed engine');
}); // Every 10 minutes

cron.schedule('*/10 * * * *', () => {
  console.log('Running scheduled CVE update...');
  runService(fetchLatestCVEs, 'CVE fetch');
}); // Every 10 minutes

// Automatic phishing mailbox polling (Microsoft 365 Graph via phishing route)
cron.schedule('*/2 * * * *', async () => {
  if (String(process.env.AUTO_PHISH_ENABLE || 'false').toLowerCase() !== 'true') return;
  try {
    const pollUrl = `http://127.0.0.1:${PORT}/api/phishing/auto/poll-now`;
    const response = await fetch(pollUrl, { method: 'POST', signal: AbortSignal.timeout(15000) });
    if (!response.ok) {
      console.error('Auto phishing poll failed with status:', response.status);
    } else {
      console.log('✅ Auto phishing poll completed');
    }
  } catch (err) {
    console.error('❌ Auto phishing polling error:', err.message);
  }
}); // Every 2 minutes

// Start server
const server = app.listen(PORT, () => {
  console.log('\n  ╔════════════════════════════════════════════════════════════╗');
  console.log('  ║   🛡  SOC Dashboard  v7.0                                 ║');
  console.log(`  ║   http://localhost:${PORT}                                   ║`);
  console.log('  ║   Query · Feed · Enrich · Logs · MITRE · Actors · AI Sec  ║');
  console.log('  ╚════════════════════════════════════════════════════════════╝\n');
  console.log('  AI Provider :', process.env.AI_PROVIDER || 'template');
  console.log('  VT API      :', process.env.VT_API_KEY && !process.env.VT_API_KEY.startsWith('your-') ? '✅ Active' : '❌ Not set');
  console.log('  AbuseIPDB   :', process.env.ABUSEIPDB_KEY && !process.env.ABUSEIPDB_KEY.startsWith('your-') ? '✅ Active' : '❌ Not set');
  console.log('');
  console.log('  📊 Background services:');
  console.log('  • CVE Ingestion    : ✅ Scheduled every 10 min');
  console.log('  • KEV Ingestion    : ✅ Scheduled every 6 hours');
  console.log('  • Exploit Monitor  : ✅ Scheduled every 30 min');
  console.log('  • Risk Engine      : ✅ Scheduled every 15 min');
  console.log('  • Feed Engine      : ✅ Scheduled every 10 min');
  console.log('  • Phishing AutoPoll: ' + (String(process.env.AUTO_PHISH_ENABLE || 'false').toLowerCase() === 'true' ? '✅ Every 2 min' : '❌ Disabled'));
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

module.exports = app;