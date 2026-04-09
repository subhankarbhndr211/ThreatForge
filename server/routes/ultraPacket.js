/**
 * ThreatForge Ultra Packet Analysis Routes
 * Mounted at /api/packet/ultra
 *
 * POST /api/packet/ultra/analyze          — upload PCAP, get full report
 * POST /api/packet/ultra/analyze/advanced — report + STIX + LLM triage
 * GET  /api/packet/ultra/analysis/:id     — retrieve cached analysis
 * GET  /api/packet/ultra/stix/:id         — STIX 2.1 bundle
 * GET  /api/packet/ultra/triage/:id       — LLM-ready triage brief
 * GET  /api/packet/ultra/interfaces       — list capture interfaces
 * POST /api/packet/ultra/live/start       — start live capture
 * POST /api/packet/ultra/live/stop/:sid   — stop live capture
 * GET  /api/packet/ultra/live/sessions    — active sessions
 * GET  /api/packet/ultra/health           — engine health
 */

const express = require('express');
const multer  = require('multer');
const router  = express.Router();
const engine  = require('../packet/UltraPacketEngine');

// ── multer: memory storage, max 500 MB PCAP ──────────────────────────────────
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 500 * 1024 * 1024 },
    fileFilter(req, file, cb) {
        const ok = ['.pcap', '.pcapng', '.cap', '.dmp'].some(ext =>
            file.originalname.toLowerCase().endsWith(ext)
        );
        cb(ok ? null : new Error('Only PCAP files accepted'), ok);
    },
});

// ── middleware: JSON error wrapper ────────────────────────────────────────────
function asyncRoute(fn) {
    return (req, res, next) => fn(req, res, next).catch(err => {
        console.error('[UltraPacket]', err.message);
        res.status(500).json({ error: err.message });
    });
}

// ── ANALYZE ───────────────────────────────────────────────────────────────────

/**
 * POST /api/packet/ultra/analyze
 * Body: multipart/form-data  field: pcap
 * Optional query: ?noML=1  ?noYara=1
 */
router.post('/analyze', upload.single('pcap'), asyncRoute(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No PCAP file uploaded (field: pcap)' });

    const opts = {
        noML:   req.query.noML   === '1',
        noYara: req.query.noYara === '1',
        timeout: parseInt(req.query.timeout) || undefined,
    };

    const report     = await engine.analyzeBuffer(req.file.buffer, opts);
    const analysisId = await engine.getAnalysis   // cache is populated inside analyzeBufferAdvanced
        ? null : null;  // basic analyze doesn't auto-cache; use /advanced for that

    res.json({
        success: true,
        filename: req.file.originalname,
        size:     req.file.size,
        report,
    });
}));

/**
 * POST /api/packet/ultra/analyze/advanced
 * Returns full report + STIX bundle + LLM triage brief, all cached.
 */
router.post('/analyze/advanced', upload.single('pcap'), asyncRoute(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No PCAP file uploaded (field: pcap)' });

    const opts = {
        noML:   req.query.noML   === '1',
        noYara: req.query.noYara === '1',
    };

    const result = await engine.analyzeBufferAdvanced(req.file.buffer, opts);

    res.json({
        success:    true,
        filename:   req.file.originalname,
        size:       req.file.size,
        analysisId: result.analysisId,
        report:     result.report,
        stix:       result.stix,
        triage:     result.triage,
    });
}));

// ── RETRIEVE ──────────────────────────────────────────────────────────────────

router.get('/analysis/:id', asyncRoute(async (req, res) => {
    const entry = engine.getAnalysis(req.params.id);
    if (!entry) return res.status(404).json({ error: 'Analysis not found or expired' });
    res.json({ analysisId: req.params.id, ...entry });
}));

router.get('/stix/:id', asyncRoute(async (req, res) => {
    const stix = engine.exportSTIX(req.params.id);
    if (!stix) return res.status(404).json({ error: 'STIX bundle not available' });
    res.setHeader('Content-Type', 'application/stix+json');
    res.json(stix);
}));

router.get('/triage/:id', asyncRoute(async (req, res) => {
    const triage = engine.getLLMTriage(req.params.id);
    if (!triage) return res.status(404).json({ error: 'Triage brief not available' });
    res.type('text/plain').send(triage);
}));

// ── LIVE CAPTURE ──────────────────────────────────────────────────────────────

/**
 * GET /api/packet/ultra/interfaces
 */
router.get('/interfaces', asyncRoute(async (req, res) => {
    const ifaces = await engine.listInterfaces();
    res.json({ interfaces: ifaces });
}));

/**
 * POST /api/packet/ultra/live/start
 * Body JSON: { iface, duration, bpf }
 * Streams events via SSE while capture runs.
 */
router.post('/live/start', asyncRoute(async (req, res) => {
    const { iface, duration = 60, bpf = '' } = req.body;
    if (!iface) return res.status(400).json({ error: 'iface required' });

    // SSE setup
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const { sessionId, emitter } = engine.startLiveCapture(iface, { duration, bpf });
    res.write(`data: ${JSON.stringify({ event: 'started', sessionId })}\n\n`);

    emitter.on('snapshot', snap => {
        res.write(`data: ${JSON.stringify({ event: 'snapshot', sessionId, data: snap })}\n\n`);
    });

    emitter.on('threat', threat => {
        res.write(`data: ${JSON.stringify({ event: 'threat', sessionId, data: threat })}\n\n`);
    });

    emitter.on('error', err => {
        res.write(`data: ${JSON.stringify({ event: 'error', sessionId, message: err.message })}\n\n`);
        res.end();
    });

    emitter.on('stop', result => {
        res.write(`data: ${JSON.stringify({ event: 'complete', ...result })}\n\n`);
        res.end();
    });

    req.on('close', () => engine.stopLiveCapture(sessionId));
}));

/**
 * POST /api/packet/ultra/live/stop/:sid
 */
router.post('/live/stop/:sid', asyncRoute(async (req, res) => {
    const stopped = engine.stopLiveCapture(req.params.sid);
    res.json({ stopped, sessionId: req.params.sid });
}));

/**
 * GET /api/packet/ultra/live/sessions
 */
router.get('/live/sessions', asyncRoute(async (req, res) => {
    res.json({ sessions: engine.listLiveSessions() });
}));

// ── HEALTH ────────────────────────────────────────────────────────────────────

router.get('/health', asyncRoute(async (req, res) => {
    const health = await engine.engineHealth();
    res.json({
        route:  'ultra-packet-engine',
        engine: 'ultra_analyzer.py',
        ...health,
    });
}));

module.exports = router;
