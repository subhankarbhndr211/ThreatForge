/**
 * ThreatForge Ultra Packet Engine Bridge v2.0
 * Node.js wrapper for ultra_analyzer.py
 *
 * Capabilities exposed to Express routes:
 *   - analyzeBuffer(buffer)          → full ultra report
 *   - analyzeFile(filePath)          → full ultra report
 *   - analyzeBufferAdvanced(buffer)  → report + STIX bundle + LLM triage
 *   - startLiveCapture(iface, opts)  → streaming analysis via EventEmitter
 *   - stopLiveCapture(sessionId)
 *   - exportSTIX(analysisId)
 *   - getLLMTriage(analysisId)
 */

const { spawn, execFile } = require('child_process');
const path    = require('path');
const fs      = require('fs');
const os      = require('os');
const crypto  = require('crypto');
const { EventEmitter } = require('events');

const PYTHON_CMD    = process.platform === 'win32' ? 'python' : 'python3';
const ENGINE_DIR    = path.join(__dirname, '..', '..', 'packet-engine');
const ULTRA_ENGINE  = path.join(ENGINE_DIR, 'ultra_analyzer.py');
const ANALYSIS_CACHE = new Map();   // analysisId -> { report, stix, triage, ts }
const LIVE_SESSIONS  = new Map();   // sessionId  -> { proc, emitter, startTs }

const MAX_CACHE     = 100;
const ANALYSIS_TTL  = 30 * 60 * 1000;   // 30 minutes
const PCAP_TIMEOUT  = 120_000;           // 2 min for large PCAPs
const LIVE_TIMEOUT  = 300_000;           // 5 min max live capture

// ── helpers ──────────────────────────────────────────────────────────────────

function _tempPcap() {
    return path.join(os.tmpdir(), `tf_ultra_${Date.now()}_${Math.random().toString(36).slice(2)}.pcap`);
}

function _runPython(args, inputBuffer = null, timeout = PCAP_TIMEOUT) {
    return new Promise((resolve, reject) => {
        const proc = spawn(PYTHON_CMD, args, {
            cwd:         ENGINE_DIR,
            windowsHide: true,
            env: { ...process.env, PYTHONUNBUFFERED: '1' },
        });

        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => {
            proc.kill('SIGTERM');
            reject(new Error(`Python process timed out after ${timeout}ms`));
        }, timeout);

        proc.stdout.on('data', d => { stdout += d.toString(); });
        proc.stderr.on('data', d => { stderr += d.toString(); });

        proc.on('close', code => {
            clearTimeout(timer);
            if (code !== 0 && !stdout.trim()) {
                return reject(new Error(`Python exited ${code}: ${stderr.slice(0, 500)}`));
            }
            try {
                resolve(JSON.parse(stdout));
            } catch {
                reject(new Error(`JSON parse failed: ${stdout.slice(0, 200)}`));
            }
        });

        proc.on('error', err => {
            clearTimeout(timer);
            reject(err);
        });
    });
}

function _cacheAnalysis(report, stix = null, triage = null) {
    const id = crypto.randomUUID();
    if (ANALYSIS_CACHE.size >= MAX_CACHE) {
        const oldest = [...ANALYSIS_CACHE.entries()]
            .sort((a, b) => a[1].ts - b[1].ts)[0];
        ANALYSIS_CACHE.delete(oldest[0]);
    }
    ANALYSIS_CACHE.set(id, { report, stix, triage, ts: Date.now() });
    return id;
}

function _purgeExpiredCache() {
    const now = Date.now();
    for (const [id, entry] of ANALYSIS_CACHE.entries()) {
        if (now - entry.ts > ANALYSIS_TTL) ANALYSIS_CACHE.delete(id);
    }
}
setInterval(_purgeExpiredCache, 5 * 60 * 1000);

// ── core analysis ─────────────────────────────────────────────────────────────

/**
 * Analyze a raw PCAP buffer.
 * Returns a full UltraAnalyzer report object.
 */
async function analyzeBuffer(buffer, opts = {}) {
    const tmp = _tempPcap();
    try {
        await fs.promises.writeFile(tmp, buffer);
        return await analyzeFile(tmp, opts);
    } finally {
        fs.unlink(tmp, () => {});
    }
}

/**
 * Analyze an on-disk PCAP file.
 */
async function analyzeFile(filePath, opts = {}) {
    const args = [ULTRA_ENGINE, filePath];
    if (opts.noML)   args.push('--no-ml');
    if (opts.noYara) args.push('--no-yara');

    const report = await _runPython(args, null, opts.timeout || PCAP_TIMEOUT);
    return report;
}

/**
 * Full-pipeline analysis: report + STIX + LLM triage in one call.
 * Returns { analysisId, report, stix, triage }
 */
async function analyzeBufferAdvanced(buffer, opts = {}) {
    const tmp = _tempPcap();
    try {
        await fs.promises.writeFile(tmp, buffer);

        // Run report
        const reportArgs = [ULTRA_ENGINE, tmp];
        if (opts.noML)   reportArgs.push('--no-ml');
        if (opts.noYara) reportArgs.push('--no-yara');

        // Run STIX export
        const stixTmp = tmp + '.stix.json';
        const stixArgs  = [ULTRA_ENGINE, tmp, '--stix', '--out', stixTmp];
        const triageArgs = [ULTRA_ENGINE, tmp, '--triage', '--out', '-'];

        const [report] = await Promise.all([
            _runPython(reportArgs, null, opts.timeout || PCAP_TIMEOUT),
        ]);

        // STIX
        let stix = null;
        try {
            await _runPython(stixArgs, null, 30_000);
            stix = JSON.parse(await fs.promises.readFile(stixTmp, 'utf8'));
        } catch { /* STIX export optional */ }
        finally { fs.unlink(stixTmp, () => {}); }

        // Triage brief (text output, not JSON)
        let triage = null;
        try {
            triage = await new Promise((res, rej) => {
                const proc = spawn(PYTHON_CMD, triageArgs, {
                    cwd: ENGINE_DIR, windowsHide: true,
                });
                let out = '';
                proc.stdout.on('data', d => { out += d; });
                proc.on('close', () => res(out.trim()));
                proc.on('error', rej);
            });
        } catch { /* optional */ }

        const analysisId = _cacheAnalysis(report, stix, triage);
        return { analysisId, report, stix, triage };

    } finally {
        fs.unlink(tmp, () => {});
    }
}

// ── live capture ──────────────────────────────────────────────────────────────

/**
 * Start a live capture session. Returns { sessionId, emitter }.
 * emitter emits: 'snapshot', 'threat', 'error', 'stop'
 */
function startLiveCapture(iface, opts = {}) {
    const sessionId = crypto.randomUUID();
    const emitter   = new EventEmitter();

    const args = [
        ULTRA_ENGINE,
        '--live', iface,
        '--duration', String(opts.duration || 60),
    ];
    if (opts.bpf) args.push('--bpf', opts.bpf);

    const proc = spawn(PYTHON_CMD, args, {
        cwd: ENGINE_DIR, windowsHide: true,
        env: { ...process.env, PYTHONUNBUFFERED: '1' },
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', d => {
        stdout += d.toString();
        // Try to emit partial JSON snapshots
        const lines = stdout.split('\n');
        lines.slice(0, -1).forEach(line => {
            try {
                const evt = JSON.parse(line.trim());
                emitter.emit('snapshot', evt);
            } catch { /* incomplete */ }
        });
        stdout = lines[lines.length - 1];
    });

    proc.stderr.on('data', d => {
        stderr += d.toString();
        const lines = stderr.split('\n');
        lines.slice(0, -1).forEach(line => {
            if (line.includes('THREAT:')) {
                try {
                    emitter.emit('threat', JSON.parse(line.replace('THREAT:', '')));
                } catch { /* ignore */ }
            }
        });
        stderr = lines[lines.length - 1];
    });

    const watchdog = setTimeout(() => proc.kill('SIGTERM'), LIVE_TIMEOUT);

    proc.on('close', code => {
        clearTimeout(watchdog);
        try {
            const report = JSON.parse(stdout || '{}');
            const id = _cacheAnalysis(report);
            emitter.emit('stop', { sessionId, analysisId: id, report, code });
        } catch {
            emitter.emit('stop', { sessionId, code });
        }
        LIVE_SESSIONS.delete(sessionId);
    });

    proc.on('error', err => {
        clearTimeout(watchdog);
        emitter.emit('error', err);
        LIVE_SESSIONS.delete(sessionId);
    });

    LIVE_SESSIONS.set(sessionId, { proc, emitter, startTs: Date.now(), iface });
    return { sessionId, emitter };
}

function stopLiveCapture(sessionId) {
    const session = LIVE_SESSIONS.get(sessionId);
    if (!session) return false;
    session.proc.kill('SIGTERM');
    return true;
}

function listLiveSessions() {
    return [...LIVE_SESSIONS.entries()].map(([id, s]) => ({
        sessionId: id,
        iface: s.iface,
        durationMs: Date.now() - s.startTs,
    }));
}

// ── retrieval ─────────────────────────────────────────────────────────────────

function getAnalysis(analysisId) {
    return ANALYSIS_CACHE.get(analysisId) || null;
}

function exportSTIX(analysisId) {
    const entry = ANALYSIS_CACHE.get(analysisId);
    return entry?.stix || null;
}

function getLLMTriage(analysisId) {
    const entry = ANALYSIS_CACHE.get(analysisId);
    return entry?.triage || null;
}

// ── interface list ────────────────────────────────────────────────────────────

async function listInterfaces() {
    return new Promise((resolve) => {
        const proc = spawn(PYTHON_CMD, [
            path.join(ENGINE_DIR, 'live_monitor.py'), '--interfaces'
        ], { cwd: ENGINE_DIR, windowsHide: true });
        let out = '';
        proc.stdout.on('data', d => { out += d; });
        proc.on('close', () => {
            const ifaces = out.trim().split('\n').map(line => {
                const [name, ip] = line.split(':').map(s => s.trim());
                return { name, ip: ip || 'N/A' };
            }).filter(i => i.name);
            resolve(ifaces);
        });
        proc.on('error', () => resolve([]));
    });
}

// ── engine health ─────────────────────────────────────────────────────────────

async function engineHealth() {
    return new Promise(resolve => {
        execFile(PYTHON_CMD, ['-c',
            `import sys; sys.path.insert(0,'${ENGINE_DIR}'); ` +
            `import importlib.util; ` +
            `spec=importlib.util.spec_from_file_location('u','${ULTRA_ENGINE}'); ` +
            `m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); ` +
            `print('{"status":"ok","ml":'+str(m.ML).lower()+',"yara":'+str(m.YARA).lower()+',"scapy":'+str(m.SCAPY).lower()+'}')`,
        ], (err, stdout) => {
            try   { resolve(JSON.parse(stdout)); }
            catch { resolve({ status: err ? 'error' : 'degraded', error: String(err) }); }
        });
    });
}

module.exports = {
    // Primary API
    analyzeBuffer,
    analyzeFile,
    analyzeBufferAdvanced,

    // Live capture
    startLiveCapture,
    stopLiveCapture,
    listLiveSessions,

    // Results
    getAnalysis,
    exportSTIX,
    getLLMTriage,

    // Utilities
    listInterfaces,
    engineHealth,
};
