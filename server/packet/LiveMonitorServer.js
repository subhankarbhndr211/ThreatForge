/**
 * ThreatForge Live Monitor Server
 * Real-time packet monitoring via WebSocket
 */
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { spawn } = require('child_process');
const path = require('path');

class LiveMonitorServer {
    constructor(port = 3001) {
        this.port = port;
        this.monitors = new Map();
        this.wss = null;
        this.server = null;
    }

    start() {
        const app = express();
        app.use(express.json());

        this.server = http.createServer(app);
        this.wss = new WebSocket.Server({ server: this.server });

        this.wss.on('connection', (ws, req) => {
            console.log('[LiveMonitor] Client connected');
            const clientId = Date.now().toString();
            
            ws.on('message', (message) => {
                try {
                    const cmd = JSON.parse(message);
                    this.handleMessage(ws, clientId, cmd);
                } catch (e) {
                    console.error('[LiveMonitor] Invalid message:', e.message);
                }
            });

            ws.on('close', () => {
                console.log('[LiveMonitor] Client disconnected');
                this.stopMonitor(clientId);
            });

            ws.send(JSON.stringify({ type: 'connected', clientId }));
        });

        app.get('/api/monitor/interfaces', (req, res) => {
            this.getInterfaces().then(interfaces => res.json(interfaces));
        });

        app.post('/api/monitor/start', async (req, res) => {
            const { interface, bpf, clientId } = req.body;
            try {
                const monitorId = await this.startMonitor(clientId || 'default', interface, bpf);
                res.json({ success: true, monitorId });
            } catch (e) {
                res.status(500).json({ error: e.message });
            }
        });

        app.post('/api/monitor/stop', (req, res) => {
            const { clientId } = req.body;
            const result = this.stopMonitor(clientId || 'default');
            res.json({ success: true, ...result });
        });

        app.get('/api/monitor/status/:clientId', (req, res) => {
            const status = this.getMonitorStatus(req.params.clientId);
            res.json(status);
        });

        this.server.listen(this.port, () => {
            console.log(`[LiveMonitor] Server running on port ${this.port}`);
        });
    }

    handleMessage(ws, clientId, cmd) {
        switch (cmd.type) {
            case 'start':
                this.startMonitor(clientId, cmd.interface, cmd.bpf)
                    .then(monitorId => ws.send(JSON.stringify({ type: 'started', monitorId })));
                break;
            case 'stop':
                const result = this.stopMonitor(clientId);
                ws.send(JSON.stringify({ type: 'stopped', ...result }));
                break;
            case 'status':
                ws.send(JSON.stringify({ type: 'status', ...this.getMonitorStatus(clientId) }));
                break;
        }
    }

    async getInterfaces() {
        return new Promise((resolve) => {
            const pyScript = path.join(__dirname, '..', '..', 'packet-engine', 'live_monitor.py');
            const proc = spawn('python', ['-c', `
import sys
sys.path.insert(0, r'${path.dirname(pyScript).replace(/\\/g, '\\\\')}')
from live_monitor import list_interfaces
import json
print(json.dumps(list_interfaces()))
`], { windowsHide: true });

            let output = '';
            proc.stdout.on('data', d => output += d.toString());
            proc.on('close', () => {
                try {
                    resolve(JSON.parse(output));
                } catch {
                    resolve([{ name: 'default', ip: '0.0.0.0', description: 'Default interface' }]);
                }
            });
            proc.on('error', () => {
                resolve([{ name: 'default', ip: '0.0.0.0', description: 'Default interface' }]);
            });
        });
    }

    async startMonitor(clientId, interfaceName, bpfFilter) {
        if (this.monitors.has(clientId)) {
            this.stopMonitor(clientId);
        }

        const monitorId = `${clientId}_${Date.now()}`;
        const pyScript = path.join(__dirname, '..', '..', 'packet-engine', 'live_monitor.py');

        const args = [pyScript];
        if (interfaceName) args.push('--monitor', interfaceName);
        if (bpfFilter) args.push(bpfFilter);

        const proc = spawn('python', args, {
            cwd: path.dirname(pyScript),
            windowsHide: true
        });

        let buffer = '';
        proc.stdout.on('data', (data) => {
            buffer += data.toString();
            let newline;
            while ((newline = buffer.indexOf('\n')) !== -1) {
                const line = buffer.slice(0, newline).trim();
                buffer = buffer.slice(newline + 1);
                if (line && line.startsWith('{')) {
                    try {
                        const snapshot = JSON.parse(line);
                        this.broadcast(clientId, { type: 'snapshot', ...snapshot });
                    } catch {}
                }
            }
        });

        proc.stderr.on('data', d => console.error('[Monitor]', d.toString()));
        proc.on('error', e => console.error('[Monitor]', e.message));

        this.monitors.set(clientId, {
            id: monitorId,
            process: proc,
            startTime: Date.now(),
            interface: interfaceName,
            bpf: bpfFilter
        });

        return monitorId;
    }

    stopMonitor(clientId) {
        const monitor = this.monitors.get(clientId);
        if (monitor) {
            if (!monitor.process.killed) {
                monitor.process.kill();
            }
            this.monitors.delete(clientId);
            return { stopped: true, duration: (Date.now() - monitor.startTime) / 1000 };
        }
        return { stopped: false };
    }

    getMonitorStatus(clientId) {
        const monitor = this.monitors.get(clientId);
        if (monitor) {
            return {
                running: true,
                id: monitor.id,
                duration: (Date.now() - monitor.startTime) / 1000,
                interface: monitor.interface
            };
        }
        return { running: false };
    }

    broadcast(clientId, message) {
        if (this.wss) {
            const msg = JSON.stringify(message);
            this.wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(msg);
                }
            });
        }
    }

    stop() {
        this.monitors.forEach((m, id) => this.stopMonitor(id));
        if (this.server) this.server.close();
    }
}

module.exports = LiveMonitorServer;
