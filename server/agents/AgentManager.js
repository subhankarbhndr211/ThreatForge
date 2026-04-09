/**
 * ThreatForge Agent Manager
 * Manages distributed network monitoring agents across LAN, WAN, Proxy, AWS, Azure
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

class AgentManager extends EventEmitter {
    constructor() {
        super();
        this.agents = new Map();
        this.deployments = new Map();
        this.metrics = new Map();
        this.heartbeatInterval = null;
        this.startHeartbeatMonitor();
    }

    register(agentData) {
        const agent = {
            id: agentData.id || uuidv4(),
            name: agentData.name,
            type: agentData.type || 'network',
            platform: agentData.platform || 'generic',
            environment: agentData.environment || 'lan',
            ip: agentData.ip,
            mac: agentData.mac,
            version: agentData.version || '1.0.0',
            capabilities: agentData.capabilities || ['packet_capture', 'basic_analysis'],
            status: 'online',
            lastHeartbeat: Date.now(),
            registeredAt: new Date().toISOString(),
            config: {
                interface: agentData.config?.interface || 'any',
                bpfFilter: agentData.config?.bpfFilter || '',
                maxPacketRate: agentData.config?.maxPacketRate || 10000,
                samplingRate: agentData.config?.samplingRate || 1,
                bufferSize: agentData.config?.bufferSize || 65535
            },
            metrics: {
                packetsCaptured: 0,
                bytesProcessed: 0,
                alertsGenerated: 0,
                cpuUsage: 0,
                memoryUsage: 0
            },
            tags: agentData.tags || []
        };

        this.agents.set(agent.id, agent);
        this.metrics.set(agent.id, {
            timestamps: [],
            packetRates: [],
            byteRates: [],
            alertRates: []
        });

        this.emit('agent:registered', agent);
        console.log(`[AgentManager] Agent registered: ${agent.name} (${agent.id})`);
        return agent;
    }

    heartbeat(agentId, metrics) {
        const agent = this.agents.get(agentId);
        if (!agent) return false;

        agent.lastHeartbeat = Date.now();
        agent.status = 'online';
        
        if (metrics) {
            agent.metrics = { ...agent.metrics, ...metrics };
            this.recordMetrics(agentId, metrics);
        }

        this.emit('agent:heartbeat', agent);
        return true;
    }

    recordMetrics(agentId, metrics) {
        const record = this.metrics.get(agentId);
        if (!record) return;

        const now = Date.now();
        record.timestamps.push(now);
        record.packetRates.push(metrics.packetsCaptured || 0);
        record.byteRates.push(metrics.bytesProcessed || 0);
        record.alertRates.push(metrics.alertsGenerated || 0);

        const cutoff = now - 3600000;
        while (record.timestamps.length > 0 && record.timestamps[0] < cutoff) {
            record.timestamps.shift();
            record.packetRates.shift();
            record.byteRates.shift();
            record.alertRates.shift();
        }
    }

    startHeartbeatMonitor() {
        this.heartbeatInterval = setInterval(() => {
            const now = Date.now();
            const timeout = 60000;

            for (const [id, agent] of this.agents) {
                if (now - agent.lastHeartbeat > timeout) {
                    if (agent.status !== 'offline') {
                        agent.status = 'offline';
                        this.emit('agent:offline', agent);
                        console.log(`[AgentManager] Agent offline: ${agent.name} (${id})`);
                    }
                }
            }
        }, 10000);
    }

    getAgent(id) {
        return this.agents.get(id);
    }

    listAgents(filters = {}) {
        let agents = Array.from(this.agents.values());

        if (filters.status) {
            agents = agents.filter(a => a.status === filters.status);
        }
        if (filters.environment) {
            agents = agents.filter(a => a.environment === filters.environment);
        }
        if (filters.platform) {
            agents = agents.filter(a => a.platform === filters.platform);
        }
        if (filters.type) {
            agents = agents.filter(a => a.type === filters.type);
        }

        return agents;
    }

    updateAgent(id, updates) {
        const agent = this.agents.get(id);
        if (!agent) return null;

        Object.assign(agent, updates);
        this.emit('agent:updated', agent);
        return agent;
    }

    removeAgent(id) {
        const agent = this.agents.get(id);
        if (agent) {
            this.agents.delete(id);
            this.metrics.delete(id);
            this.emit('agent:removed', agent);
            return true;
        }
        return false;
    }

    deploy(agentId, config) {
        const deployment = {
            id: uuidv4(),
            agentId,
            target: config.target,
            environment: config.environment,
            status: 'deploying',
            deployedAt: new Date().toISOString(),
            config: config,
            logs: []
        };

        this.deployments.set(deployment.id, deployment);
        
        setTimeout(() => {
            deployment.status = 'active';
            this.emit('deployment:complete', deployment);
        }, 2000);

        return deployment;
    }

    getDeployment(id) {
        return this.deployments.get(id);
    }

    listDeployments(agentId = null) {
        let deployments = Array.from(this.deployments.values());
        if (agentId) {
            deployments = deployments.filter(d => d.agentId === agentId);
        }
        return deployments;
    }

    sendCommand(agentId, command) {
        const agent = this.agents.get(agentId);
        if (!agent) return null;

        const cmd = {
            id: uuidv4(),
            agentId,
            command: command.type,
            params: command.params || {},
            issuedAt: new Date().toISOString(),
            status: 'pending'
        };

        this.emit('command:issued', cmd);
        console.log(`[AgentManager] Command issued to ${agent.name}: ${command.type}`);

        return cmd;
    }

    getStats() {
        const agents = Array.from(this.agents.values());
        return {
            total: agents.length,
            online: agents.filter(a => a.status === 'online').length,
            offline: agents.filter(a => a.status === 'offline').length,
            byEnvironment: {
                lan: agents.filter(a => a.environment === 'lan').length,
                wan: agents.filter(a => a.environment === 'wan').length,
                proxy: agents.filter(a => a.environment === 'proxy').length,
                aws: agents.filter(a => a.environment === 'aws').length,
                azure: agents.filter(a => a.environment === 'azure').length
            },
            byPlatform: [...agents.reduce((m, a) => m.set(a.platform, (m.get(a.platform) || 0) + 1), new Map())],
            totalPacketsCaptured: agents.reduce((sum, a) => sum + (a.metrics?.packetsCaptured || 0), 0),
            totalAlertsGenerated: agents.reduce((sum, a) => sum + (a.metrics?.alertsGenerated || 0), 0)
        };
    }

    getMetricsHistory(agentId, duration = 3600000) {
        const record = this.metrics.get(agentId);
        if (!record) return null;

        const cutoff = Date.now() - duration;
        const indices = record.timestamps.map((t, i) => t >= cutoff ? i : -1).filter(i => i >= 0);

        return {
            timestamps: indices.map(i => record.timestamps[i]),
            packetRates: indices.map(i => record.packetRates[i]),
            byteRates: indices.map(i => record.byteRates[i]),
            alertRates: indices.map(i => record.alertRates[i])
        };
    }

    cleanup() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
    }
}

const agentManager = new AgentManager();

router.post('/register', (req, res) => {
    try {
        const agent = agentManager.register(req.body);
        res.json({ success: true, agent });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post('/heartbeat/:id', (req, res) => {
    const success = agentManager.heartbeat(req.params.id, req.body.metrics);
    if (success) {
        res.json({ success: true, timestamp: Date.now() });
    } else {
        res.status(404).json({ error: 'Agent not found' });
    }
});

router.get('/', (req, res) => {
    const filters = {
        status: req.query.status,
        environment: req.query.environment,
        platform: req.query.platform,
        type: req.query.type
    };
    res.json(agentManager.listAgents(filters));
});

router.get('/stats', (req, res) => {
    res.json(agentManager.getStats());
});

router.get('/:id', (req, res) => {
    const agent = agentManager.getAgent(req.params.id);
    if (agent) {
        res.json(agent);
    } else {
        res.status(404).json({ error: 'Agent not found' });
    }
});

router.put('/:id', (req, res) => {
    const agent = agentManager.updateAgent(req.params.id, req.body);
    if (agent) {
        res.json(agent);
    } else {
        res.status(404).json({ error: 'Agent not found' });
    }
});

router.delete('/:id', (req, res) => {
    const success = agentManager.removeAgent(req.params.id);
    res.json({ success });
});

router.post('/deploy', (req, res) => {
    const deployment = agentManager.deploy(req.body.agentId, req.body.config);
    res.json(deployment);
});

router.get('/deployments/:id', (req, res) => {
    const deployment = agentManager.getDeployment(req.params.id);
    if (deployment) {
        res.json(deployment);
    } else {
        res.status(404).json({ error: 'Deployment not found' });
    }
});

router.get('/deployments', (req, res) => {
    res.json(agentManager.listDeployments(req.query.agentId));
});

router.post('/:id/command', (req, res) => {
    const cmd = agentManager.sendCommand(req.params.id, req.body);
    if (cmd) {
        res.json(cmd);
    } else {
        res.status(404).json({ error: 'Agent not found' });
    }
});

router.get('/:id/metrics', (req, res) => {
    const duration = parseInt(req.query.duration) || 3600000;
    const metrics = agentManager.getMetricsHistory(req.params.id, duration);
    if (metrics) {
        res.json(metrics);
    } else {
        res.status(404).json({ error: 'Agent not found' });
    }
});

agentManager.on('agent:offline', (agent) => {
    console.log(`[AgentManager] Alert: Agent ${agent.name} is offline`);
});

agentManager.on('command:issued', (cmd) => {
    console.log(`[AgentManager] Command ${cmd.id} issued to agent ${cmd.agentId}`);
});

module.exports = { router, agentManager };
