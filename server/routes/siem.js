// server/routes/siem.js
const express = require('express');
const router = express.Router();
const axios = require('axios');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// Store active SIEM connections
const activeConnections = new Map();

// SIEM connection configurations
const SIEM_CONFIGS = {
    splunk: {
        name: 'Splunk',
        type: 'SIEM',
        fields: ['url', 'token', 'index'],
        validate: async (config) => {
            try {
                const response = await axios.post(`${config.url}/services/collector/event`, 
                    { event: 'test', sourcetype: 'manual' },
                    { headers: { Authorization: `Splunk ${config.token}` }, timeout: 5000 }
                );
                return { success: true, message: 'Connected to Splunk successfully' };
            } catch (error) {
                return { success: false, message: `Splunk connection failed: ${error.message}` };
            }
        }
    },
    sentinel: {
        name: 'Microsoft Sentinel',
        type: 'SIEM',
        fields: ['workspaceId', 'primaryKey', 'tenantId'],
        validate: async (config) => {
            try {
                // Test Azure Log Analytics connection
                const response = await axios.post(
                    `https://api.loganalytics.io/v1/workspaces/${config.workspaceId}/query`,
                    { query: 'Heartbeat | take 1' },
                    { 
                        headers: { 
                            'Authorization': `Bearer ${config.primaryKey}`,
                            'Content-Type': 'application/json'
                        },
                        timeout: 5000
                    }
                );
                return { success: true, message: 'Connected to Sentinel successfully' };
            } catch (error) {
                return { success: false, message: `Sentinel connection failed: ${error.message}` };
            }
        }
    },
    crowdstrike: {
        name: 'CrowdStrike Falcon',
        type: 'EDR',
        fields: ['clientId', 'clientSecret', 'cloud'],
        validate: async (config) => {
            try {
                const response = await axios.post(
                    `https://api.${config.cloud}.crowdstrike.com/oauth2/token`,
                    `client_id=${config.clientId}&client_secret=${config.clientSecret}`,
                    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 5000 }
                );
                return { success: true, message: 'Connected to CrowdStrike successfully' };
            } catch (error) {
                return { success: false, message: `CrowdStrike connection failed: ${error.message}` };
            }
        }
    },
    defender: {
        name: 'Microsoft Defender XDR',
        type: 'XDR',
        fields: ['tenantId', 'clientId', 'clientSecret'],
        validate: async (config) => {
            try {
                const response = await axios.post(
                    `https://login.microsoftonline.com/${config.tenantId}/oauth2/token`,
                    {
                        grant_type: 'client_credentials',
                        client_id: config.clientId,
                        client_secret: config.clientSecret,
                        resource: 'https://api.security.microsoft.com'
                    },
                    { timeout: 5000 }
                );
                return { success: true, message: 'Connected to Defender XDR successfully' };
            } catch (error) {
                return { success: false, message: `Defender connection failed: ${error.message}` };
            }
        }
    },
    elastic: {
        name: 'Elastic SIEM',
        type: 'SIEM',
        fields: ['url', 'apiKey', 'index'],
        validate: async (config) => {
            try {
                const response = await axios.get(`${config.url}/_cluster/health`,
                    { headers: { Authorization: `ApiKey ${config.apiKey}` }, timeout: 5000 }
                );
                return { success: true, message: 'Connected to Elastic successfully' };
            } catch (error) {
                return { success: false, message: `Elastic connection failed: ${error.message}` };
            }
        }
    },
    qradar: {
        name: 'IBM QRadar',
        type: 'SIEM',
        fields: ['url', 'apiToken', 'version'],
        validate: async (config) => {
            try {
                const response = await axios.get(`${config.url}/api/system/about`,
                    { headers: { SEC: config.apiToken }, timeout: 5000 }
                );
                return { success: true, message: 'Connected to QRadar successfully' };
            } catch (error) {
                return { success: false, message: `QRadar connection failed: ${error.message}` };
            }
        }
    },
    chronicle: {
        name: 'Google Chronicle',
        type: 'SIEM',
        fields: ['projectId', 'region', 'credentials'],
        validate: async (config) => {
            try {
                // Write credentials to temp file and test
                const credFile = `/tmp/chronicle-${Date.now()}.json`;
                await execPromise(`echo '${config.credentials}' > ${credFile}`);
                const response = await execPromise(
                    `gcloud auth activate-service-account --key-file=${credFile} && ` +
                    `gcloud config set project ${config.projectId}`
                );
                await execPromise(`rm ${credFile}`);
                return { success: true, message: 'Connected to Chronicle successfully' };
            } catch (error) {
                return { success: false, message: `Chronicle connection failed: ${error.message}` };
            }
        }
    },
    datadog: {
        name: 'Datadog SIEM',
        type: 'SIEM',
        fields: ['site', 'apiKey', 'appKey'],
        validate: async (config) => {
            try {
                const response = await axios.get(
                    `https://api.${config.site}/api/v1/validate`,
                    { headers: { 'DD-API-KEY': config.apiKey, 'DD-APPLICATION-KEY': config.appKey }, timeout: 5000 }
                );
                return { success: true, message: 'Connected to Datadog successfully' };
            } catch (error) {
                return { success: false, message: `Datadog connection failed: ${error.message}` };
            }
        }
    },
    sentinelone: {
        name: 'SentinelOne',
        type: 'EDR',
        fields: ['url', 'apiToken'],
        validate: async (config) => {
            try {
                const response = await axios.get(`${config.url}/web/api/v2.1/system/info`,
                    { headers: { Authorization: `ApiToken ${config.apiToken}` }, timeout: 5000 }
                );
                return { success: true, message: 'Connected to SentinelOne successfully' };
            } catch (error) {
                return { success: false, message: `SentinelOne connection failed: ${error.message}` };
            }
        }
    },
    paloalto: {
        name: 'Palo Alto XSIAM',
        type: 'XDR',
        fields: ['url', 'apiKey', 'keyId'],
        validate: async (config) => {
            try {
                const response = await axios.get(`${config.url}/public_api/v1/agents`,
                    { headers: { 'x-xdr-auth-id': config.keyId, Authorization: config.apiKey }, timeout: 5000 }
                );
                return { success: true, message: 'Connected to XSIAM successfully' };
            } catch (error) {
                return { success: false, message: `XSIAM connection failed: ${error.message}` };
            }
        }
    }
};

// Connect to SIEM/EDR tool
router.post('/connect', async (req, res) => {
    const { tool, config } = req.body;
    
    if (!SIEM_CONFIGS[tool]) {
        return res.status(400).json({ success: false, message: 'Unknown tool' });
    }

    try {
        const result = await SIEM_CONFIGS[tool].validate(config);
        if (result.success) {
            const connectionId = `${tool}-${Date.now()}`;
            activeConnections.set(connectionId, { tool, config, connectedAt: new Date() });
            
            // Log successful connection
            console.log(`✅ SIEM Connected: ${tool} at ${new Date().toISOString()}`);
            
            res.json({ 
                success: true, 
                message: result.message,
                connectionId,
                status: 'connected'
            });
        } else {
            res.status(400).json({ success: false, message: result.message });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Get connection status
router.get('/status', (req, res) => {
    const connections = Array.from(activeConnections.entries()).map(([id, conn]) => ({
        id,
        tool: conn.tool,
        name: SIEM_CONFIGS[conn.tool].name,
        type: SIEM_CONFIGS[conn.tool].type,
        connectedAt: conn.connectedAt
    }));
    
    res.json({
        success: true,
        connections,
        count: connections.length
    });
});

// Disconnect from SIEM/EDR
router.post('/disconnect/:connectionId', (req, res) => {
    const { connectionId } = req.params;
    
    if (activeConnections.delete(connectionId)) {
        console.log(`❌ SIEM Disconnected: ${connectionId} at ${new Date().toISOString()}`);
        res.json({ success: true, message: 'Disconnected successfully' });
    } else {
        res.status(404).json({ success: false, message: 'Connection not found' });
    }
});

// Execute SIEM query
router.post('/query', async (req, res) => {
    const { connectionId, query, timeRange } = req.body;
    
    const connection = activeConnections.get(connectionId);
    if (!connection) {
        return res.status(404).json({ success: false, message: 'No active connection' });
    }

    try {
        let results;
        const { tool, config } = connection;

        switch (tool) {
            case 'splunk':
                results = await executeSplunkQuery(config, query, timeRange);
                break;
            case 'sentinel':
                results = await executeSentinelQuery(config, query, timeRange);
                break;
            case 'crowdstrike':
                results = await executeCrowdStrikeQuery(config, query);
                break;
            case 'defender':
                results = await executeDefenderQuery(config, query, timeRange);
                break;
            case 'elastic':
                results = await executeElasticQuery(config, query, timeRange);
                break;
            case 'qradar':
                results = await executeQRadarQuery(config, query, timeRange);
                break;
            case 'chronicle':
                results = await executeChronicleQuery(config, query, timeRange);
                break;
            case 'datadog':
                results = await executeDatadogQuery(config, query, timeRange);
                break;
            case 'sentinelone':
                results = await executeSentinelOneQuery(config, query);
                break;
            case 'paloalto':
                results = await executeXSIAMQuery(config, query, timeRange);
                break;
            default:
                results = { error: 'Unsupported tool for queries' };
        }

        res.json({ success: true, results });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Query execution functions
async function executeSplunkQuery(config, query, timeRange) {
    const response = await axios.post(
        `${config.url}/services/search/jobs`,
        { search: `search ${query} | head 100`, earliest_time: timeRange || '-24h' },
        { headers: { Authorization: `Splunk ${config.token}` } }
    );
    return response.data;
}

async function executeSentinelQuery(config, query, timeRange) {
    const response = await axios.post(
        `https://api.loganalytics.io/v1/workspaces/${config.workspaceId}/query`,
        { query: query },
        { headers: { Authorization: `Bearer ${config.primaryKey}` } }
    );
    return response.data;
}

async function executeCrowdStrikeQuery(config, query) {
    const auth = await axios.post(
        `https://api.${config.cloud}.crowdstrike.com/oauth2/token`,
        `client_id=${config.clientId}&client_secret=${config.clientSecret}`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    
    const response = await axios.get(
        `https://api.${config.cloud}.crowdstrike.com/detects/queries/detects/v1`,
        { headers: { Authorization: `Bearer ${auth.data.access_token}` } }
    );
    return response.data;
}

async function executeDefenderQuery(config, query, timeRange) {
    const auth = await axios.post(
        `https://login.microsoftonline.com/${config.tenantId}/oauth2/token`,
        {
            grant_type: 'client_credentials',
            client_id: config.clientId,
            client_secret: config.clientSecret,
            resource: 'https://api.security.microsoft.com'
        }
    );

    const response = await axios.post(
        'https://api.security.microsoft.com/api/advancedhunting/run',
        { Query: query },
        { headers: { Authorization: `Bearer ${auth.data.access_token}` } }
    );
    return response.data;
}

async function executeElasticQuery(config, query, timeRange) {
    const response = await axios.post(
        `${config.url}/${config.index}/_search`,
        {
            query: {
                query_string: { query: query }
            },
            size: 100
        },
        { headers: { Authorization: `ApiKey ${config.apiKey}` } }
    );
    return response.data;
}

async function executeQRadarQuery(config, query, timeRange) {
    const response = await axios.get(
        `${config.url}/api/ariel/searches`,
        {
            params: { query_expression: query },
            headers: { SEC: config.apiToken }
        }
    );
    return response.data;
}

async function executeChronicleQuery(config, query, timeRange) {
    const credFile = `/tmp/chronicle-${Date.now()}.json`;
    await execPromise(`echo '${config.credentials}' > ${credFile}`);
    
    const response = await execPromise(
        `gcloud auth activate-service-account --key-file=${credFile} && ` +
        `gcloud alpha chronicle search "${query}"`
    );
    
    await execPromise(`rm ${credFile}`);
    return { results: response.stdout };
}

async function executeDatadogQuery(config, query, timeRange) {
    const response = await axios.get(
        `https://api.${config.site}/api/v1/logs-queries/list`,
        {
            params: { query: query, time: timeRange || 'now-1h' },
            headers: { 
                'DD-API-KEY': config.apiKey,
                'DD-APPLICATION-KEY': config.appKey
            }
        }
    );
    return response.data;
}

async function executeSentinelOneQuery(config, query) {
    const response = await axios.get(
        `${config.url}/web/api/v2.1/threats`,
        { headers: { Authorization: `ApiToken ${config.apiToken}` } }
    );
    return response.data;
}

async function executeXSIAMQuery(config, query, timeRange) {
    const response = await axios.get(
        `${config.url}/public_api/v1/xql/query`,
        {
            params: { query: query, from: timeRange || '-24h' },
            headers: { 
                'x-xdr-auth-id': config.keyId,
                Authorization: config.apiKey
            }
        }
    );
    return response.data;
}

// Get real-time alerts from connected SIEMs
router.get('/alerts/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendAlert = (alert) => {
        res.write(`data: ${JSON.stringify(alert)}\n\n`);
    };

    // Poll connected SIEMs for new alerts
    const interval = setInterval(async () => {
        for (const [id, conn] of activeConnections) {
            try {
                const alerts = await fetchAlertsFromSIEM(conn);
                alerts.forEach(alert => sendAlert(alert));
            } catch (error) {
                console.error(`Error fetching alerts from ${conn.tool}:`, error.message);
            }
        }
    }, 30000); // Poll every 30 seconds

    req.on('close', () => {
        clearInterval(interval);
        res.end();
    });
});

async function fetchAlertsFromSIEM(connection) {
    const { tool, config } = connection;
    
    try {
        switch (tool) {
            case 'splunk':
                return await fetchSplunkAlerts(config);
            case 'sentinel':
                return await fetchSentinelAlerts(config);
            case 'crowdstrike':
                return await fetchCrowdStrikeAlerts(config);
            case 'defender':
                return await fetchDefenderAlerts(config);
            default:
                return [];
        }
    } catch (error) {
        console.error(`Error in fetchAlertsFromSIEM for ${tool}:`, error.message);
        return [];
    }
}

async function fetchSplunkAlerts(config) {
    const response = await axios.get(
        `${config.url}/services/alerts/fired_alerts`,
        { headers: { Authorization: `Splunk ${config.token}` } }
    );
    return response.data.entry || [];
}

async function fetchSentinelAlerts(config) {
    const response = await axios.post(
        `https://api.loganalytics.io/v1/workspaces/${config.workspaceId}/query`,
        { query: 'SecurityAlert | where TimeGenerated > ago(5m) | take 50' },
        { headers: { Authorization: `Bearer ${config.primaryKey}` } }
    );
    return response.data.tables[0]?.rows || [];
}

async function fetchCrowdStrikeAlerts(config) {
    const auth = await axios.post(
        `https://api.${config.cloud}.crowdstrike.com/oauth2/token`,
        `client_id=${config.clientId}&client_secret=${config.clientSecret}`,
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    
    const response = await axios.get(
        `https://api.${config.cloud}.crowdstrike.com/detects/entities/detects/v1`,
        { headers: { Authorization: `Bearer ${auth.data.access_token}` } }
    );
    return response.data.resources || [];
}

async function fetchDefenderAlerts(config) {
    const auth = await axios.post(
        `https://login.microsoftonline.com/${config.tenantId}/oauth2/token`,
        {
            grant_type: 'client_credentials',
            client_id: config.clientId,
            client_secret: config.clientSecret,
            resource: 'https://api.security.microsoft.com'
        }
    );

    const response = await axios.get(
        'https://api.security.microsoft.com/api/alerts',
        { headers: { Authorization: `Bearer ${auth.data.access_token}` } }
    );
    return response.data.value || [];
}

module.exports = router;