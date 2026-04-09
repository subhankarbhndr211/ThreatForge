const express = require('express');
const router = express.Router();

const AI_SERVICE_URL = 'http://localhost:8001';

router.post('/analyze', async (req, res) => {
    try {
        const response = await fetch(`${AI_SERVICE_URL}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });
        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error('AI service error:', error);
        res.status(503).json({ 
            error: 'AI service unavailable',
            ai_score: 0,
            risk_level: 'Unknown',
            confidence: 'Low'
        });
    }
});

router.post('/chat', async (req, res) => {
    try {
        const { message } = req.body;
        
        // Simple keyword-based response for demo
        const lowerMsg = message.toLowerCase();
        let response = "I'm analyzing the threat landscape...";
        
        if (lowerMsg.includes('apt') || lowerMsg.includes('group')) {
            response = "Recent APT groups exploiting zero-days include Lazarus (North Korea), APT29 (Russia), and APT41 (China). They're targeting vulnerabilities in Exchange, Log4j, and VPN appliances.";
        } else if (lowerMsg.includes('query') || lowerMsg.includes('detection')) {
            response = "Here's a Splunk query for recent exploits: `index=* (sourcetype=WinEventLog:Security EventCode=4625) OR (sourcetype=linux_secure failed password)`";
        } else if (lowerMsg.includes('cve') || lowerMsg.includes('vulnerability')) {
            response = "Top critical CVEs being exploited: CVE-2025-55182 (React), CVE-2020-1472 (Zerologon), CVE-2025-8088 (WinRAR)";
        }
        
        res.json({
            response: response,
            confidence: "Medium",
            sources: ["Zero-Day Intelligence"]
        });
    } catch (error) {
        res.json({
            response: "I'm in offline mode. Please ensure the AI service is running.",
            confidence: "Low",
            sources: []
        });
    }
});

module.exports = router;