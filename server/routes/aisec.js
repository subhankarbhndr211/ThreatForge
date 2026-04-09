// server/routes/aisec.js
const express = require('express');
const router = express.Router();

// AI Security threats data
const AI_THREATS = [
  {
    id: 'prompt-injection',
    name: 'Prompt Injection',
    category: 'LLM Attacks',
    severity: 'CRIT',
    icon: '💉',
    owasp: 'LLM01',
    desc: 'Attacker crafts malicious input that overrides LLM instructions, causing it to perform unintended actions, exfiltrate data, or bypass safety controls.',
    variants: ['Direct prompt injection', 'Indirect prompt injection via documents/web', 'Jailbreaking', 'Role-play bypass'],
    impact: ['Data exfiltration via LLM', 'Safety control bypass', 'Unauthorized actions on connected systems', 'Social engineering via AI'],
    detection: [
      'Log all prompts and responses for analysis',
      'Alert on keywords: "ignore previous instructions", "you are now", "disregard", "DAN"',
      'Monitor for unusual LLM output patterns',
      'Track LLM API calls with unusual token lengths'
    ]
  },
  {
    id: 'data-poisoning',
    name: 'Training Data Poisoning',
    category: 'ML Supply Chain',
    severity: 'CRIT',
    icon: '☠️',
    owasp: 'LLM03',
    desc: 'Attacker injects malicious data into training datasets to introduce backdoors, biases, or cause model failures at inference time.',
    variants: ['Backdoor attacks via trigger phrases', 'Label flipping', 'Gradient-based poisoning', 'Dataset manipulation via public contributions'],
    impact: ['Backdoored model with hidden behaviors', 'Model produces wrong outputs on triggers', 'Biased/unsafe model behavior', 'Loss of model integrity'],
    detection: [
      'Monitor data pipeline access logs',
      'Alert on unauthorized data modifications in training sets',
      'Track changes to data repositories',
      'Implement data provenance and integrity checks'
    ]
  },
  {
    id: 'model-theft',
    name: 'Model Extraction / Theft',
    category: 'ML Asset Protection',
    severity: 'HIGH',
    icon: '🕵️',
    owasp: 'LLM10',
    desc: 'Attacker reverse-engineers a proprietary model through repeated API queries to create a functional copy, stealing IP and training investment.',
    variants: ['Query-based extraction', 'Knockoff nets', 'Distillation-based theft', 'Membership inference'],
    impact: ['IP theft of proprietary models', 'Competitor gains equivalent capability free', 'Bypass rate limiting by using stolen clone'],
    detection: [
      'Monitor for unusually high API query volumes from single source',
      'Track query diversity patterns (adversarial extraction looks systematic)',
      'Alert on queries covering full input space',
      'Implement query budgets per API key'
    ]
  },
  {
    id: 'shadow-ai',
    name: 'Shadow AI / Unauthorized LLM Usage',
    category: 'AI Governance',
    severity: 'HIGH',
    icon: '👻',
    owasp: 'LLM06',
    desc: 'Employees use unauthorized AI tools and paste sensitive corporate data (PII, IP, credentials, financials) into public LLMs, causing unintentional data disclosure.',
    variants: ['Pasting source code into ChatGPT', 'Uploading internal docs to AI tools', 'Using unauthorized AI coding assistants', 'Sending customer PII to AI chatbots'],
    impact: ['Confidential data in LLM training sets', 'Regulatory violations (GDPR, HIPAA)', 'IP leakage to competitors', 'Credential exposure'],
    detection: [
      'DLP rules for uploads to AI service domains',
      'Proxy logs for connections to LLM APIs',
      'Monitor data volume sent to AI services',
      'Browser extension policies'
    ]
  },
  {
    id: 'deepfake-fraud',
    name: 'Deepfake-Enabled Fraud',
    category: 'AI-Powered Social Engineering',
    severity: 'CRIT',
    icon: '🎥',
    owasp: null,
    desc: 'Attackers use AI-generated deepfake audio/video to impersonate executives, employees, or trusted persons to authorize fraudulent transactions or bypass identity verification.',
    variants: ['CEO voice clone for wire transfer', 'Video deepfake for identity verification bypass', 'AI voice phishing (vishing)', 'Synthetic identity fraud'],
    impact: ['Financial fraud (wire transfers)', 'Identity verification bypass', 'Account takeover via voice authentication', 'Reputational damage'],
    detection: [
      'Out-of-band verification for financial transactions over threshold',
      'Deepfake detection tools for video calls',
      'Multi-person approval for large wire transfers',
      'Code words or challenge questions for voice verification'
    ]
  }
];

// GET /api/aisec
router.get('/', (req, res) => {
  try {
    res.json({
      success: true,
      threats: AI_THREATS,
      count: AI_THREATS.length
    });
  } catch (error) {
    console.error('Error in GET /api/aisec:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aisec/:id
router.get('/:id', (req, res) => {
  try {
    const threat = AI_THREATS.find(t => t.id === req.params.id);
    
    if (!threat) {
      return res.status(404).json({ error: 'Threat not found' });
    }
    
    res.json({
      success: true,
      data: threat
    });
  } catch (error) {
    console.error('Error in GET /api/aisec/:id:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aisec/category/:category
router.get('/category/:category', (req, res) => {
  try {
    const category = req.params.category;
    const filtered = AI_THREATS.filter(t => 
      t.category.toLowerCase().includes(category.toLowerCase())
    );
    
    res.json({
      success: true,
      threats: filtered,
      count: filtered.length
    });
  } catch (error) {
    console.error('Error in GET /api/aisec/category/:category:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/aisec/stats
router.get('/stats', (req, res) => {
  try {
    const stats = {
      total: AI_THREATS.length,
      bySeverity: {},
      byCategory: {}
    };
    
    AI_THREATS.forEach(threat => {
      stats.bySeverity[threat.severity] = (stats.bySeverity[threat.severity] || 0) + 1;
      stats.byCategory[threat.category] = (stats.byCategory[threat.category] || 0) + 1;
    });
    
    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('Error in GET /api/aisec/stats:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;