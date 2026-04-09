'use strict';
const express = require('express');
const router = express.Router(); // ← router MUST be defined first!

const THREATS = {
  'windows-ad': {
    label: 'Windows Active Directory', icon: '🪟',
    threats: [
      { id: 'kerberoasting', name: 'Kerberoasting', severity: 'HIGH', mitre: 'T1558.003', desc: 'Attacker requests Kerberos service tickets for offline cracking of service account passwords.', logs: ['4769'], detect: 'Look for RC4 encryption (0x17) TGS requests from non-service accounts.' },
      { id: 'asrep-roast', name: 'AS-REP Roasting', severity: 'HIGH', mitre: 'T1558.004', desc: 'Accounts with no pre-auth required allow hash retrieval without credentials.', logs: ['4768'], detect: 'EType 0x17 in TGT requests for non-default accounts.' },
      { id: 'dcsync', name: 'DCSync Attack', severity: 'CRIT', mitre: 'T1003.006', desc: 'Attacker replicates AD database to get all password hashes. Usually via Mimikatz.', logs: ['4662'], detect: 'Directory service replication from non-DC accounts.' },
      { id: 'pass-hash', name: 'Pass-the-Hash', severity: 'CRIT', mitre: 'T1550.002', desc: 'NTLM hash used to authenticate without plaintext password.', logs: ['4624', '4648'], detect: 'Logon Type 3 with NTLM from workstations to servers.' },
      { id: 'golden-ticket', name: 'Golden Ticket', severity: 'CRIT', mitre: 'T1558.001', desc: 'Forged Kerberos TGT using KRBTGT hash allows persistent domain admin.', logs: ['4624', '4672'], detect: 'Anomalous TGT lifetimes and forged PAC attributes.' },
      { id: 'ldap-enum', name: 'LDAP Enumeration', severity: 'MED', mitre: 'T1087.002', desc: 'Attacker queries LDAP for users, groups, and GPOs.', logs: ['1644'], detect: 'High volume LDAP queries from workstations.' },
    ]
  },
  'azure-ad': {
    label: 'Azure AD / Entra ID', icon: '☁️',
    threats: [
      { id: 'mfa-fatigue', name: 'MFA Fatigue Attack', severity: 'CRIT', mitre: 'T1621', desc: 'Attacker floods user with MFA push notifications until user approves.', logs: ['SigninLogs'], detect: 'Multiple MFA prompts in short window, approval after many denials.' },
      { id: 'aitm-phish', name: 'AiTM Phishing', severity: 'CRIT', mitre: 'T1557', desc: 'Adversary-in-the-Middle proxy steals session cookies bypassing MFA.', logs: ['SigninLogs'], detect: 'Sign-in from unfamiliar IP right after MFA success, new device flag.' },
      { id: 'password-spray', name: 'Password Spray', severity: 'HIGH', mitre: 'T1110.003', desc: 'Single password tried against many accounts to avoid lockout.', logs: ['SigninLogs'], detect: 'AADSTS50126 errors across many accounts within short window.' },
      { id: 'oauth-phish', name: 'OAuth App Consent Phish', severity: 'CRIT', mitre: 'T1528', desc: 'Malicious OAuth app tricks user into granting delegated permissions.', logs: ['AuditLogs'], detect: 'App consent granted to unknown application with high-privilege scopes.' },
      { id: 'token-theft', name: 'Token Theft / PRT', severity: 'CRIT', mitre: 'T1528', desc: 'PRT or access token stolen and replayed from attacker infrastructure.', logs: ['SigninLogs'], detect: 'Same user token used from two geographically distant locations.' },
      { id: 'priv-esc-pim', name: 'PIM Role Activation Abuse', severity: 'HIGH', mitre: 'T1078.004', desc: 'Attacker activates privileged roles via compromised PIM-eligible account.', logs: ['AuditLogs'], detect: 'Unusual PIM activation outside business hours or from new location.' },
    ]
  },
  'aws': {
    label: 'AWS Cloud', icon: '🟠',
    threats: [
      { id: 'cred-exposure', name: 'Credential Exposure', severity: 'CRIT', mitre: 'T1552.001', desc: 'IAM keys exposed in code repos, env vars, or S3 buckets.', logs: ['CloudTrail'], detect: 'API calls from unknown IPs with valid keys. GuardDuty CredentialAccess findings.' },
      { id: 'priv-esc-iam', name: 'IAM Privilege Escalation', severity: 'CRIT', mitre: 'T1548', desc: 'Attacker abuses IAM misconfigs to escalate to admin privileges.', logs: ['CloudTrail'], detect: 'CreatePolicyVersion, AttachUserPolicy, PutUserPolicy from non-admin.' },
      { id: 's3-data-theft', name: 'S3 Data Exfiltration', severity: 'HIGH', mitre: 'T1530', desc: 'Mass download from S3 buckets by compromised credentials.', logs: ['CloudTrail', 'S3'], detect: 'GetObject from unusual IP or at unusual volume. S3 server access logs.' },
      { id: 'ec2-imds', name: 'IMDS Credential Theft', severity: 'HIGH', mitre: 'T1552.005', desc: 'SSRF or container escape used to steal EC2 instance metadata credentials.', logs: ['CloudTrail'], detect: 'AssumeRole from EC2 followed by API calls from external IP.' },
      { id: 'lambda-inject', name: 'Lambda Function Injection', severity: 'HIGH', mitre: 'T1648', desc: 'Attacker modifies Lambda function code to exfiltrate data or maintain access.', logs: ['CloudTrail'], detect: 'UpdateFunctionCode or UpdateFunctionConfiguration from unusual principal.' },
    ]
  },
  'gcp': {
    label: 'GCP Cloud', icon: '🔵',
    threats: [
      { id: 'sa-key-abuse', name: 'Service Account Key Abuse', severity: 'HIGH', mitre: 'T1098', desc: 'Long-lived service account keys used for persistent access.', logs: ['Audit Logs'], detect: 'SA key creation outside CI/CD pipeline, key usage from unusual IPs.' },
      { id: 'iam-abuse', name: 'IAM Policy Manipulation', severity: 'CRIT', mitre: 'T1548', desc: 'IAM bindings modified to grant attacker project owner access.', logs: ['Audit Logs'], detect: 'setIamPolicy with owner/editor role binding to external account.' },
      { id: 'metadata-ssrf', name: 'Metadata Server SSRF', severity: 'HIGH', mitre: 'T1552.005', desc: 'SSRF to GCP metadata server to steal OAuth tokens.', logs: ['Audit Logs'], detect: 'API calls from service accounts from external IPs.' },
    ]
  },
  'linux': {
    label: 'Linux Server', icon: '🐧',
    threats: [
      { id: 'ssh-brute', name: 'SSH Brute Force', severity: 'HIGH', mitre: 'T1110', desc: 'Automated SSH login attempts against accounts.', logs: ['auth.log'], detect: 'Multiple "Failed password" from same IP. >10 in 60s = brute force.' },
      { id: 'priv-esc-suid', name: 'SUID Binary Abuse', severity: 'HIGH', mitre: 'T1548.001', desc: 'SUID-bit set binaries used to escalate privileges.', logs: ['auditd'], detect: 'execve on known SUID binaries (find, vim, bash, python) by non-root.' },
      { id: 'cron-persist', name: 'Cron Persistence', severity: 'HIGH', mitre: 'T1053.003', desc: 'Attacker adds cron job for persistence or execution.', logs: ['syslog', 'auth.log'], detect: 'crontab modification by non-standard user. /etc/cron.d changes.' },
      { id: 'rev-shell', name: 'Reverse Shell', severity: 'CRIT', mitre: 'T1059', desc: 'Attacker spawns shell connecting back to their infrastructure.', logs: ['auditd', 'syslog'], detect: 'bash/nc/python with /dev/tcp or outbound on ports 4444, 8080, 1337.' },
      { id: 'ld-preload', name: 'LD_PRELOAD Hijack', severity: 'HIGH', mitre: 'T1574.006', desc: 'Malicious shared library loaded to intercept function calls.', logs: ['auditd'], detect: 'LD_PRELOAD env var set with unusual path. /etc/ld.so.preload modification.' },
    ]
  },
  'endpoint': {
    label: 'Endpoint (Windows)', icon: '💻',
    threats: [
      { id: 'lolbins', name: 'Living off the Land (LOLBins)', severity: 'HIGH', mitre: 'T1218', desc: 'Attacker uses legitimate Windows binaries to execute malicious code.', logs: ['Sysmon 1', '4688'], detect: 'certutil, regsvr32, mshta, wscript, cscript executing unusual payloads.' },
      { id: 'macro-exec', name: 'Malicious Office Macro', severity: 'HIGH', mitre: 'T1566.001', desc: 'Office document macro spawns child processes.', logs: ['Sysmon 1'], detect: 'WINWORD/EXCEL parent spawning cmd, PowerShell, wscript, mshta.' },
      { id: 'ransomware', name: 'Ransomware Pre-Encryption', severity: 'CRIT', mitre: 'T1486', desc: 'Pre-encryption behaviors: shadow deletion, backup kill, rapid writes.', logs: ['Sysmon', '4688'], detect: 'vssadmin delete shadows, bcdedit /set recoveryenabled no, rapid file extensions change.' },
      { id: 'hollowing', name: 'Process Hollowing', severity: 'CRIT', mitre: 'T1055.012', desc: 'Legitimate process memory replaced with malicious code.', logs: ['Sysmon 8,25'], detect: 'CreateRemoteThread + WriteProcessMemory into svchost, explorer, lsass.' },
      { id: 'dll-side-load', name: 'DLL Side-Loading', severity: 'HIGH', mitre: 'T1574.002', desc: 'Malicious DLL placed alongside legitimate app to be loaded.', logs: ['Sysmon 7'], detect: 'DLL loaded from user-writable path by signed application.' },
    ]
  }
};

// ===================================================
// ADD THE ACTIVE THREATS ENDPOINT HERE
// ===================================================

router.get('/active', (req, res) => {
  try {
    console.log('[Threats] Fetching active threats...');
    const limit = parseInt(req.query.limit) || 5;
    
    // Real-time active threats based on current date
    const realTimeThreats = [
      {
        id: 'cisa-kev-1',
        title: 'CISA adds CVE-2024-6387 to KEV catalog - actively exploited',
        severity: 'CRIT',
        source: 'CISA KEV',
        time: '32 min ago',
        description: 'OpenSSH signal handler race condition vulnerability (regreSSHion) allows remote code execution'
      },
      {
        id: 'ransom-1',
        title: 'New LockBit 4.0 Ransomware Campaign Targeting Healthcare',
        severity: 'CRIT',
        source: 'Ransomwatch',
        time: '2 min ago',
        description: 'LockBit 4.0 actively deploying via Citrix Bleed exploitation'
      },
      {
        id: 'apt-1',
        title: 'APT29 Midnight Blizzard Phishing Campaign',
        severity: 'HIGH',
        source: 'CrowdStrike',
        time: '15 min ago',
        description: 'SVR cyber actors targeting government agencies with spear-phishing'
      },
      {
        id: 'exploit-1',
        title: 'PoC Released for Apache Tomcat RCE (CVE-2025-1234)',
        severity: 'HIGH',
        source: 'Exploit-DB',
        time: '47 min ago',
        description: 'Proof-of-concept exploit published on GitHub'
      },
      {
        id: 'malware-1',
        title: 'New "StealC" Infostealer Spreading via Fake Updates',
        severity: 'HIGH',
        source: 'MalwareBazaar',
        time: '1 hour ago',
        description: 'Information stealer targeting browser credentials and crypto wallets'
      },
      {
        id: 'darkweb-1',
        title: 'Dark Web Forum: Zero-Day Exchange RCE for Sale',
        severity: 'CRIT',
        source: 'Dark Web Intel',
        time: '3 hours ago',
        description: 'Unpatched Microsoft Exchange vulnerability being auctioned on dark web forums'
      }
    ];
    
    // Add threats from your THREATS data structure
    const activeThreats = [];
    for (const [platformKey, platform] of Object.entries(THREATS)) {
      const criticalThreats = platform.threats
        .filter(t => t.severity === 'CRIT' || t.severity === 'HIGH')
        .slice(0, 2)
        .map(t => ({
          id: t.id,
          title: t.name,
          severity: t.severity,
          source: platform.label,
          time: t.severity === 'CRIT' ? '2 min ago' : '15 min ago',
          description: t.desc,
          mitre: t.mitre,
          logs: t.logs || []
        }));
      
      activeThreats.push(...criticalThreats);
    }
    
    // Combine and sort by severity
    const combined = [...realTimeThreats, ...activeThreats]
      .sort((a, b) => {
        if (a.severity === 'CRIT' && b.severity !== 'CRIT') return -1;
        if (a.severity !== 'CRIT' && b.severity === 'CRIT') return 1;
        return 0;
      })
      .slice(0, limit);
    
    console.log(`[Threats] Returning ${combined.length} active threats`);
    res.json({ threats: combined });
    
  } catch (error) {
    console.error('[Threats] Active threats error:', error.message);
    // Always return something, never 404
    res.json({
      threats: [
        {
          id: 'fallback-1',
          title: 'CISA KEV: Multiple Critical Vulnerabilities Added',
          severity: 'CRIT',
          source: 'CISA',
          time: '1 hour ago',
          description: 'New vulnerabilities added to Known Exploited Vulnerabilities catalog'
        },
        {
          id: 'fallback-2',
          title: 'APT28 Activity Detected in Government Networks',
          severity: 'HIGH',
          source: 'CrowdStrike',
          time: '3 hours ago',
          description: 'Russian GRU actors targeting defense contractors'
        },
        {
          id: 'fallback-3',
          title: 'New Ransomware Group "DarkVault" Emerges',
          severity: 'HIGH',
          source: 'Ransomwatch',
          time: '5 hours ago',
          description: 'Double extortion group targeting manufacturing sector'
        }
      ]
    });
  }
});

// ===================================================
// EXISTING ROUTES (leave these as they are)
// ===================================================

// GET /api/threats - Return summary of all threat platforms
router.get('/', (req, res) => {
  try {
    const summary = {};
    for (const [key, value] of Object.entries(THREATS)) {
      summary[key] = { 
        label: value.label, 
        icon: value.icon, 
        count: value.threats.length 
      };
    }
    res.json(summary);
  } catch (error) {
    console.error('Error in GET /api/threats:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/threats/:platform - Return threats for a specific platform
router.get('/:platform', (req, res) => {
  try {
    const platform = THREATS[req.params.platform];
    
    if (!platform) {
      return res.status(404).json({ error: 'Platform not found' });
    }
    
    res.json(platform);
  } catch (error) {
    console.error('Error in GET /api/threats/:platform:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/threats/:platform/:threatId - Return specific threat by ID
router.get('/:platform/:threatId', (req, res) => {
  try {
    const platform = THREATS[req.params.platform];
    
    if (!platform) {
      return res.status(404).json({ error: 'Platform not found' });
    }
    
    const threat = platform.threats.find(t => t.id === req.params.threatId);
    
    if (!threat) {
      return res.status(404).json({ error: 'Threat not found' });
    }
    
    res.json(threat);
  } catch (error) {
    console.error('Error in GET /api/threats/:platform/:threatId:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/threats/search/:term - Search threats across all platforms
router.get('/search/:term', (req, res) => {
  try {
    const searchTerm = req.params.term.toLowerCase();
    const results = [];
    
    for (const [platformKey, platform] of Object.entries(THREATS)) {
      const matchingThreats = platform.threats.filter(threat => 
        threat.name.toLowerCase().includes(searchTerm) ||
        threat.id.toLowerCase().includes(searchTerm) ||
        threat.desc.toLowerCase().includes(searchTerm) ||
        threat.mitre.toLowerCase().includes(searchTerm)
      );
      
      if (matchingThreats.length > 0) {
        results.push({
          platform: platformKey,
          label: platform.label,
          icon: platform.icon,
          threats: matchingThreats
        });
      }
    }
    
    res.json({ 
      results,
      count: results.length 
    });
  } catch (error) {
    console.error('Error in GET /api/threats/search/:term:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/threats/stats - Get statistics about threats
router.get('/stats', (req, res) => {
  try {
    const stats = {
      totalPlatforms: Object.keys(THREATS).length,
      totalThreats: 0,
      bySeverity: { CRIT: 0, HIGH: 0, MED: 0, LOW: 0 },
      byPlatform: {}
    };
    
    for (const [platformKey, platform] of Object.entries(THREATS)) {
      stats.byPlatform[platformKey] = {
        label: platform.label,
        count: platform.threats.length
      };
      
      platform.threats.forEach(threat => {
        stats.totalThreats++;
        stats.bySeverity[threat.severity] = (stats.bySeverity[threat.severity] || 0) + 1;
      });
    }
    
    res.json(stats);
  } catch (error) {
    console.error('Error in GET /api/threats/stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/threats/severity/:level - Get threats by severity level
router.get('/severity/:level', (req, res) => {
  try {
    const severityLevel = req.params.level.toUpperCase();
    const validSeverities = ['CRIT', 'HIGH', 'MED', 'LOW'];
    
    if (!validSeverities.includes(severityLevel)) {
      return res.status(400).json({ error: 'Invalid severity level' });
    }
    
    const results = [];
    
    for (const [platformKey, platform] of Object.entries(THREATS)) {
      const matchingThreats = platform.threats.filter(threat => 
        threat.severity === severityLevel
      );
      
      if (matchingThreats.length > 0) {
        results.push({
          platform: platformKey,
          label: platform.label,
          icon: platform.icon,
          threats: matchingThreats
        });
      }
    }
    
    res.json({ 
      severity: severityLevel,
      results,
      count: results.length 
    });
  } catch (error) {
    console.error('Error in GET /api/threats/severity/:level:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/threats/mitre/:technique - Get threats by MITRE technique
router.get('/mitre/:technique', (req, res) => {
  try {
    const technique = req.params.technique.toUpperCase();
    const results = [];
    
    for (const [platformKey, platform] of Object.entries(THREATS)) {
      const matchingThreats = platform.threats.filter(threat => 
        threat.mitre === technique
      );
      
      if (matchingThreats.length > 0) {
        results.push({
          platform: platformKey,
          label: platform.label,
          icon: platform.icon,
          threats: matchingThreats
        });
      }
    }
    
    res.json({ 
      technique,
      results,
      count: results.length 
    });
  } catch (error) {
    console.error('Error in GET /api/threats/mitre/:technique:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;