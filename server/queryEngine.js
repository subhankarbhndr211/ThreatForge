'use strict';

const SEV_SCORE = { LOW: 40, MED: 60, HIGH: 80, CRIT: 95 };

function clean(str) {
  return String(str).replace(/[`\\]/g, "'").replace(/"/g, "'").slice(0, 400);
}

function now() {
  return new Date().toISOString().slice(0, 19) + 'Z';
}

// ── All Platform Generators ─────────────────────────────────────────────────

const generators = {

  // ── SIEM ──────────────────────────────────────────────────────────────────

  splunk: (ctx, sev) => ({
    platform: 'Splunk',
    language: 'SPL',
    type: 'SIEM',
    icon: '🔍',
    description: 'Splunk SPL detection query — ' + ctx.slice(0, 80),
    query: [
      'index=* sourcetype IN (WinEventLog:Security, XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)',
      '| search (',
      '    (EventCode=4688 (CommandLine="*-enc*" OR CommandLine="*EncodedCommand*" OR CommandLine="*DownloadString*" OR CommandLine="*IEX*"))',
      '    OR (EventCode=4697 OR EventCode=7045)',
      '    OR (EventCode=4776 Status="0xC000006A")',
      '    OR (EventCode=4624 Logon_Type=3)',
      '  )',
      '| eval threat_score=case(',
      '    match(CommandLine,"(?i)-enc|-EncodedCommand|IEX|DownloadString"), 85,',
      '    match(CommandLine,"(?i)WebClient|Invoke-WebRequest|wget|curl"), 75,',
      '    EventCode=4697, 80,',
      '    EventCode=4776 AND Status="0xC000006A", 70,',
      '    true(), 50',
      '  )',
      '| where threat_score >= ' + SEV_SCORE[sev],
      '| stats',
      '    count            AS event_count,',
      '    values(CommandLine) AS commands,',
      '    values(dest)     AS targets,',
      '    dc(dest)         AS unique_targets,',
      '    earliest(_time)  AS first_seen,',
      '    latest(_time)    AS last_seen',
      '    BY user, src_ip, threat_score',
      '| eval severity="' + sev + '"',
      '| eval mitre="T1059.001, T1078, T1021.001"',
      '| sort -threat_score',
      '| table user, src_ip, targets, unique_targets, commands, threat_score, severity, mitre'
    ].join('\n'),
    mitre: ['T1059.001', 'T1078', 'T1021.001'],
    notes: [
      'Use tstats for better performance on large datasets',
      'Scope index= to specific security indexes for speed',
      'Adjust threat_score threshold to reduce false positives'
    ]
  }),

  elastic: (ctx, sev) => ({
    platform: 'Elastic SIEM',
    language: 'KQL',
    type: 'SIEM',
    icon: '⚡',
    description: 'Elastic SIEM KQL detection — ' + ctx.slice(0, 80),
    query: [
      '// Elastic SIEM — KQL Detection',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      '(',
      '  (',
      '    event.category: "process" AND event.action: "start"',
      '    AND process.name: ("powershell.exe" OR "cmd.exe" OR "wscript.exe" OR "mshta.exe")',
      '    AND (',
      '      process.args: ("*-EncodedCommand*" OR "*-enc*" OR "*DownloadString*" OR "*IEX*")',
      '      OR process.parent.name: ("WINWORD.EXE" OR "EXCEL.EXE" OR "OUTLOOK.EXE")',
      '    )',
      '  )',
      '  OR',
      '  (',
      '    event.category: "network" AND network.direction: "outbound"',
      '    AND destination.port: (4444 OR 8080 OR 8443 OR 1337 OR 9001)',
      '    AND NOT destination.ip: ("10.0.0.0/8" OR "192.168.0.0/16" OR "172.16.0.0/12")',
      '  )',
      '  OR',
      '  (',
      '    event.category: "authentication" AND event.outcome: "failure"',
      '    AND winlog.event_id: (4776 OR 4625)',
      '  )',
      ')',
      'AND host.os.type: "windows"',
      'AND NOT user.name: ("SYSTEM" OR "LOCAL SERVICE" OR "NETWORK SERVICE")'
    ].join('\n'),
    mitre: ['T1059.001', 'T1071', 'T1110'],
    notes: [
      'Pair with ML anomaly detection jobs for baseline deviation',
      'Add threat.indicator enrichment via Threat Intel module',
      'Create as Detection Rule for continuous monitoring'
    ]
  }),

  sentinel: (ctx, sev) => ({
    platform: 'Azure Sentinel',
    language: 'KQL',
    type: 'SIEM',
    icon: '☁️',
    description: 'Azure Sentinel Analytic Rule — ' + ctx.slice(0, 80),
    query: [
      '// Azure Sentinel — Scheduled Analytic Rule',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      'let timeframe        = 1h;',
      'let threshold        = 5;',
      'let susp_procs       = dynamic(["powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe"]);',
      'let encoded_patterns = dynamic(["-enc","-EncodedCommand","IEX","DownloadString","WebClient","FromBase64String"]);',
      '',
      'SecurityEvent',
      '| where TimeGenerated >= ago(timeframe)',
      '| where EventID in (4688, 4697, 4698, 4624, 4625, 4776)',
      '| where (Process has_any (susp_procs) and CommandLine has_any (encoded_patterns))',
      '      or EventID == 4697',
      '      or (EventID == 4624 and LogonType == 3',
      '          and IpAddress !startswith "10."',
      '          and IpAddress !startswith "192.168.")',
      '| summarize',
      '    EventCount   = count(),',
      '    FirstSeen    = min(TimeGenerated),',
      '    LastSeen     = max(TimeGenerated),',
      '    Commands     = make_set(CommandLine, 10),',
      '    Hosts        = make_set(Computer, 20),',
      '    UniqueHosts  = dcount(Computer)',
      '    by Account, IpAddress, Process',
      '| where EventCount > threshold or UniqueHosts > 3',
      '| extend',
      '    ThreatScore = case(',
      '      UniqueHosts > 10, 95,',
      '      UniqueHosts > 5,  80,',
      '      EventCount  > 20, 75,',
      '      true(),           60',
      '    ),',
      '    Severity    = "' + sev + '",',
      '    MITRE       = "T1059.001, T1078, T1021"',
      '| project-reorder ThreatScore, Account, UniqueHosts, EventCount, MITRE'
    ].join('\n'),
    mitre: ['T1059.001', 'T1078', 'T1021'],
    notes: [
      'Set as Scheduled Rule — run every 5min, lookback 1hr',
      'Entity mapping: Account→Account, IpAddress→IP',
      'Link Playbook for auto-isolation on CRITICAL alerts'
    ]
  }),

  qradar: (ctx, sev) => ({
    platform: 'IBM QRadar',
    language: 'AQL',
    type: 'SIEM',
    icon: '🔷',
    description: 'IBM QRadar AQL detection — ' + ctx.slice(0, 80),
    query: [
      '-- IBM QRadar AQL Detection Query',
      '-- Severity: ' + sev + ' | Generated: ' + now(),
      '',
      'SELECT',
      '  DATEFORMAT(starttime, \'YYYY-MM-dd HH:mm:ss\') AS "Event Time",',
      '  USERNAME                                       AS "User",',
      '  SOURCEIP                                       AS "Source IP",',
      '  DESTINATIONIP                                  AS "Dest IP",',
      '  "QID_Name"(qid)                               AS "Event Name",',
      '  "UTF8"(payload)                               AS "Raw Payload",',
      '  COUNT(*)                                       AS "Event Count",',
      '  UNIQUECOUNT(DESTINATIONIP)                     AS "Unique Dests",',
      '  magnitude                                      AS "Magnitude"',
      'FROM events',
      'WHERE',
      '  LOGSOURCETYPENAME(devicetype) IN (',
      '    \'Microsoft Windows Security Event Log\',',
      '    \'Microsoft Sysmon\',',
      '    \'Microsoft Windows PowerShell\'',
      '  )',
      '  AND (',
      '    (CATEGORY = \'Authentication\' AND magnitude >= ' + (sev === 'CRIT' ? 8 : sev === 'HIGH' ? 6 : 4) + ')',
      '    OR (RULENAME ILIKE \'%powershell%\' OR RULENAME ILIKE \'%encoded%\')',
      '    OR (RULENAME ILIKE \'%lateral%\' AND magnitude >= 5)',
      '  )',
      '  AND STARTTIME >= NOW() - 3600000',
      'GROUP BY USERNAME, SOURCEIP, DESTINATIONIP, qid, magnitude',
      'HAVING COUNT(*) > 3 OR UNIQUECOUNT(DESTINATIONIP) > 3',
      'ORDER BY magnitude DESC, "Event Count" DESC'
    ].join('\n'),
    mitre: ['T1059', 'T1110', 'T1021'],
    notes: [
      'Configure Offense Rules to auto-escalate high magnitude events',
      'Tune magnitude thresholds to reduce false positives',
      'Enable Reference Sets for dynamic IP/user whitelisting'
    ]
  }),

  chronicle: (ctx, sev) => ({
    platform: 'Google Chronicle',
    language: 'YARA-L',
    type: 'SIEM',
    icon: '🌐',
    description: 'Google Chronicle YARA-L 2.0 rule — ' + ctx.slice(0, 80),
    query: [
      '// Google Chronicle — YARA-L 2.0 Detection Rule',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      'rule threatforge_detection {',
      '  meta:',
      '    author          = "ThreatForge SOC"',
      '    severity        = "' + sev + '"',
      '    mitre_tactic    = "Execution, Lateral Movement"',
      '    mitre_technique = "T1059.001, T1021.001, T1078"',
      '    version         = "1.0"',
      '',
      '  events:',
      '    $e1.metadata.event_type = "PROCESS_LAUNCH"',
      '    $e1.principal.process.file.full_path =',
      '      /(?i)(powershell|cmd|wscript|mshta)\\.exe/',
      '    $e1.target.process.command_line =',
      '      /(?i)(-enc|-EncodedCommand|IEX|DownloadString|WebClient)/',
      '    $e1.principal.user.userid !=',
      '      /(?i)(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)/',
      '',
      '    $e2.metadata.event_type = "NETWORK_CONNECTION"',
      '    $e2.principal.ip = $e1.principal.ip',
      '    $e2.target.port != 80',
      '    $e2.target.port != 443',
      '    $e2.target.port != 53',
      '    not net.ip_in_range_cidr($e2.target.ip, "10.0.0.0/8")',
      '    not net.ip_in_range_cidr($e2.target.ip, "192.168.0.0/16")',
      '    not net.ip_in_range_cidr($e2.target.ip, "172.16.0.0/12")',
      '',
      '    #user = $e1.principal.user.userid',
      '    #host = $e1.principal.hostname',
      '',
      '  match:',
      '    #user, #host over 15m',
      '',
      '  condition:',
      '    $e1 and $e2',
      '}'
    ].join('\n'),
    mitre: ['T1059.001', 'T1021.001', 'T1078'],
    notes: [
      'Deploy as Detection Rule in Chronicle > Rules Editor',
      'Run retrohunt for 30-day historical analysis',
      'Configure SOAR actions via Chronicle Integrations'
    ]
  }),

  arcsight: (ctx, sev) => ({
    platform: 'ArcSight ESM',
    language: 'CEL',
    type: 'SIEM',
    icon: '🔺',
    description: 'ArcSight ESM Active Channel & Correlation Rule — ' + ctx.slice(0, 80),
    query: [
      '/* ArcSight ESM — Active Channel + Correlation Rule',
      '   Severity: ' + sev + ' | Generated: ' + now() + ' */',
      '',
      '/* ── ACTIVE CHANNEL FILTER ──────────────────────── */',
      'Filter:',
      '  (destinationProcessName CONTAINS "powershell.exe"',
      '   OR destinationProcessName CONTAINS "cmd.exe"',
      '   OR destinationProcessName CONTAINS "wscript.exe")',
      '',
      '  AND (',
      '    message CONTAINS "-EncodedCommand"',
      '    OR message CONTAINS "-enc "',
      '    OR message CONTAINS "DownloadString"',
      '    OR message CONTAINS "IEX("',
      '    OR message CONTAINS "WebClient"',
      '  )',
      '',
      '  AND NOT destinationUserName CONTAINS "SYSTEM"',
      '',
      '  AND (',
      '    deviceEventClassId = "Microsoft-Windows-Security-Auditing:4688"',
      '    OR deviceEventClassId = "Sysmon:1"',
      '  )',
      '',
      'Time Range: Last 3600 seconds',
      '',
      '/* ── CORRELATION RULE ───────────────────────────── */',
      'Rule Name:  "ThreatForge_' + sev + '_Suspicious_Execution"',
      'Rule Type:  Threshold',
      'Condition:  COUNT(events WHERE message CONTAINS "-enc") >= 3',
      '            WITHIN 300 seconds',
      '            GROUPED BY sourceAddress, destinationUserName',
      'Severity:   ' + (sev === 'CRIT' ? 10 : sev === 'HIGH' ? 8 : 5) + ' / 10',
      'Actions:    Send Notification → SOC Team',
      '            Create Case → Tier 2 Analyst'
    ].join('\n'),
    mitre: ['T1059.001', 'T1078'],
    notes: [
      'Import rule XML via ESM Console > Rules > Import',
      'Add to Active Channel Package for real-time visibility',
      'Integrate with ServiceNow via SmartConnector'
    ]
  }),

  logrhythm: (ctx, sev) => ({
    platform: 'LogRhythm SIEM',
    language: 'LQL',
    type: 'SIEM',
    icon: '📊',
    description: 'LogRhythm AI Engine rule — ' + ctx.slice(0, 80),
    query: [
      '// LogRhythm SIEM — Log Search + AI Engine Rule',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      '/* ── LOG SEARCH QUERY ──────────────────────────── */',
      'logSource:"Windows Security" OR logSource:"Sysmon"',
      'AND (',
      '  message:"powershell.exe"',
      '  AND (',
      '    message:"-EncodedCommand" OR',
      '    message:"-enc "           OR',
      '    message:"DownloadString"  OR',
      '    message:"IEX("            OR',
      '    message:"WebClient"',
      '  )',
      ')',
      'AND NOT login:"SYSTEM"',
      'AND NOT login:"LOCAL SERVICE"',
      'AND date:[NOW-1HOUR TO NOW]',
      '',
      '/* ── AI ENGINE RULE ────────────────────────────── */',
      'Rule Name:   "ThreatForge_Suspicious_PowerShell_' + sev + '"',
      'Rule Type:   Behavioral (Threshold)',
      'Threshold:   3 events within 300 seconds',
      'Group By:    User Login, Origin Host IP',
      'Risk Score:  ' + (sev === 'CRIT' ? 100 : sev === 'HIGH' ? 75 : 50),
      'MITRE:       T1059.001, T1078',
      '',
      '/* ── ALARM ACTIONS ─────────────────────────────── */',
      'Notification: SOC Distribution List',
      'Case:         Create case, Priority ' + sev,
      'SmartResponse: Block-Host (if CRITICAL)'
    ].join('\n'),
    mitre: ['T1059.001', 'T1078'],
    notes: [
      'Enable full PowerShell Script Block Logging (Event 4104)',
      'Configure SmartResponse for automated host blocking',
      'Enable UEBA module for user behavioral baseline'
    ]
  }),

  sumo: (ctx, sev) => ({
    platform: 'Sumo Logic',
    language: 'SuQL',
    type: 'SIEM',
    icon: '🎯',
    description: 'Sumo Logic Cloud SIEM query — ' + ctx.slice(0, 80),
    query: [
      '// Sumo Logic — Log Search + Cloud SIEM Signal',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      '_sourceCategory=Windows/Security OR _sourceCategory=Sysmon',
      '| where (',
      '    process_name matches /(?i)(powershell|cmd|wscript|mshta)\\.exe/',
      '    and (',
      '      command_line matches /(?i)(-enc|-EncodedCommand|DownloadString|IEX|WebClient)/',
      '      or command_line matches /(?i)(http|https|ftp):\\/\\//',
      '    )',
      '  )',
      '  and !user matches /(?i)(system|local service|network service)/',
      '',
      '| count as event_count,',
      '  first(command_line) as sample_command,',
      '  first(src_ip) as src_ip',
      '  by user, dest_host, process_name',
      '| where event_count > 3',
      '',
      '/* ── CLOUD SIEM RULE ────────────────────────────── */',
      '// Rule Type:  Threshold',
      '// Entity:     User, Hostname',
      '// Severity:   ' + sev,
      '// Tags:       T1059.001, Execution',
      '// Window:     15 minutes',
      '// Threshold:  event_count > 5'
    ].join('\n'),
    mitre: ['T1059.001', 'T1071'],
    notes: [
      'Use Field Extraction Rules (FER) for structured log parsing',
      'Enable Cloud SIEM for automatic signal correlation',
      'Configure Webhook to Slack #soc-alerts'
    ]
  }),

  // ── EDR ───────────────────────────────────────────────────────────────────

  crowdstrike: (ctx, sev) => ({
    platform: 'CrowdStrike Falcon',
    language: 'EQL/FQL',
    type: 'EDR',
    icon: '🦅',
    description: 'CrowdStrike Falcon Event Query — ' + ctx.slice(0, 80),
    query: [
      '// CrowdStrike Falcon — Event Query Language (EQL/FQL)',
      '// Navigate: Falcon > Investigate > Event Search',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      'event_simpleName IN (ProcessRollup2, SyntheticProcessRollup2)',
      '| where ImageFileName REGEXP "(?i)(powershell|cmd|wscript|mshta|certutil)\\.exe"',
      '| where CommandLine REGEXP "(?i)(-enc|-EncodedCommand|DownloadString|IEX|WebClient|FromBase64String)"',
      '   OR   CommandLine REGEXP "(?i)(http://|https://)[^\\s]+"',
      '   OR   ParentBaseFileName REGEXP "(?i)(WINWORD|EXCEL|OUTLOOK)\\.EXE"',
      '',
      '| eval threat_level = if(',
      '    match(CommandLine, "(?i)-enc|-EncodedCommand"), "CRITICAL",',
      '    if(match(CommandLine, "(?i)DownloadString|WebClient"), "HIGH",',
      '    if(match(ParentBaseFileName, "(?i)WINWORD|EXCEL|OUTLOOK"), "HIGH", "MEDIUM")))',
      '',
      '| stats count()          as EventCount,',
      '        dc(ComputerName) as UniqueHosts,',
      '        values(CommandLine)[0:5] as CommandSamples',
      '        by UserName, FileName, threat_level, aid',
      '',
      '| where EventCount > 2 OR UniqueHosts > 1',
      '| sort -EventCount',
      '',
      '// ── RTR LIVE RESPONSE (run on flagged host) ──────',
      '// netstat -ano  →  active connections',
      '// ps            →  running processes',
      '// get-process   →  process list with memory'
    ].join('\n'),
    mitre: ['T1059.001', 'T1566.001', 'T1204.002'],
    notes: [
      'Scope by aid (Agent ID) or cid for tenant-wide search',
      'Use RTR (Real Time Response) for live host investigation',
      'Build Indicator of Activity (IOA) from this pattern'
    ]
  }),

  defender: (ctx, sev) => ({
    platform: 'Microsoft Defender XDR',
    language: 'KQL',
    type: 'EDR',
    icon: '🛡️',
    description: 'Microsoft Defender Advanced Hunting — ' + ctx.slice(0, 80),
    query: [
      '// Microsoft Defender XDR — Advanced Hunting',
      '// Navigate: security.microsoft.com > Hunting > Advanced Hunting',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      'let timeRange         = ago(24h);',
      'let encodedPatterns   = dynamic(["-enc","-EncodedCommand","IEX(","FromBase64String","DownloadString"]);',
      'let suspiciousParents = dynamic(["WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","MSHTA.EXE","WSCRIPT.EXE"]);',
      'let targetProcs       = dynamic(["powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe"]);',
      '',
      'DeviceProcessEvents',
      '| where Timestamp >= timeRange',
      '| where (FileName in~ (targetProcs) and ProcessCommandLine has_any (encodedPatterns))',
      '      or (InitiatingProcessFileName has_any (suspiciousParents) and FileName in~ (targetProcs))',
      '| extend ThreatScore = case(',
      '    ProcessCommandLine has_any (["-enc","-EncodedCommand"])',
      '      and InitiatingProcessFileName has_any (suspiciousParents), 95,',
      '    ProcessCommandLine has "DownloadString", 80,',
      '    ProcessCommandLine has "IEX",            75,',
      '    InitiatingProcessFileName has_any (suspiciousParents), 70,',
      '    true(), 50',
      '  )',
      '| where ThreatScore >= ' + SEV_SCORE[sev],
      '| join kind=leftouter (',
      '    DeviceNetworkEvents',
      '    | where Timestamp >= timeRange',
      '    | where ActionType == "ConnectionSuccess"',
      '    | where RemotePort !in (80, 443, 53)',
      '    | project DeviceId, RemoteIP, RemotePort, Timestamp',
      '  ) on DeviceId',
      '| summarize',
      '    Events      = count(),',
      '    UniqueHosts = dcount(DeviceName),',
      '    Commands    = make_set(ProcessCommandLine, 5),',
      '    RemoteIPs   = make_set(RemoteIP, 10),',
      '    MaxThreat   = max(ThreatScore)',
      '    by AccountName, DeviceName, FileName',
      '| where MaxThreat >= ' + SEV_SCORE[sev],
      '| extend Severity = "' + sev + '", MITRE = "T1059.001, T1021, T1078"',
      '| order by MaxThreat desc'
    ].join('\n'),
    mitre: ['T1059.001', 'T1021', 'T1078'],
    notes: [
      'Create Detection Rule from query for continuous alerting',
      'Enable Auto-Investigation on HIGH+ severity detections',
      'Review DeviceLogonEvents for lateral movement correlation'
    ]
  }),

  sentinelone: (ctx, sev) => ({
    platform: 'SentinelOne',
    language: 'DQL',
    type: 'EDR',
    icon: '💜',
    description: 'SentinelOne Deep Visibility DQL hunt — ' + ctx.slice(0, 80),
    query: [
      '// SentinelOne Deep Visibility — DQL',
      '// Navigate: Visibility > Deep Visibility',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      '/* ── PROCESS EXECUTION ───────────────────────── */',
      'EventType = "Process Creation"',
      'AND (',
      '  TgtProcName ContainsCIS "powershell.exe"',
      '  OR TgtProcName ContainsCIS "cmd.exe"',
      '  OR TgtProcName ContainsCIS "wscript.exe"',
      '  OR TgtProcName ContainsCIS "mshta.exe"',
      ')',
      'AND (',
      '  TgtProcCmdLine ContainsCIS "-EncodedCommand"',
      '  OR TgtProcCmdLine ContainsCIS "-enc "',
      '  OR TgtProcCmdLine ContainsCIS "DownloadString"',
      '  OR TgtProcCmdLine ContainsCIS "IEX("',
      '  OR TgtProcCmdLine ContainsCIS "WebClient"',
      ')',
      'AND NOT SrcProcUser In ("NT AUTHORITY\\\\SYSTEM", "NT AUTHORITY\\\\LOCAL SERVICE")',
      '',
      '| Group By SrcProcUser, TgtProcName, AgentName',
      '| Sort By Count Desc',
      '',
      '/* ── NETWORK CORRELATION ─────────────────────── */',
      '// EventType = "IP Connect"',
      '// AND NetworkDirection = "OUTBOUND"',
      '// AND NOT DstIP In CIDRRange "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"',
      '// AND DstPort In [4444, 8080, 8443, 1337, 9001]',
      '// | Group By SrcProcName, DstIP, DstPort, AgentName',
      '// | Sort By Count Desc'
    ].join('\n'),
    mitre: ['T1059.001', 'T1071', 'T1547.001'],
    notes: [
      'Enable Full Telemetry collection policy for complete data',
      'Use Storyline to visualize process tree from any event',
      'Configure STAR Rule for continuous detection'
    ]
  }),

  carbonblack: (ctx, sev) => ({
    platform: 'Carbon Black Cloud',
    language: 'CBC Query',
    type: 'EDR',
    icon: '⬛',
    description: 'VMware Carbon Black Cloud query — ' + ctx.slice(0, 80),
    query: [
      '/* Carbon Black Cloud — Process Search',
      '   Severity: ' + sev + ' | Generated: ' + now() + ' */',
      '',
      '/* ── PROCESS SEARCH ─────────────────────────── */',
      '(process_name:powershell.exe OR process_name:cmd.exe OR process_name:wscript.exe)',
      'AND (',
      '  process_cmdline:"-EncodedCommand"',
      '  OR process_cmdline:"-enc "',
      '  OR process_cmdline:"IEX("',
      '  OR process_cmdline:"DownloadString"',
      '  OR process_cmdline:"WebClient"',
      ')',
      'AND NOT process_username:("NT AUTHORITY\\\\SYSTEM")',
      '',
      '/* ── RISK ENRICHMENT ────────────────────────── */',
      '/* Review these fields on results:',
      '   filemod_count:[100 TO *]   → ransomware indicator',
      '   regmod_count:[10 TO *]     → persistence activity',
      '   crossproc_count:[5 TO *]   → process injection',
      '   netconn_count:[1 TO *]     → C2 callback */',
      '',
      '/* ── PARENT-CHILD CHAIN ─────────────────────── */',
      '// parent_name:excel.exe AND process_name:(powershell.exe OR cmd.exe)'
    ].join('\n'),
    mitre: ['T1059.001', 'T1071', 'T1055'],
    notes: [
      'Use Live Response for real-time host investigation',
      'Enable Enhanced EDR sensor for full command-line telemetry',
      'Save as Watchlist for persistent threat hunting'
    ]
  }),

  cortex: (ctx, sev) => ({
    platform: 'Cortex XDR',
    language: 'XQL',
    type: 'EDR',
    icon: '🔶',
    description: 'Palo Alto Cortex XDR XQL query — ' + ctx.slice(0, 80),
    query: [
      '// Palo Alto Cortex XDR — XQL',
      '// Navigate: XDR > Investigation > Query Builder',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      'dataset = xdr_data',
      '',
      '| filter',
      '    (',
      '      event_type = ENUM.EVENT_TYPE_PROCESS',
      '      and action_process_image_name ~= "(?i)(powershell|cmd|wscript|mshta)\\.exe"',
      '      and (',
      '        action_process_command_line ~= "(?i)(-enc|-EncodedCommand|DownloadString|IEX|WebClient)"',
      '        or actor_process_image_name ~= "(?i)(WINWORD|EXCEL|OUTLOOK)\\.EXE"',
      '      )',
      '    )',
      '    or',
      '    (',
      '      event_type = ENUM.EVENT_TYPE_NETWORK',
      '      and action_network_connection_id != null',
      '      and action_network_remote_port not in (80, 443, 53)',
      '      and not (action_remote_hostname ~= "(?i)(microsoft|windows|google)\\.com$")',
      '    )',
      '',
      '| fields',
      '    _time,',
      '    agent_hostname,',
      '    actor_effective_username,',
      '    action_process_image_name,',
      '    action_process_command_line,',
      '    action_network_remote_ip,',
      '    action_network_remote_port',
      '',
      '| comp',
      '    count()                           as event_count,',
      '    count_distinct(agent_hostname)    as unique_hosts,',
      '    array_agg(action_process_command_line, 5) as sampled_commands',
      '    by actor_effective_username, action_process_image_name',
      '',
      '| filter event_count > 2 or unique_hosts > 1',
      '| sort desc event_count'
    ].join('\n'),
    mitre: ['T1059.001', 'T1071', 'T1566'],
    notes: [
      'Enable Cortex Analytics BIOC rules for ML detection',
      'Configure XSOAR Playbook for automated investigation',
      'Use Live Terminal for remote host access on alerts'
    ]
  }),

  elastic_edr: (ctx, sev) => ({
    platform: 'Elastic EDR',
    language: 'EQL',
    type: 'EDR',
    icon: '⚡',
    description: 'Elastic EDR EQL sequence detection — ' + ctx.slice(0, 80),
    query: [
      '// Elastic EDR — EQL Sequence Detection',
      '// Navigate: Security > Timelines > EQL Search',
      '// Severity: ' + sev + ' | Generated: ' + now(),
      '',
      '/* ── SEQUENCE: Encoded PS → Network Callback ─── */',
      'sequence by process.entity_id with maxspan=2m',
      '',
      '  [process where event.action == "start"',
      '    and process.name : ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")',
      '    and (',
      '      process.args : ("-EncodedCommand","-enc","IEX*","*DownloadString*","*WebClient*")',
      '      or process.parent.name : ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE")',
      '    )',
      '    and not user.name : ("SYSTEM","Local Service","Network Service")',
      '  ]',
      '',
      '  [network where event.action == "connection_attempted"',
      '    and not cidrmatch(destination.ip,',
      '      "10.0.0.0/8","192.168.0.0/16","172.16.0.0/12","127.0.0.0/8")',
      '    and destination.port not in (80, 443, 53)',
      '  ]',
      '',
      '/* ── PERSISTENCE DETECTION (uncomment) ─────────',
      '   registry where registry.path : (',
      '     "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*",',
      '     "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\*"',
      '   ) */'
    ].join('\n'),
    mitre: ['T1059.001', 'T1566.001', 'T1547.001'],
    notes: [
      'EQL sequences detect multi-stage attack chains powerfully',
      'Create Detection Rule from EQL for continuous monitoring',
      'Tune maxspan based on your environment dwell-time baseline'
    ]
  }),

  // ── Correlation Rules ─────────────────────────────────────────────────────

  correlation: (ctx, sev) => ({
    platform: 'Cross-Platform Correlation',
    language: 'Universal',
    type: 'CORRELATION',
    icon: '🔗',
    description: 'Cross-platform correlation rules — ' + ctx.slice(0, 80),
    isCorrelation: true,
    rules: [
      {
        title: '🔗 Multi-Stage Kill Chain Detection',
        mitre: ['T1078', 'T1059.001', 'T1071', 'T1041'],
        desc: [
          'Detects complete attack chain in a 30-minute sliding window:',
          '',
          '  [1] Auth event (EventID 4624/4776) from unusual external IP',
          '  [2] Within 10min: Encoded command execution on same host',
          '  [3] Within 15min: Unusual outbound connection from process',
          '  [4] Within 30min: Data transfer >10MB to non-corporate dest',
          '',
          'TRIGGER:  2+ stages → HIGH alert',
          '          3+ stages → CRITICAL + auto-isolate',
          'GROUP BY: SourceIP, Username, Hostname',
          'APPLY TO: All SIEM platforms via correlation search'
        ].join('\n')
      },
      {
        title: '🔗 Impossible Travel + Endpoint Anomaly',
        mitre: ['T1078', 'T1110.001'],
        desc: [
          'Correlates geographic auth anomalies with endpoint activity:',
          '',
          '  [1] User authenticates from Location A',
          '  [2] Same user authenticates from Location B within 2 hours',
          '  [3] Distance ÷ Time > 900 km/h (physically impossible)',
          '  [4] Either session triggers suspicious process or data access',
          '',
          'RESPONSE:  Force MFA → Alert Tier 1 SOC → Open incident',
          'EXCEPTION: Known VPN exit nodes, corporate travel policy'
        ].join('\n')
      },
      {
        title: '🔗 Credential Dumping → Lateral Movement',
        mitre: ['T1003.001', 'T1550.002', 'T1021.001'],
        desc: [
          'Detects LSASS access followed by pass-the-hash movement:',
          '',
          '  [A] Sysmon Event 10: LSASS accessed by non-standard process',
          '  [B] EDR: Mimikatz signature or sekurlsa module loaded',
          '  [C] New credential used within 5min from different host',
          '  [D] Multiple 4625 failures → 4624 success on admin account',
          '',
          'TRIGGER:  Any 2 of [A,B,C,D] within 5-minute window',
          'SEVERITY: ' + (sev === 'CRIT' || sev === 'HIGH' ? 'CRITICAL — immediate response required' : 'HIGH')
        ].join('\n')
      },
      {
        title: '🔗 C2 Beaconing Pattern Detection',
        mitre: ['T1071.001', 'T1132', 'T1573'],
        desc: [
          'Statistical detection of command-and-control beaconing:',
          '',
          'ALGORITHM: Standard deviation of connection inter-arrival times',
          'THRESHOLD: stdev(intervals) < 15s AND count > 10 per hour',
          '',
          'INDICATORS:',
          '  - Consistent intervals (jitter < 10%)',
          '  - Consistent payload size (±15% variance)',
          '  - Destination NOT in known-good domain whitelist',
          '  - Connections persist outside business hours (24/7)',
          '',
          'SPLUNK:  | streamstats window=20 stdev(interval) AS beacon_score',
          'ELASTIC: ML job — count_by_bucket + rare destination',
          'SENTINEL: | summarize stdev(interval) by src, dst | where stdev < 15'
        ].join('\n')
      },
      {
        title: '🔗 Ransomware Pre-Encryption Early Warning',
        mitre: ['T1490', 'T1486', 'T1083'],
        desc: [
          'Multi-signal early warning before mass encryption begins:',
          '',
          '  [1] vssadmin delete shadows /all /quiet',
          '  [2] bcdedit /set recoveryenabled No',
          '  [3] Rapid file enumeration: >1000 reads in 60 seconds',
          '  [4] Known ransomware process name or file hash (TI feed)',
          '  [5] MBR/partition table write from unusual process',
          '',
          'TRIGGER:   2+ signals → HIGH alert',
          '           3+ signals → CRITICAL + auto-isolate',
          'AUTO-ACT:  Isolate via EDR API → Snapshot VM → Page on-call'
        ].join('\n')
      }
    ]
  }),

  // ── Additional EDR/Platform generators ──────────────────────────────────────

  crowdstrike_edr: (ctx, sev) => ({
    platform: 'CrowdStrike EDR',
    language: 'EQL/FQL',
    type: 'EDR',
    icon: '🦅',
    description: 'CrowdStrike EDR detection — ' + ctx.slice(0, 80),
    query: [
      '// CrowdStrike Falcon — Event Query Language',
      '// Severity: ' + sev,
      '',
      'event_simpleName IN (ProcessRollup2, NetworkConnectIP4, DnsRequest)',
      '| search (',
      '    (event_simpleName=ProcessRollup2',
      '     FileName IN ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","certutil.exe")',
      '     CommandLine IN ("*-enc*","*-EncodedCommand*","*DownloadString*","*IEX*","*/transfer*"))',
      '    OR (event_simpleName=NetworkConnectIP4',
      '     RemotePort IN (4444, 1337, 8080, 8443)',
      '     NOT RemoteAddressIP4 IN ("10.*","192.168.*","172.16.*"))',
      '    OR (event_simpleName=DnsRequest',
      '     DomainName IN ("*.onion","*pastebin*","*ngrok*"))',
      '  )',
      '| stats count by ComputerName, UserName, FileName, CommandLine, RemoteAddressIP4',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1059.001', 'T1071', 'T1568'],
    notes: ['Run in Falcon Insight > Event Search', 'Adjust time range and RemotePort list', 'Create as Saved Search for alerting']
  }),

  // ── Web Server generators ────────────────────────────────────────────────────

  iis: (ctx, sev) => ({
    platform: 'IIS Logs',
    language: 'W3C/Regex',
    type: 'Web',
    icon: '🌍',
    description: 'IIS log analysis — ' + ctx.slice(0, 80),
    query: [
      '// IIS W3C Access Log Analysis',
      '// Ingest via Splunk/Elastic Universal Forwarder or Windows Event Log',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="iis" OR sourcetype="ms:iis:auto"',
      '| eval suspicious=case(',
      '    match(cs_uri_stem, "(?i)(\\.asp|\\.aspx|\\.php|\\.jsp)(;|\\.)|(\\.\\.)|\\.\\\\"),    "Path Traversal/Webshell",',
      '    match(cs_uri_query, "(?i)(select|union|insert|update|delete|drop|exec|xp_|0x[0-9a-f]{4,})"), "SQL Injection",',
      '    match(cs_uri_query, "(?i)(<script|javascript:|onerror=|onload=|alert\\()"),                  "XSS",',
      '    match(cs_uri_stem, "(?i)(cmd\\.exe|powershell|net\\.exe|whoami|systeminfo)"),                 "RCE Attempt",',
      '    sc_status IN (500, 502, 503) AND count > 20,                                                 "Error Spike",',
      '    true(), null()',
      '  )',
      '| where isnotnull(suspicious)',
      '| stats count, values(cs_uri_stem) AS paths, values(cs_uri_query) AS params BY c_ip, suspicious, sc_status',
      '| sort -count',
      '',
      '// === ELASTIC KQL ===',
      '// iis.access.response_code: (400 OR 500 OR 403) AND iis.access.url.path: ("*../*" OR "*cmd.exe*" OR "*.aspx;*")'
    ].join('\n'),
    mitre: ['T1190', 'T1505.003', 'T1059.003'],
    notes: ['Enable W3C extended logging with all fields', 'Monitor 5xx spikes for exploit attempts', 'Alert on .asp/.aspx files in upload directories']
  }),

  apache: (ctx, sev) => ({
    platform: 'Apache Access',
    language: 'Regex/SPL',
    type: 'Web',
    icon: '🦊',
    description: 'Apache log detection — ' + ctx.slice(0, 80),
    query: [
      '// Apache Access Log Analysis',
      '// Common Log Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="access_combined" OR sourcetype="apache:access"',
      '| rex field=_raw "(?<client_ip>\\d+\\.\\d+\\.\\d+\\.\\d+).+\\\"(?<method>\\w+) (?<uri>[^ ]+)[^\\\"]+\\\" (?<status>\\d+) (?<bytes>\\d+) \\\"[^\\\"]*\\\" \\\"(?<ua>[^\\\"]+)\\\""',
      '| eval attack_type=case(',
      '    match(uri,     "(?i)(\\.\\.[\\/\\\\]){2,}|etc/passwd|proc/self"),      "Directory Traversal",',
      '    match(uri,     "(?i)(select|union|;\\s*(drop|exec|insert))"),          "SQLi",',
      '    match(uri,     "(?i)(\\$\\{jndi:|\\${[^}]*\\$\\{)"),                 "Log4j/JNDI",',
      '    match(uri,     "(?i)(webshell|c99\\.php|r57\\.php|b374k)"),           "Webshell Upload",',
      '    match(ua,      "(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster)"),  "Scanner",',
      '    status IN (400, 403, 404, 500) AND count > 50,                        "Error Flood",',
      '    true(), null()',
      '  )',
      '| where isnotnull(attack_type)',
      '| stats count, dc(uri) AS unique_paths, values(uri) AS paths BY client_ip, attack_type, status',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1190', 'T1505.003', 'T1595.002'],
    notes: ['Enable mod_security WAF for active blocking', 'Log4j: alert on any ${jndi: in URI or User-Agent', 'Rotate and forward logs in real-time with Filebeat']
  }),

  nginx: (ctx, sev) => ({
    platform: 'Nginx Access',
    language: 'Regex/SPL',
    type: 'Web',
    icon: '🚀',
    description: 'Nginx log detection — ' + ctx.slice(0, 80),
    query: [
      '// Nginx Combined Log Format Detection',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="nginx:plus:access" OR sourcetype="nginx:access"',
      '| rex field=_raw "(?<ip>[\\d\\.]+).+\\\"(?<method>[A-Z]+) (?<uri>[^\\\"]+) HTTP/[\\d\\.]+\\\" (?<status>\\d{3}) (?<bytes>\\d+)"',
      '| eval threat=case(',
      '    match(uri, "(?i)(\\.\\.[\\/]){2,}|/etc/(passwd|shadow)|/proc/"),      "Path Traversal",',
      '    match(uri, "(?i)(\\$\\{jndi:|\\$\\{[^}]*\\$\\{)"),                   "Log4j JNDI",',
      '    match(uri, "(?i)(<[sS][cC][rR][iI][pP][tT]|onerror=|alert\\()"),     "XSS",',
      '    match(uri, "(?i)(select.+from|union.+select|exec.+sp_)"),             "SQLi",',
      '    status="404" AND count > 100,                                          "Directory Scan",',
      '    status IN ("400","500") AND count > 30,                               "Error Flood",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(uri) AS paths, dc(uri) AS unique_uris BY ip, threat, status',
      '| eval rate_per_min=count/60',
      '| where rate_per_min > 2',
      '| sort -count',
      '',
      '// === GEO-BLOCK CHECK ===',
      '// | iplocation ip | search Country IN ("RU","CN","KP","IR") | table ip, Country, count, threat'
    ].join('\n'),
    mitre: ['T1190', 'T1595.002', 'T1071.001'],
    notes: ['Enable nginx error log for server-side errors', 'Use fail2ban with nginx log for auto-blocking', 'Alert on Log4j ${jndi: pattern immediately — CRIT severity']
  }),

  // ── Container generators ─────────────────────────────────────────────────────

  docker: (ctx, sev) => ({
    platform: 'Docker',
    language: 'JSON/Syslog',
    type: 'Container',
    icon: '🐳',
    description: 'Docker container security — ' + ctx.slice(0, 80),
    query: [
      '// Docker Security Monitoring',
      '// Requires Docker daemon logging + forwarding to SIEM',
      '',
      '// === SPLUNK SPL (Docker JSON Logs) ===',
      'index=* sourcetype="docker:events" OR sourcetype="docker:container:*"',
      '| eval risk=case(',
      '    Action IN ("exec_create","exec_start") AND match(Attributes.execID, ".+"),  "Exec in Container",',
      '    match(Image, "(?i)(alpine|busybox|scratch)") AND Privileged=true,           "Privileged Container",',
      '    match(Mounts, "/var/run/docker\\.sock"),                                    "Docker Socket Mount",',
      '    match(Mounts, "(^|,)/(:ro|:rw)?$"),                                        "Root FS Mount",',
      '    Action IN ("pull") AND match(Image, "^[^/]+/[^/]+$") AND NOT match(Image, "^(docker\\.io|gcr\\.io|quay\\.io)"), "Unverified Image",',
      '    true(), null()',
      '  )',
      '| where isnotnull(risk)',
      '| stats count, values(Image) AS images, values(Name) AS containers BY Actor.ID, risk, Action',
      '| sort -count',
      '',
      '// === CONTAINER ESCAPE INDICATORS ===',
      '// Monitor host syslog for processes spawned from container namespace:',
      '// index=* sourcetype=syslog | search "container_id" AND ("nsenter" OR "runc" OR "cgroup") | stats count by host, process_name'
    ].join('\n'),
    mitre: ['T1610', 'T1611', 'T1552.007'],
    notes: ['Enable --log-driver=json-file with --log-opt max-size', 'Alert on any exec_create in production containers immediately', 'Privileged containers + docker.sock mount = full host compromise']
  }),

  kubernetes: (ctx, sev) => ({
    platform: 'Kubernetes',
    language: 'K8s Audit/SPL',
    type: 'Container',
    icon: '☸',
    description: 'Kubernetes security monitoring — ' + ctx.slice(0, 80),
    query: [
      '// Kubernetes Audit Log Detection',
      '// Enable K8s audit logging → forward to SIEM via Fluentd/Filebeat',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="kube:audit"',
      '| eval risk=case(',
      '    verb IN ("create","patch") AND requestObject.spec.hostPID=true,                 "HostPID Abuse",',
      '    verb IN ("create","patch") AND requestObject.spec.hostNetwork=true,             "Host Network",',
      '    verb IN ("create","patch") AND requestObject.spec.containers{}.securityContext.privileged=true, "Privileged Pod",',
      '    verb IN ("get","list","watch") AND objectRef.resource="secrets",                "Secret Enumeration",',
      '    verb="create" AND objectRef.resource="clusterrolebindings",                     "RBAC Escalation",',
      '    user.username="system:anonymous" OR user.groups{}="system:unauthenticated",      "Anonymous Access",',
      '    verb="exec" AND objectRef.resource="pods",                                      "Pod Exec",',
      '    true(), null()',
      '  )',
      '| where isnotnull(risk)',
      '| stats count, values(objectRef.name) AS resources, values(requestObject.metadata.name) AS names',
      '    BY user.username, sourceIPs{}, risk, verb',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1610', 'T1611', 'T1078.001'],
    notes: ['Enable K8s API server audit logging with RequestResponse level', 'Alert on any anonymous access immediately', 'Pod exec (kubectl exec) = potential lateral movement or persistence']
  }),

  // ── Database generators ─────────────────────────────────────────────────────

  sqlserver: (ctx, sev) => ({
    platform: 'SQL Server',
    language: 'SQL/SPL',
    type: 'Database',
    icon: '📊',
    description: 'SQL Server security monitoring — ' + ctx.slice(0, 80),
    query: [
      '// SQL Server Audit Log Detection',
      '// Requires SQL Server Audit enabled + forwarding to SIEM',
      '',
      '// === SPLUNK SPL (Windows Event Log or SQL Audit) ===',
      'index=* sourcetype="WinEventLog:Application" source="MSSQLSERVER"',
      '  OR index=* sourcetype="mssql:audit"',
      '| eval threat=case(',
      '    match(statement, "(?i)(xp_cmdshell|sp_oacreate|openrowset|bulk insert)"),  "OS Command Exec",',
      '    match(statement, "(?i)(create\\s+(login|user)|grant.+sysadmin|alter.+login)"), "Privilege Abuse",',
      '    match(statement, "(?i)(select.+(password|pwdhash|master\\.sys\\.(logins|sql_logins)))"), "Credential Harvesting",',
      '    match(statement, "(?i)(drop\\s+table|truncate|delete\\s+from)\\s+(users|admin|audit|log)"), "Data Destruction",',
      '    match(statement, "(?i)(union.+select|exec.+xp_|openrowset|bulk.+insert)"), "SQL Injection",',
      '    failed_login_count > 5, "Brute Force",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(statement) AS statements, values(database_name) AS dbs',
      '    BY server_principal_name, client_ip, threat',
      '| sort -count',
      '',
      '// === CRITICAL: Check xp_cmdshell status ===',
      '// SELECT name, value_in_use FROM sys.configurations WHERE name = \'xp_cmdshell\''
    ].join('\n'),
    mitre: ['T1505.001', 'T1078.002', 'T1110'],
    notes: ['Disable xp_cmdshell unless absolutely required', 'Audit logins, schema changes, and privileged commands', 'Alert on any sa/sysadmin account activity outside change windows']
  }),

  mysql: (ctx, sev) => ({
    platform: 'MySQL',
    language: 'SQL/Log',
    type: 'Database',
    icon: '🐬',
    description: 'MySQL security monitoring — ' + ctx.slice(0, 80),
    query: [
      '// MySQL General & Error Log Detection',
      '// Enable: general_log=ON, log_error=/var/log/mysql/error.log',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="mysql:generallog" OR sourcetype="mysql:errorlog"',
      '| eval threat=case(',
      '    match(query, "(?i)(load_file|into outfile|into dumpfile)"),                    "File R/W via SQL",',
      '    match(query, "(?i)(select.+from.+information_schema|show.+(tables|databases|grants))"), "Schema Enumeration",',
      '    match(query, "(?i)(union.+select|order by [0-9]+--|benchmark|sleep\\\\()"),     "SQLi/Timing Attack",',
      '    match(query, "(?i)(create.+user|grant.+all|flush.+privileges|set.+global)"),   "Privilege Abuse",',
      '    match(query, "(?i)(drop.+(table|database|user)|truncate)"),                    "Data Destruction",',
      '    failed_auth_count > 10, "Brute Force",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(user) AS users, values(host) AS hosts, values(query) AS queries BY threat',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1190', 'T1505', 'T1110'],
    notes: ['Enable MySQL general log only for short-term forensics (performance impact)', 'Audit log plugin provides better production logging', 'Restrict LOAD DATA LOCAL INFILE and FILE privilege']
  }),

  postgresql: (ctx, sev) => ({
    platform: 'PostgreSQL',
    language: 'pgAudit/Log',
    type: 'Database',
    icon: '🐘',
    description: 'PostgreSQL security monitoring — ' + ctx.slice(0, 80),
    query: [
      '// PostgreSQL pgAudit Log Detection',
      '// Requires pgaudit extension: log = "all" in postgresql.conf',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="postgresql:audit" OR sourcetype="postgresql:csv"',
      '| eval threat=case(',
      '    match(command_tag, "(?i)(COPY|EXECUTE|DO)") AND match(command_text, "(?i)(pg_read_file|lo_read|pg_ls_dir)"), "OS File Access",',
      '    match(command_text, "(?i)(create.+extension|alter.+system|pg_reload_conf)"), "Config Tamper",',
      '    match(command_text, "(?i)(create.+(role|user)|grant.+(superuser|replication))"), "Priv Escalation",',
      '    match(command_text, "(?i)(union.+select|pg_sleep|extract.+epoch)"), "SQLi",',
      '    error_severity IN ("FATAL","PANIC") AND count > 5, "Auth Failure Spike",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(session_user) AS users, values(database) AS dbs BY threat, connection_from',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1190', 'T1078', 'T1505'],
    notes: ['Install pgaudit for detailed query logging', 'Alert on superuser creation outside maintenance windows', 'COPY TO/FROM PROGRAM is equivalent to OS command execution']
  }),

  // ── Identity / Endpoint generators ──────────────────────────────────────────

  sysmon: (ctx, sev) => ({
    platform: 'Sysmon',
    language: 'WinEventLog/SPL',
    type: 'Endpoint',
    icon: '🔧',
    description: 'Sysmon event detection — ' + ctx.slice(0, 80),
    query: [
      '// Sysmon Event Log Detection',
      '// Source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
      '',
      '// === SPLUNK SPL ===',
      'index=* source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
      '| eval risk=case(',
      '    EventID=1  AND match(ParentImage, "(?i)(WINWORD|EXCEL|OUTLOOK|POWERPNT|AcroRd32|chrome|firefox)"),  "Suspicious Process Parent",',
      '    EventID=3  AND NOT match(DestinationIp, "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.0)"), "Outbound C2",',
      '    EventID=7  AND match(ImageLoaded, "(?i)AppData|Temp|Downloads") AND NOT match(Signature, "^Microsoft"), "Unsigned DLL Load",',
      '    EventID=8,                                                                    "CreateRemoteThread",',
      '    EventID=10 AND match(TargetImage, "(?i)lsass\\.exe") AND NOT match(SourceImage, "(?i)(csrss|winlogon|werfault|MsMpEng)"), "LSASS Access",',
      '    EventID=12 OR EventID=13 AND match(TargetObject, "(?i)(\\\\Run\\\\|\\\\RunOnce\\\\|\\\\Winlogon\\\\|IFEO)"), "Registry Persistence",',
      '    EventID=22 AND match(QueryName, "(?i)(pastebin|ngrok|serveo|\\.onion|\\.xyz|DGA-[a-z]{8,15}\\.)"),        "Suspicious DNS",',
      '    true(), null()',
      '  )',
      '| where isnotnull(risk)',
      '| stats count, values(Image) AS processes, values(TargetImage) AS targets',
      '    BY ComputerName, User, EventID, risk',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1059', 'T1071', 'T1055', 'T1003.001', 'T1547.001'],
    notes: ['Use SwiftOnSecurity or Olaf Hartong Sysmon config for comprehensive coverage', 'EventID 10 (LSASS access) = credential dumping — highest priority', 'Tune EventID 1 with known-good parent-child process pairs']
  }),

  exchange: (ctx, sev) => ({
    platform: 'Exchange',
    language: 'Message Tracking/SPL',
    type: 'Email',
    icon: '📧',
    description: 'Exchange server security — ' + ctx.slice(0, 80),
    query: [
      '// Exchange Message Tracking & Audit Log Detection',
      '',
      '// === SPLUNK SPL (Message Tracking Logs) ===',
      'index=* sourcetype="MSExchange:MessageTracking" OR sourcetype="o365:management:activity"',
      '| eval threat=case(',
      '    match(RecipientStatus, "(?i)(fail|bounce)") AND count > 50, "Mail Flood/Backscatter",',
      '    match(SenderAddress, "(?i)(@spoofed|@malicious|no-reply@.{1,8}\\.)"),       "Phishing Sender",',
      '    match(Subject, "(?i)(password|invoice|urgent|verify|account|suspended)") AND match(MessageId, "^<[a-z0-9]{30,}@"), "Phishing Keywords",',
      '    Operation="Set-Mailbox" AND match(Parameters, "(?i)(ForwardingSmtpAddress|DeliverToMailboxAndForward)"), "Email Forwarding Rule",',
      '    Operation IN ("New-InboxRule","Set-InboxRule") AND match(Parameters, "(?i)(DeleteMessage|MarkAsRead|MoveToFolder)"), "Auto-Delete Rule",',
      '    match(ClientIPAddress, "^(?!(10\\.|192\\.168\\.|172\\.1[6-9]\\.|172\\.2[0-9]\\.|172\\.3[01]\\.|127\\.))"),  "External OWA Access",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(SenderAddress) AS senders, values(RecipientAddress) AS recipients BY threat, ClientIPAddress',
      '| sort -count',
      '',
      '// === CRITICAL: Check for forwarding rules ===',
      '// Get-InboxRule -Mailbox * | Where {$_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo}'
    ].join('\n'),
    mitre: ['T1114.002', 'T1566.001', 'T1078.004'],
    notes: ['Enable Message Tracking logs (enabled by default, 30-day retention)', 'Alert on ANY external mail forwarding rule creation', 'Monitor for mailbox delegation changes (Send-As, Full Access)']
  }),

  iam: (ctx, sev) => ({
    platform: 'IAM Logs',
    language: 'Auth/SPL',
    type: 'Identity',
    icon: '🔐',
    description: 'Identity & Access Management detection — ' + ctx.slice(0, 80),
    query: [
      '// IAM / Authentication Log Detection',
      '// Sources: LDAP, RADIUS, Okta, ADFS, Azure AD',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype IN ("okta:im2", "ActiveDirectory", "adfs", "radius")',
      '| eval threat=case(',
      '    match(outcome.result, "(?i)(FAILURE|DENIED|FAILED)") AND count > 10,          "Brute Force",',
      '    match(target{}.type, "(?i)(AppUser|User)") AND eventType="user.account.update_password" AND NOT match(actor.alternateId, ".*@yourdomain\\.com"), "External Passwd Reset",',
      '    eventType="application.lifecycle.update" AND match(target{}.displayName, "(?i)(admin|root|privileged)"), "Privilege App Change",',
      '    match(authenticationContext.authenticationStep, "(?i)(MFA)") AND outcome.result="FAILURE" AND count > 3, "MFA Fatigue",',
      '    match(securityContext.asOrg, "(?i)(tor|proxy|vpn|anonymous|datacenter)"),      "Anonymizer Login",',
      '    eventType="user.lifecycle.deactivate" AND actor.id != "service-account-id",    "Manual Deactivation",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(actor.alternateId) AS users, values(client.ipAddress) AS ips',
      '    BY threat, displayMessage',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1110', 'T1621', 'T1078', 'T1098'],
    notes: ['Okta System Log: use /api/v1/logs with since/until parameters', 'Alert on impossible travel (same user, different country, <1 hour)', 'Monitor service account authentication outside business hours']
  }),

  proxy: (ctx, sev) => ({
    platform: 'Proxy Logs',
    language: 'Squid/SPL',
    type: 'Network',
    icon: '🌐',
    description: 'Proxy log analysis — ' + ctx.slice(0, 80),
    query: [
      '// Web Proxy (Squid/Bluecoat/Zscaler) Detection',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype IN ("squid", "bluecoat:proxysg", "zscaler:proxy")',
      '| eval threat=case(',
      '    match(cs_url, "(?i)(pastebin|raw\\.githubusercontent|hastebin|ghostbin|transfer\\.sh)"),    "Data Staging Site",',
      '    match(cs_url, "(?i)(\\.onion\\.|ngrok\\.io|serveo\\.net|\\.xyz\\/[a-z0-9]{8,})"),          "C2 Infrastructure",',
      '    sc_bytes > 50000000 AND match(cs_method, "POST|PUT"),                                      "Large Upload/Exfil",',
      '    match(cs_useragent, "(?i)(curl|wget|python-requests|go-http|PowerShell)"),                  "Non-Browser UA",',
      '    match(c_ip, "\\d+") AND count > 500 AND sc_time < 2,                                       "Beaconing Pattern",',
      '    cs_categories IN ("Malware", "Phishing", "C2", "Newly Registered Domain"),                 "Threat Category",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, dc(cs_url) AS unique_urls, sum(sc_bytes) AS total_bytes',
      '    BY c_ip, cs_username, threat',
      '| eval total_mb=round(total_bytes/1048576, 2)',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1071.001', 'T1048', 'T1568'],
    notes: ['SSL inspection required to see HTTPS payload destinations', 'Beacon detection: look for regular intervals ±10% variance', 'Alert on >100MB uploads to non-corporate destinations']
  }),

  // ── Network generators ───────────────────────────────────────────────────────

  firewall: (ctx, sev) => ({
    platform: 'Firewall',
    language: 'NetFlow/SPL',
    type: 'Network',
    icon: '🔥',
    description: 'Firewall log analysis — ' + ctx.slice(0, 80),
    query: [
      '// Firewall Log Detection (Palo Alto / Fortinet / Cisco / pfSense)',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype IN ("pan:traffic", "fortigate", "cisco:asa", "pfsense")',
      '| eval threat=case(',
      '    action="deny" AND dest_port IN (22, 3389, 445, 1433, 3306) AND count > 20,  "Port Probe",',
      '    action="allow" AND dest_port IN (4444, 1337, 8080) AND NOT match(dest_ip, "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)"), "Suspicious Outbound",',
      '    match(app, "(?i)(tor|bittorrent|megaupload|teamviewer)"),                   "Unauthorized App",',
      '    bytes_out > 104857600 AND NOT match(dest_ip, "^(10\\.|192\\.168\\.|172\\.)"), "Large Exfil",',
      '    action="allow" AND match(src_country, "(RU|CN|KP|IR|SY)") AND dest_zone="internal", "High-Risk Country",',
      '    count > 1000 AND dc(dest_port) > 100,                                       "Port Scan",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(dest_port) AS ports, sum(bytes_out) AS total_out',
      '    BY src_ip, dest_ip, threat, action',
      '| eval MB_out=round(total_out/1048576, 2)',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1046', 'T1048', 'T1071'],
    notes: ['Enable application identification (App-ID on Palo Alto)', 'Geo-blocking: alert do not block — investigate first', 'Large outbound over 100MB to single external IP = exfiltration']
  }),

  network: (ctx, sev) => ({
    platform: 'Network Devices',
    language: 'Syslog/SPL',
    type: 'Network',
    icon: '🌐',
    description: 'Network device syslog detection — ' + ctx.slice(0, 80),
    query: [
      '// Network Device Syslog Detection (Cisco/Juniper/Aruba)',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="syslog" (source="router" OR source="switch" OR source="ap")',
      '| eval threat=case(',
      '    match(_raw, "(?i)(config.change|configuration changed|archive config)") AND NOT match(_raw, "scheduled backup"), "Config Change",',
      '    match(_raw, "(?i)(authentication fail|login fail|invalid password).+console"),                                  "Console Brute Force",',
      '    match(_raw, "(?i)(CDP|LLDP).+changed") AND count > 5,                                                          "Network Recon",',
      '    match(_raw, "(?i)(spanning.tree.+change|topology change|port.+flapping)"),                                     "STP Manipulation",',
      '    match(_raw, "(?i)(mac.address.+flood|cam.table.+full|broadcast.storm)"),                                       "MAC Flood",',
      '    match(_raw, "(?i)(vlan.+change|trunk.+modify|allowed.vlan)"),                                                   "VLAN Hopping",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(host) AS devices BY threat',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1557', 'T1598', 'T1562.007'],
    notes: ['Enable SNMP traps for config changes', 'Alert on any out-of-band config changes immediately', 'Correlate with authentication logs for insider threat detection']
  }),

  zeek: (ctx, sev) => ({
    platform: 'Zeek/Bro',
    language: 'Zeek/SPL',
    type: 'Network IDS',
    icon: '🔍',
    description: 'Zeek network detection — ' + ctx.slice(0, 80),
    query: [
      '// Zeek Network Security Monitor Detection',
      '// Log types: conn.log, dns.log, http.log, ssl.log, weird.log, notice.log',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype IN ("bro:conn:json", "zeek:conn:json", "bro:http:json", "bro:dns:json")',
      '| eval threat=case(',
      '    sourcetype IN ("bro:dns:json","zeek:dns:json") AND match(query, "(?i)([a-z0-9]{15,}\\.){3,}"), "DNS Tunneling/DGA",',
      '    sourcetype IN ("bro:http:json","zeek:http:json") AND match(uri, "(?i)(\\.\\.[\\/]|/etc/|cmd\\.exe|powershell)"), "Web Attack",',
      '    sourcetype IN ("bro:conn:json","zeek:conn:json") AND orig_bytes > 10000000 AND NOT match(id_resp_h, "^(10\\.|192\\.168\\.|172\\.)"), "Large Exfil",',
      '    match(service, "ftp-data") AND orig_bytes > 1000000,                                             "FTP Exfil",',
      '    match(conn_state, "(S0|REJ|RSTO)") AND count > 50 AND dc(id_resp_p) > 20,                       "Port Scan",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, dc(id_resp_p) AS ports, sum(orig_bytes) AS bytes_out BY id_orig_h, threat',
      '| eval MB_out=round(bytes_out/1048576, 2)',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1071.004', 'T1190', 'T1048', 'T1046'],
    notes: ['Zeek scripts available at github.com/zeek/zeek-scripts', 'dns.log query length > 100 chars = DNS tunneling indicator', 'weird.log contains anomalies that dont fit normal protocols']
  }),

  suricata: (ctx, sev) => ({
    platform: 'Suricata',
    language: 'EVE-JSON/SPL',
    type: 'IDS/IPS',
    icon: '⚡',
    description: 'Suricata IDS/IPS detection — ' + ctx.slice(0, 80),
    query: [
      '// Suricata EVE JSON Log Analysis',
      '// Suricata output: /var/log/suricata/eve.json',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="suricata" OR sourcetype="suricata:eve"',
      '| eval threat=case(',
      '    event_type="alert" AND alert.category IN ("Exploit Kit","Malware Command and Control","Targeted Malicious Activity"), "High Severity Alert",',
      '    event_type="alert" AND match(alert.signature, "(?i)(ET EXPLOIT|ET CURRENT EVENTS|ET TROJAN)"),   "Emerging Threats Alert",',
      '    event_type="alert" AND alert.severity=1,                                                         "Critical Signature",',
      '    event_type="dns" AND match(dns.rrname, "[a-z0-9]{12,}\\.[a-z]{2,3}$") AND dns.rcode="NOERROR",  "Possible DGA Domain",',
      '    event_type="http" AND match(http.url, "(?i)(JNDI|\\$\\{|cmd=|exec=)"),                           "Exploit Attempt",',
      '    event_type="alert" AND match(alert.signature, "(?i)(SCAN|Nmap|masscan)"),                        "Scan Activity",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, values(alert.signature) AS sigs, values(dest_ip) AS targets',
      '    BY src_ip, threat, alert.category',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1190', 'T1046', 'T1568', 'T1071'],
    notes: ['Enable ET Open or ET Pro rulesets for best coverage', 'Review dropped_alerts.log to catch blocked attacks', 'Tune rules with threshold.conf to reduce false positives']
  }),

  // ── Cloud generators ─────────────────────────────────────────────────────────

  aws: (ctx, sev) => ({
    platform: 'AWS CloudTrail',
    language: 'SQL/Athena',
    type: 'Cloud',
    icon: '☁️',
    description: 'AWS CloudTrail detection — ' + ctx.slice(0, 80),
    query: [
      '// AWS CloudTrail Security Detection',
      '// Query via Athena, Splunk CIM, or Elastic CloudTrail integration',
      '',
      '// === ATHENA SQL ===',
      "SELECT useridentity.arn, useridentity.type, eventsource, eventname,",
      '       sourceipaddress, useragent, errorcode, requestparameters,',
      "       eventtime",
      "FROM cloudtrail_logs",
      "WHERE eventsource IN (",
      "    'iam.amazonaws.com', 'sts.amazonaws.com', 's3.amazonaws.com',",
      "    'ec2.amazonaws.com', 'cloudtrail.amazonaws.com', 'kms.amazonaws.com'",
      ")",
      "AND (",
      "    -- Privilege escalation",
      "    (eventname IN ('CreateAccessKey','CreateLoginProfile','AttachUserPolicy','PutUserPolicy','UpdateLoginProfile') AND useridentity.type != 'IAMUser')",
      "    -- Defense evasion",
      "    OR eventname IN ('DeleteTrail','StopLogging','PutEventSelectors','DisableKey')",
      "    -- Data exposure",
      "    OR (eventname = 'PutBucketAcl' AND requestparameters LIKE '%AuthenticatedUsers%')",
      "    -- Lateral movement",
      "    OR (eventname = 'AssumeRole' AND useridentity.arn LIKE '%:assumed-role%'",
      "        AND sourceipaddress NOT LIKE '%.amazonaws.com')",
      ")",
      "AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR",
      "ORDER BY eventtime DESC",
      '',
      '// === SPLUNK (Splunk App for AWS) ===',
      '// index=aws sourcetype=aws:cloudtrail errorCode=AccessDenied | stats count by user, eventName | where count > 5'
    ].join('\n'),
    mitre: ['T1078.004', 'T1548', 'T1530', 'T1562.008'],
    notes: ['Enable CloudTrail in ALL regions including us-east-1', 'Send to S3 + CloudWatch Logs for real-time alerting', 'GuardDuty findings should trigger immediate investigation']
  }),

  azure: (ctx, sev) => ({
    platform: 'Azure Activity',
    language: 'KQL',
    type: 'Cloud',
    icon: '🌤',
    description: 'Azure Activity Log detection — ' + ctx.slice(0, 80),
    query: [
      '// Azure Activity Log — Kusto Query Language',
      '',
      'AzureActivity',
      '| where TimeGenerated >= ago(24h)',
      '| extend threat = case(',
      '    OperationNameValue has_any ("Microsoft.Authorization/roleAssignments/write","Microsoft.Authorization/policyAssignments/delete"), "RBAC/Policy Change",',
      '    OperationNameValue has_any ("Microsoft.Network/networkSecurityGroups/securityRules/write","Microsoft.Network/networkSecurityGroups/write"), "NSG Modification",',
      '    OperationNameValue has_any ("Microsoft.Compute/virtualMachines/delete","Microsoft.Storage/storageAccounts/delete"), "Resource Deletion",',
      '    OperationNameValue has_any ("Microsoft.Insights/diagnosticSettings/delete","microsoft.insights/activityLogAlerts/delete"), "Logging Disabled",',
      '    OperationNameValue has_any ("Microsoft.KeyVault/vaults/secrets/read","Microsoft.KeyVault/vaults/keys/read"), "Key Vault Access",',
      '    ActivityStatus =~ "Failed" and count() > 5, "Authorization Failures",',
      '    true(), ""',
      '  )',
      '| where isnotempty(threat)',
      '| summarize count(), make_set(OperationNameValue), make_set(CallerIpAddress)',
      '    by Caller, threat, ActivityStatusValue',
      '| sort by count_ desc'
    ].join('\n'),
    mitre: ['T1078.004', 'T1562', 'T1552', 'T1548'],
    notes: ['Enable Diagnostic Settings on all subscriptions to Log Analytics', 'Microsoft Sentinel has built-in Azure Activity analytics rules', 'Alert on any Key Vault access outside normal service principal activity']
  }),

  gcp: (ctx, sev) => ({
    platform: 'GCP Audit',
    language: 'BigQuery SQL',
    type: 'Cloud',
    icon: '🌀',
    description: 'GCP Cloud Audit detection — ' + ctx.slice(0, 80),
    query: [
      '// GCP Cloud Audit Log Detection — BigQuery',
      '',
      'SELECT',
      '  protopayload_auditlog.authenticationInfo.principalEmail AS principal,',
      '  resource.type AS resource_type,',
      '  protopayload_auditlog.methodName AS method,',
      '  protopayload_auditlog.requestMetadata.callerIp AS caller_ip,',
      '  timestamp,',
      '  CASE',
      "    WHEN protopayload_auditlog.methodName LIKE '%setIamPolicy%' THEN 'IAM Policy Change'",
      "    WHEN protopayload_auditlog.methodName LIKE '%serviceAccounts%.create%' THEN 'SA Created'",
      "    WHEN protopayload_auditlog.methodName LIKE '%firewall%insert%' THEN 'Firewall Rule Added'",
      "    WHEN protopayload_auditlog.methodName LIKE '%storage%.setIamPolicy%' THEN 'Bucket ACL Change'",
      "    WHEN protopayload_auditlog.methodName LIKE '%cloudresourcemanager%' THEN 'Org Policy Change'",
      '  END AS threat',
      "FROM `[PROJECT].cloudaudit_googleapis_com_activity_*`",
      "WHERE _TABLE_SUFFIX >= FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY))",
      "  AND threat IS NOT NULL",
      "  AND protopayload_auditlog.authenticationInfo.principalEmail NOT LIKE '%gserviceaccount.com'",
      "ORDER BY timestamp DESC",
      "LIMIT 1000"
    ].join('\n'),
    mitre: ['T1078.004', 'T1548', 'T1530'],
    notes: ['Enable Data Access audit logs for sensitive datasets', 'Org Policy changes require immediate review', 'VPC Service Controls violations = potential data exfil attempt']
  }),

  cloudflare: (ctx, sev) => ({
    platform: 'Cloudflare',
    language: 'Logpull/SPL',
    type: 'Cloud/CDN',
    icon: '🌐',
    description: 'Cloudflare log detection — ' + ctx.slice(0, 80),
    query: [
      '// Cloudflare Logpush / Logpull Detection',
      '// Enable: Cloudflare Dashboard → Logs → Logpush to S3/Splunk/Elastic',
      '',
      '// === SPLUNK SPL ===',
      'index=* sourcetype="cloudflare:logpull" OR sourcetype="cloudflare:json"',
      '| eval threat=case(',
      '    WAFAction="block" AND WAFRuleGroup IN ("Drupal","WordPress","Log4j","CVE"),  "WAF Block — Known Exploit",',
      '    EdgeResponseStatus IN (429, 503) AND count > 100,                           "Rate Limit/DDoS",',
      '    FirewallMatchAction="block" AND match(ClientRequestPath, "(?i)(\\.\\.[\\/]|etc/passwd|/proc/)"), "Path Traversal Blocked",',
      '    BotScore < 30 AND NOT BotScoreSrc IN ("Verified Bot","Not Computed"),        "Bot Traffic",',
      '    WAFAction="allow" AND match(ClientRequestPath, "(?i)(admin|wp-login|phpmyadmin|\.git)"), "Admin Path Probe",',
      '    ClientCountry IN ("KP","SY","CU") AND WAFAction="allow",                    "Sanctioned Country Bypass",',
      '    true(), null()',
      '  )',
      '| where isnotnull(threat)',
      '| stats count, dc(ClientRequestPath) AS unique_paths BY ClientIP, threat, WAFAction',
      '| sort -count'
    ].join('\n'),
    mitre: ['T1190', 'T1595', 'T1071.001'],
    notes: ['Enable Cloudflare WAF and Bot Management for best detection', 'Review WAF allow logs — attackers probe for bypass vectors', 'DDoS > 10k req/min should trigger automatic mitigation']
  }),

};

/**
 * Generate queries for specified platforms
 * @param {string} context - Threat scenario
 * @param {string[]} tools  - Tool IDs to generate for
 * @param {string} severity - LOW | MED | HIGH | CRIT
 * @returns {object[]}
 */
function generateQueries(context, tools, severity) {
  const sev = ['LOW', 'MED', 'HIGH', 'CRIT'].includes(severity) ? severity : 'MED';
  const results = [];

  for (const tool of tools) {
    if (generators[tool]) {
      try {
        results.push({
          id: tool,
          ...generators[tool](clean(context), sev),
          generatedAt: now()
        });
      } catch (err) {
        console.error('Generator error for ' + tool + ':', err.message);
      }
    }
  }

  return results;
}

module.exports = { generateQueries };
