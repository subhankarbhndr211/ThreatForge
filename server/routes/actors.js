'use strict';
const express = require('express');
const router = express.Router();

const ACTORS = [

  // ═══════════════════════════════════════════════════════
  // 🇷🇺 RUSSIA — STATE ACTORS
  // ═══════════════════════════════════════════════════════
  {
    id: 'apt29', name: 'APT29 / Cozy Bear', aliases: ['The Dukes', 'YTTRIUM', 'Midnight Blizzard', 'NOBELIUM', 'UNC2452'],
    icon: '🐻', origin: 'Russia', sponsor: 'SVR (Foreign Intelligence Service)', motivation: 'Espionage',
    active: true, severity: 'CRIT', type: 'Nation-State',
    targets: ['Government', 'Defense', 'Think Tanks', 'Healthcare', 'Technology', 'Political Parties'],
    campaigns: ['SolarWinds SUNBURST (2020)', 'COVID-19 Vaccine Research Theft (2020)', 'Microsoft Email Breach (2024)', 'Democratic National Committee (2016)', 'Norwegian Government (2023)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566.001', name: 'Spearphishing Link' },
      { tactic: 'Initial Access', technique: 'T1195.002', name: 'Supply Chain: Software' },
      { tactic: 'Persistence', technique: 'T1053.005', name: 'Scheduled Task' },
      { tactic: 'Persistence', technique: 'T1078.004', name: 'Valid Cloud Accounts' },
      { tactic: 'Credential Access', technique: 'T1003.006', name: 'DCSync' },
      { tactic: 'Lateral Movement', technique: 'T1550.001', name: 'Application Access Token' },
      { tactic: 'Command & Control', technique: 'T1102', name: 'Web Service C2' },
      { tactic: 'Exfiltration', technique: 'T1567.002', name: 'Exfil to Cloud Storage' },
    ],
    tools: ['SUNBURST', 'SUNSPOT', 'TEARDROP', 'BEATDROP', 'GraphSteel', 'CobaltStrike', 'WellMess', 'WellMail', 'MagicWeb', 'FOGGYWEB'],
    detection_tips: [
      'Monitor for SUNBURST DGA patterns: avsvmcloud[.]com subdomains',
      'Alert on DCSync: EventID 4662 with replication properties from non-DC',
      'Monitor OAuth token abuse: impossible travel + new OAuth app grants',
      'Hunt for MagicWeb: ADFS claims manipulation via modified dll',
      'Alert on Midnight Blizzard: Microsoft Graph API access from new app registrations',
    ],
    hunt_queries: {
      splunk: 'index=* (EventCode=4662 Properties="*1131f6ad*") OR (sourcetype=o365 Operation=Add_member_to_role) | stats count by user, src_ip | sort -count',
      sentinel: 'SigninLogs | where AuthenticationRequirement == "multiFactorAuthentication" | where ResultType in ("500121","50158") | summarize count() by UserPrincipalName, IPAddress | order by count_ desc'
    },
    iocs: { domains: ['avsvmcloud.com', 'freescanonline.com', 'deftsecurity.com'], ips: [] }
  },

  {
    id: 'apt28', name: 'APT28 / Fancy Bear', aliases: ['Sofacy', 'STRONTIUM', 'Forest Blizzard', 'Pawn Storm', 'Sednit'],
    icon: '🐻', origin: 'Russia', sponsor: 'GRU (Unit 26165)', motivation: 'Espionage / Influence Operations',
    active: true, severity: 'CRIT', type: 'Nation-State',
    targets: ['Military', 'Government', 'NATO', 'Political Organizations', 'Media', 'Defense'],
    campaigns: ['DNC Hack & Podesta Emails (2016)', 'Olympic Destroyer (2018)', 'Norwegian Parliament (2020)', 'German Bundestag (2015)', 'CVE-2023-23397 Outlook Campaign (2023)', 'Ukrainian Military Targeting (2022-2024)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566.001', name: 'Spearphishing' },
      { tactic: 'Initial Access', technique: 'T1566.002', name: 'Spearphishing Link' },
      { tactic: 'Execution', technique: 'T1059.001', name: 'PowerShell' },
      { tactic: 'Persistence', technique: 'T1547.001', name: 'Registry Run Keys' },
      { tactic: 'Credential Access', technique: 'T1550.002', name: 'Pass-the-Hash' },
      { tactic: 'Credential Access', technique: 'T1557.001', name: 'LLMNR/NBT-NS Poisoning' },
      { tactic: 'Collection', technique: 'T1114', name: 'Email Collection' },
      { tactic: 'Exfiltration', technique: 'T1048', name: 'Exfil over Alternative Protocol' },
    ],
    tools: ['X-Agent (CHOPSTICK)', 'X-Tunnel', 'Sofacy', 'LoJax (UEFI rootkit)', 'Zebrocy', 'Drovorub (Linux)', 'GooseEgg', 'OwlProxy'],
    detection_tips: [
      'CVE-2023-23397: Alert on Outlook meeting UNC path to attacker SMB server',
      'Monitor for LoJax: UEFI SPI flash write from OS level - extremely rare',
      'Hunt GooseEgg: netlogon exploit artifacts, printnightmare-style exploitation',
      'Alert on LLMNR/NBT-NS spoofing: Responder tool signatures in network logs',
      'Monitor for X-Agent: Encrypted communications to hardcoded C2 IPs',
    ],
    hunt_queries: {
      splunk: 'index=* sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3 | stats count by user, src_ip, dest | where count > 5 | sort -count',
      sentinel: 'DeviceNetworkEvents | where RemotePort == 445 and InitiatingProcessFileName !in~ ("System","svchost.exe") | summarize count() by DeviceName, RemoteIP, InitiatingProcessFileName'
    },
    iocs: { domains: ['worldnewsonline.eu', 'sendmevideo.net'], ips: [] }
  },

  {
    id: 'sandworm', name: 'Sandworm', aliases: ['BlackEnergy', 'TeleBots', 'Voodoo Bear', 'IRIDIUM', 'Seashell Blizzard'],
    icon: '🐛', origin: 'Russia', sponsor: 'GRU (Unit 74455)', motivation: 'Destruction / Sabotage',
    active: true, severity: 'CRIT', type: 'Nation-State',
    targets: ['Energy', 'Critical Infrastructure', 'Ukraine Government', 'Financial Sector', 'Olympics'],
    campaigns: ['NotPetya (2017) - most destructive cyberattack in history', 'Ukrainian Power Grid Attack (2015, 2016)', 'Olympic Destroyer (2018)', 'Ukrainian Wiper Campaigns (2022-2024)', 'Georgia DDOS during war (2008)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit Public-Facing Application' },
      { tactic: 'Execution', technique: 'T1059.003', name: 'Windows Command Shell' },
      { tactic: 'Impact', technique: 'T1485', name: 'Data Destruction' },
      { tactic: 'Impact', technique: 'T1561', name: 'Disk Wipe' },
      { tactic: 'Lateral Movement', technique: 'T1210', name: 'Exploitation of Remote Services' },
      { tactic: 'Command & Control', technique: 'T1071.001', name: 'Web Protocols C2' },
    ],
    tools: ['NotPetya', 'KillDisk', 'Industroyer/CRASHOVERRIDE', 'Industroyer2', 'CaddyWiper', 'HermeticWiper', 'WhisperGate', 'Prestige Ransomware'],
    detection_tips: [
      'Alert on MBR overwrites: low-level disk write to sector 0 from user processes',
      'Hunt Industroyer2: IEC-104 protocol abuse on OT networks',
      'Monitor for wiper patterns: mass file deletion + VSS deletion + MBR clear',
      'Alert on WhisperGate: MBR-overwriting + file-corrupting payload stages',
      'Critical infrastructure: any unauthorized ICS/SCADA protocol traffic',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 (CommandLine="*vssadmin*delete*" OR CommandLine="*bcdedit*no*" OR CommandLine="*wmic*shadowcopy*delete*") | stats count by host, user, CommandLine',
      sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("vssadmin delete","bcdedit /set recoveryenabled no","wmic shadowcopy delete") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'cozy-bear-cloud', name: 'Midnight Blizzard (SVR Cloud Ops)', aliases: ['NOBELIUM Cloud', 'APT29-Cloud'],
    icon: '❄️', origin: 'Russia', sponsor: 'SVR', motivation: 'Espionage via Cloud Services',
    active: true, severity: 'CRIT', type: 'Nation-State',
    targets: ['Government Cloud Tenants', 'Microsoft 365', 'Azure AD', 'Tech Companies'],
    campaigns: ['Microsoft Corporate Email Breach (Jan 2024)', 'HPE Email Breach (2023)', 'TeamCity CI/CD Attack (2023)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1078.004', name: 'Valid Cloud Accounts' },
      { tactic: 'Persistence', technique: 'T1098.001', name: 'Additional Cloud Credentials' },
      { tactic: 'Collection', technique: 'T1114.002', name: 'Remote Email Collection' },
      { tactic: 'Defense Evasion', technique: 'T1550.001', name: 'Application Access Token' },
    ],
    tools: ['FOGGYWEB', 'MagicWeb', 'ROOTSAW', 'BoomBox', 'NativeZone', 'EnvyScout'],
    detection_tips: [
      'Alert on new OAuth app registrations with Mail.Read permissions in Entra ID',
      'Hunt for ADFS DLL modifications: Microsoft.IdentityServer.Servicehost.exe unusual modules',
      'Monitor service principal credential additions to existing apps',
      'Alert on SAML token forgery: logins without matching sign-in risk events',
    ],
    hunt_queries: {
      splunk: 'index=o365 Operation IN ("Add service principal credentials","Update application") | stats count by UserId, ObjectId | sort -count',
      sentinel: 'AuditLogs | where OperationName in ("Add service principal credentials","Add OAuth2PermissionGrant") | project TimeGenerated, InitiatedBy, TargetResources'
    },
    iocs: { domains: [], ips: [] }
  },

  // ═══════════════════════════════════════════════════════
  // 🇨🇳 CHINA — STATE ACTORS
  // ═══════════════════════════════════════════════════════
  {
    id: 'apt41', name: 'APT41 / Double Dragon', aliases: ['Winnti', 'Barium', 'Wicked Panda', 'Bronze Atlas', 'Brass Typhoon'],
    icon: '🐉', origin: 'China', sponsor: 'MSS (Ministry of State Security)', motivation: 'Espionage + Financial Crime',
    active: true, severity: 'CRIT', type: 'Nation-State',
    targets: ['Healthcare', 'Pharmaceuticals', 'Technology', 'Telecoms', 'Finance', 'Gaming Industry'],
    campaigns: ['COVID-19 Research Theft (2020)', 'US State Government Attacks (2021)', 'ManageEngine Exploitation (2023)', 'ShadowPad Supply Chain (2017)', 'CCleaner Supply Chain (2017)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1195.002', name: 'Supply Chain Compromise' },
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit Public-Facing Application' },
      { tactic: 'Persistence', technique: 'T1543.003', name: 'Windows Service' },
      { tactic: 'Defense Evasion', technique: 'T1036', name: 'Masquerading' },
      { tactic: 'Credential Access', technique: 'T1003', name: 'OS Credential Dumping' },
      { tactic: 'Command & Control', technique: 'T1573', name: 'Encrypted Channel' },
    ],
    tools: ['ShadowPad', 'PlugX', 'Cobalt Strike', 'MESSAGETAP', 'DEADEYE', 'KEYPLUG', 'Speculoos', 'CrossWalk'],
    detection_tips: [
      'Hunt ShadowPad: encrypted plugin-based RAT hiding in legitimate software',
      'Alert on PlugX: DLL side-loading from legitimate signed executables',
      'Monitor gaming studio networks for unusual crypto transactions (financial motive)',
      'Hunt MESSAGETAP: SS7 telecom network traffic interception',
      'Alert on ManageEngine zero-days: unusual Java process spawning shell',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=7045 NOT (ServiceName="WinDefend" OR ServiceName="MpsSvc") | stats count by ServiceName, ServiceFileName, host | sort -count',
      sentinel: 'DeviceProcessEvents | where InitiatingProcessFileName has_any ("svchost.exe","services.exe") | where FileName has_any ("powershell.exe","cmd.exe") | where ProcessCommandLine has_any ("-enc","-nop","-w hidden") | project TimeGenerated, DeviceName, ProcessCommandLine'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'volt-typhoon', name: 'Volt Typhoon', aliases: ['VANGUARD PANDA', 'Bronze Silhouette', 'Dev-0391', 'UNC3236'],
    icon: '⚡', origin: 'China', sponsor: 'PLA (People\'s Liberation Army)', motivation: 'Pre-positioning for conflict / Critical Infrastructure',
    active: true, severity: 'CRIT', type: 'Nation-State',
    targets: ['US Critical Infrastructure', 'Military Bases', 'Power Grid', 'Water Systems', 'Comms', 'Guam Military'],
    campaigns: ['US Critical Infrastructure Pre-positioning (2021-2024)', 'Guam Military Network Compromise', 'CISA/FBI/NSA Joint Advisory (Feb 2024)', 'KV-Botnet SOHO Router Campaign'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit Public-Facing Application' },
      { tactic: 'Execution', technique: 'T1059.003', name: 'Windows Command Shell LOTL' },
      { tactic: 'Defense Evasion', technique: 'T1036.003', name: 'Rename System Utilities' },
      { tactic: 'Defense Evasion', technique: 'T1218', name: 'System Binary Proxy Execution' },
      { tactic: 'Collection', technique: 'T1119', name: 'Automated Collection' },
      { tactic: 'Command & Control', technique: 'T1090.003', name: 'Proxy via Compromised Routers' },
      { tactic: 'Lateral Movement', technique: 'T1021.002', name: 'SMB/Windows Admin Shares' },
    ],
    tools: ['Living-off-the-Land (LOTL)', 'netsh', 'wmic', 'ntdsutil', 'PowerShell', 'certutil', 'cmdkey', 'net.exe', 'Impacket', 'FRP (Fast Reverse Proxy)', 'KV-Botnet'],
    detection_tips: [
      'Hunt LOTL: netsh interface portproxy commands for port forwarding',
      'Alert on ntdsutil: "activate instance ntds" for NTDS.dit extraction',
      'Monitor for cmdkey credential caching from unusual processes',
      'Hunt compromised SOHO routers used as proxy infrastructure',
      'Alert on FRP (fast reverse proxy) tool indicators',
      'Baseline legitimate admin tool usage and alert on deviations',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 (CommandLine="*netsh*portproxy*" OR CommandLine="*ntdsutil*" OR CommandLine="*cmdkey*" OR CommandLine="*wmic*process*call*create*") | stats count by host, user, CommandLine | sort -count',
      sentinel: 'DeviceProcessEvents | where FileName in~ ("netsh.exe","wmic.exe","ntdsutil.exe","cmdkey.exe") | where ProcessCommandLine has_any ("portproxy","ntds","create","delete") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'apt10', name: 'APT10 / Stone Panda', aliases: ['menuPass', 'Potassium', 'Cicada', 'Bronze Riverside', 'Cloud Hopper'],
    icon: '🐼', origin: 'China', sponsor: 'MSS (Tianjin State Security Bureau)', motivation: 'Espionage / IP Theft',
    active: true, severity: 'HIGH', type: 'Nation-State',
    targets: ['Managed Service Providers', 'Healthcare', 'Defense', 'Aerospace', 'Finance'],
    campaigns: ['Operation Cloud Hopper (2017-2019) - MSP supply chain', 'Operation Soft Cell - Telecoms', 'Japanese Defense Contractor Breaches (2019-2023)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1199', name: 'Trusted Relationship (MSP)' },
      { tactic: 'Persistence', technique: 'T1078', name: 'Valid Accounts' },
      { tactic: 'Credential Access', technique: 'T1558.003', name: 'Kerberoasting' },
      { tactic: 'Lateral Movement', technique: 'T1021.001', name: 'RDP' },
      { tactic: 'Collection', technique: 'T1039', name: 'Data from Network Shared Drive' },
      { tactic: 'Exfiltration', technique: 'T1002', name: 'Data Compressed' },
    ],
    tools: ['RedLeaves', 'PlugX', 'QuasarRAT', 'Mimikatz', 'UPPERCUT', 'ANEL'],
    detection_tips: [
      'MSP-focused: alert on RDP from MSP IP ranges to customer DCs',
      'Hunt RedLeaves: DLL side-loading with specific export function names',
      'Monitor VPN connections from MSP ranges outside business hours',
      'Alert on mass credential dumping via Mimikatz from MSP-used accounts',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4624 Logon_Type=10 | stats count by user, src_ip, dest | where count > 5 | sort -count',
      sentinel: 'SigninLogs | where AppDisplayName == "Windows Sign In" | where RiskLevelDuringSignIn != "none" | summarize count() by UserPrincipalName, IPAddress'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'salt-typhoon', name: 'Salt Typhoon', aliases: ['GhostEmperor', 'FamousSparrow'],
    icon: '🧂', origin: 'China', sponsor: 'PLA / MSS', motivation: 'Telecom Espionage / Wiretapping',
    active: true, severity: 'CRIT', type: 'Nation-State',
    targets: ['US Telecom Companies', 'ISPs', 'Government Officials Phone Records', 'AT&T/Verizon/T-Mobile'],
    campaigns: ['US Telecom Breach - CALEA Wiretap Access (2024)', 'Routers and Core Network Infiltration (2023-2024)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit Network Devices' },
      { tactic: 'Collection', technique: 'T1119', name: 'Automated Collection of Call Records' },
      { tactic: 'Collection', technique: 'T1040', name: 'Network Sniffing' },
      { tactic: 'Defense Evasion', technique: 'T1027', name: 'Obfuscated Files' },
    ],
    tools: ['SparrowDoor', 'ShadowPad', 'GhostSpider', 'Demodex (rootkit)', 'WOFSE'],
    detection_tips: [
      'Monitor core router configurations for unauthorized changes',
      'Alert on CALEA lawful intercept system access from unusual IPs',
      'Hunt for unusual data flows on SS7 and Diameter network infrastructure',
      'Monitor BGP routing table anomalies for traffic redirection',
    ],
    hunt_queries: {
      splunk: 'index=network sourcetype=router_config (action=modified OR action=created) user!="automation" | stats count by device, user, action | sort -count',
      sentinel: 'CommonSecurityLog | where DeviceVendor has_any ("Cisco","Juniper","Palo Alto") | where Activity has_any ("config changed","modified","added") | where SourceUserID !has "automation" | project TimeGenerated, Computer, Activity, SourceUserID'
    },
    iocs: { domains: [], ips: [] }
  },

  // ═══════════════════════════════════════════════════════
  // 🇰🇵 NORTH KOREA — STATE ACTORS
  // ═══════════════════════════════════════════════════════
  {
    id: 'lazarus', name: 'Lazarus Group', aliases: ['HIDDEN COBRA', 'Guardians of Peace', 'APT38', 'Whois Team', 'Zinc', 'Diamond Sleet'],
    icon: '💀', origin: 'North Korea', sponsor: 'RGB (Reconnaissance General Bureau)', motivation: 'Financial / Espionage / Disruption',
    active: true, severity: 'CRIT', type: 'Nation-State',
    targets: ['Cryptocurrency Exchanges', 'Banks (SWIFT)', 'Defense', 'Media', 'Aerospace', 'DeFi Protocols'],
    campaigns: ['Sony Pictures Hack (2014)', 'Bangladesh Bank SWIFT Heist $81M (2016)', 'WannaCry (2017)', 'Ronin Network $625M Crypto Theft (2022)', 'Harmony Horizon $100M Theft (2022)', 'Atomic Wallet $100M Theft (2023)', 'TraderTraitor - Crypto Platform Attacks (2024)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566.003', name: 'Spearphishing via Service (LinkedIn)' },
      { tactic: 'Initial Access', technique: 'T1195', name: 'Supply Chain Compromise' },
      { tactic: 'Execution', technique: 'T1204.002', name: 'Malicious File (Fake Job Offer)' },
      { tactic: 'Persistence', technique: 'T1543', name: 'Create or Modify System Process' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted for Impact' },
      { tactic: 'Impact', technique: 'T1657', name: 'Financial Theft' },
      { tactic: 'Collection', technique: 'T1560', name: 'Archive Collected Data' },
    ],
    tools: ['BLINDINGCAN', 'HOPLIGHT', 'FASTCash', 'ELECTRICFISH', 'Bookcode', 'DRATzarus', 'AppleJeus', 'ComRAT', 'PoolRAT'],
    detection_tips: [
      'Alert on AppleJeus: fake crypto apps with trojanized trading software',
      'Hunt TraderTraitor: fake VC or recruiter LinkedIn outreach with malware',
      'Monitor SWIFT: unusual transaction patterns, large round-number transfers',
      'Alert on DeFi bridge contract interactions from new addresses',
      'Hunt BLINDINGCAN: HTTP C2 with RC4 encrypted traffic',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 (CommandLine="*powershell*-enc*" OR CommandLine="*wscript*" OR CommandLine="*mshta*") ParentImage="*WINWORD*" OR ParentImage="*EXCEL*" | stats count by host, CommandLine',
      sentinel: 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","HWP.exe") | where FileName in~ ("powershell.exe","wscript.exe","mshta.exe","cmd.exe") | project TimeGenerated, DeviceName, ProcessCommandLine'
    },
    iocs: { domains: ['celasllc.com'], ips: [] }
  },

  {
    id: 'kimsuky', name: 'Kimsuky', aliases: ['Black Banshee', 'Velvet Chollima', 'APT43', 'Emerald Sleet', 'Thallium'],
    icon: '🌸', origin: 'North Korea', sponsor: 'RGB', motivation: 'Espionage / Intelligence Collection',
    active: true, severity: 'HIGH', type: 'Nation-State',
    targets: ['South Korean Government', 'US Policy Think Tanks', 'Nuclear Program Countries', 'UN Sanctions Officials', 'Journalists'],
    campaigns: ['Operation AppleSeed', 'Operation Kabar Cobra', 'Think Tank Targeting Campaign (2023)', 'UN Sanctions Experts Compromise (2023)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566', name: 'Phishing / BEC' },
      { tactic: 'Persistence', technique: 'T1547.001', name: 'Registry Run Keys' },
      { tactic: 'Collection', technique: 'T1114', name: 'Email Collection (Gold Plugins)' },
      { tactic: 'Credential Access', technique: 'T1056', name: 'Input Capture (Keylogger)' },
    ],
    tools: ['AppleSeed', 'BabyShark', 'FlowerPower', 'GoldDragon', 'CSPY Downloader', 'PebbleDash'],
    detection_tips: [
      'Hunt AppleSeed: VBS/JS-based spearphishing with HWP documents',
      'Alert on Gold plugin: Chrome/Edge browser credential theft',
      'Monitor for HWP (Hangul Word Processor) spawning unusual processes',
      'Alert on keylogger indicators: HKCU run keys writing to AppData',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 ParentImage="*hwp.exe*" | stats count by CommandLine, host',
      sentinel: 'DeviceProcessEvents | where InitiatingProcessFileName =~ "hwp.exe" | project TimeGenerated, DeviceName, ProcessCommandLine'
    },
    iocs: { domains: [], ips: [] }
  },

  // ═══════════════════════════════════════════════════════
  // 🇮🇷 IRAN — STATE ACTORS
  // ═══════════════════════════════════════════════════════
  {
    id: 'apt33', name: 'APT33 / Elfin', aliases: ['Refined Kitten', 'Magnallium', 'Holmium', 'Peach Sandstorm'],
    icon: '🦅', origin: 'Iran', sponsor: 'IRGC (Islamic Revolutionary Guard Corps)', motivation: 'Espionage / Sabotage',
    active: true, severity: 'HIGH', type: 'Nation-State',
    targets: ['Aerospace', 'Defense', 'Energy', 'Petrochemical', 'Saudi Arabia', 'US Military Contractors'],
    campaigns: ['Operation Shamoon Wiper Campaigns (2017-2018)', 'Password Spray Campaign Against Defense Contractors (2023)', 'Citrix Bleed Exploitation (2024)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1110.003', name: 'Password Spraying' },
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit VPN Vulnerabilities' },
      { tactic: 'Impact', technique: 'T1485', name: 'Data Destruction (Shamoon)' },
      { tactic: 'Persistence', technique: 'T1543', name: 'Create System Service' },
    ],
    tools: ['SHAPESHIFT', 'TURNEDUP', 'DROPSHOT', 'StoneDrill', 'Shamoon', 'DistTrack', 'Plink'],
    detection_tips: [
      'Alert on Shamoon: mass file overwrite with random data + MBR destruction',
      'Hunt password spray: many failed logins to different accounts from same IP',
      'Monitor VPN authentication for off-hours access from Iranian IP ranges',
      'Alert on Citrix NetScaler exploit patterns in web server logs',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4625 | stats dc(user) as unique_users, count by src_ip | where unique_users > 20 | sort -unique_users',
      sentinel: 'SigninLogs | where ResultType == "50126" | summarize users=dcount(UserPrincipalName), total=count() by IPAddress, bin(TimeGenerated, 1h) | where users > 15 | order by users desc'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'apt34', name: 'APT34 / OilRig', aliases: ['Helix Kitten', 'Crambus', 'Hazel Sandstorm', 'Chrysene', 'EUROPIUM'],
    icon: '⛽', origin: 'Iran', sponsor: 'Ministry of Intelligence (MOIS)', motivation: 'Espionage / Regional Influence',
    active: true, severity: 'HIGH', type: 'Nation-State',
    targets: ['Middle East Government', 'Financial', 'Energy', 'Telecom', 'Chemical'],
    campaigns: ['Targeting Middle Eastern Governments (2014-present)', 'Operation SideCopy', 'HOMERUN Campaign', 'DNS Tunneling C2 Campaign'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566.001', name: 'Spearphishing Attachment' },
      { tactic: 'Command & Control', technique: 'T1071.004', name: 'DNS Tunneling C2' },
      { tactic: 'Exfiltration', technique: 'T1048.003', name: 'Exfil Over DNS' },
      { tactic: 'Persistence', technique: 'T1505.003', name: 'Web Shell' },
    ],
    tools: ['BONDUPDATER', 'QUADAGENT', 'PICKPOCKET', 'TON', 'Helminth', 'LONGWATCH', 'ISMAgent'],
    detection_tips: [
      'Hunt DNS tunneling: long subdomains, high query rate, TXT record exfil',
      'Monitor PowerShell DNS requests for high-entropy subdomain queries',
      'Alert on web shell: unusual child processes from web server processes',
      'Hunt BONDUPDATER: scheduled tasks with PowerShell DNS communication',
    ],
    hunt_queries: {
      splunk: 'index=dns | eval domain_len=len(query) | where domain_len > 50 | stats count, avg(domain_len) by src_ip, query | where count > 20 | sort -count',
      sentinel: 'DnsEvents | extend subdomain_length = strlen(Name) | where subdomain_length > 50 | summarize count() by Computer, Name, IPAddresses | where count_ > 10'
    },
    iocs: { domains: [], ips: [] }
  },

  // ═══════════════════════════════════════════════════════
  // 💰 RANSOMWARE GROUPS (WITH FULL TTP WORKFLOWS)
  // ═══════════════════════════════════════════════════════
  {
    id: 'lockbit', name: 'LockBit 3.0 / Black', aliases: ['LockBit', 'ABCD', 'LockBit 2.0', 'LockBit 3.0', 'LockBitSupp'],
    icon: '🔒', origin: 'Russia', sponsor: 'Criminal (RaaS)', motivation: 'Financial',
    active: true, severity: 'CRIT', type: 'Ransomware',
    targets: ['All Sectors', 'Healthcare', 'Legal', 'Government', 'Manufacturing', 'Critical Infrastructure'],
    campaigns: ['ICBC Bank Attack (2023)', 'Boeing Data Theft (2023)', 'Royal Mail UK ($80M demand 2023)', 'CISA Advisory (2023)', 'CDW Attack', 'Accenture Attack (2021)'],
    attack_workflow: [
      { phase: '1. Initial Access', detail: 'Exploit RDP (CVE-2021-34527), VPN vulnerabilities, or purchase access from Initial Access Brokers (IAB). Also phishing and credential stuffing.' },
      { phase: '2. Establish Foothold', detail: 'Deploy Stealc or Raccoon info-stealer to harvest credentials, then use Cobalt Strike or Sliver C2 beacon.' },
      { phase: '3. Discovery & Recon', detail: 'BloodHound/SharpHound AD enumeration. net.exe commands to map domain. Identify backup servers and high-value targets.' },
      { phase: '4. Lateral Movement', detail: 'Pass-the-hash, Kerberoasting, PsExec/WMI lateral movement to domain controller. Compromise backup systems.' },
      { phase: '5. Credential Theft', detail: 'Mimikatz for LSASS dump. DCSync to dump all AD hashes. Harvest credentials from browser, password managers.' },
      { phase: '6. Data Exfiltration (Double Extortion)', detail: 'StealBit or Rclone to copy data to Mega.nz, FTP, or SFTP servers. 100GB-10TB often exfiltrated before encryption.' },
      { phase: '7. Pre-Encryption Prep', detail: 'Delete shadow copies (vssadmin, wbadmin). Disable backup services. Clear event logs. Stop antivirus/EDR.' },
      { phase: '8. Encryption', detail: 'AES-256 encrypted files, RSA-2048 key. Extensions randomized per victim. LockBit 3.0 is extremely fast (speed-optimized).' },
      { phase: '9. Ransom Note & Timer', detail: 'LockBit ransom note deployed. Leak site with countdown timer. DDoS threat added as pressure in some cases.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit RDP/VPN' },
      { tactic: 'Initial Access', technique: 'T1078', name: 'Valid Accounts (IAB Purchase)' },
      { tactic: 'Execution', technique: 'T1059.001', name: 'PowerShell' },
      { tactic: 'Persistence', technique: 'T1543.003', name: 'Windows Service' },
      { tactic: 'Privilege Escalation', technique: 'T1068', name: 'Exploit Vulnerability' },
      { tactic: 'Defense Evasion', technique: 'T1562.001', name: 'Disable Security Tools' },
      { tactic: 'Credential Access', technique: 'T1003.001', name: 'LSASS Memory' },
      { tactic: 'Lateral Movement', technique: 'T1550.002', name: 'Pass the Hash' },
      { tactic: 'Exfiltration', technique: 'T1048', name: 'Exfil over Alternative Protocol' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted for Impact' },
      { tactic: 'Impact', technique: 'T1490', name: 'Inhibit System Recovery' },
    ],
    tools: ['Cobalt Strike', 'Stealbit', 'Rclone', 'BloodHound', 'Mimikatz', 'AnyDesk', 'PsExec', 'Sliver', 'MEGAsync'],
    detection_tips: [
      'Alert on vssadmin delete shadows + bcdedit recoveryenabled no in same session',
      'Monitor for Rclone to Mega.nz: large outbound HTTPS transfers to rclone C2',
      'Hunt StealBit: specific file enumeration and staging to temp directory',
      'Alert on BloodHound: 4798/4799 rapid AD enumeration events',
      'Monitor AnyDesk/TeamViewer installs by non-IT accounts',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 (CommandLine="*vssadmin*delete*" OR CommandLine="*bcdedit*no*" OR CommandLine="*wbadmin*delete*" OR CommandLine="*wmic*shadowcopy*" OR CommandLine="*rclone*mega*") | stats count by host, user, CommandLine | sort -count',
      sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("vssadmin delete","bcdedit /set recoveryenabled no","wbadmin delete catalog","rclone copy") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine'
    },
    iocs: { domains: ['lockbitapt28.com'], ips: [] }
  },

  {
    id: 'blackcat', name: 'ALPHV / BlackCat', aliases: ['ALPHV', 'Noberus', 'BlackCat', 'Coreid'],
    icon: '🐱', origin: 'Russia', sponsor: 'Criminal (RaaS)', motivation: 'Financial',
    active: true, severity: 'CRIT', type: 'Ransomware',
    targets: ['Healthcare', 'Energy', 'Finance', 'Government', 'Critical Infrastructure'],
    campaigns: ['MGM Resorts $100M Attack (2023) via Scattered Spider', 'Caesars Entertainment $15M (2023)', 'Change Healthcare/UnitedHealth $22M (2024) - biggest healthcare cyber attack', 'Reddit Breach (2023)'],
    attack_workflow: [
      { phase: '1. Initial Access', detail: 'Credentials from dark web markets, phishing, or affiliate access brokers. Also ESXi/VMware exploit for VM-based environments.' },
      { phase: '2. C2 Deployment', detail: 'Rust-based BlackCat payload deployed. ExMatter exfiltration tool staged. Evasion via process injection into legitimate processes.' },
      { phase: '3. AD Compromise', detail: 'BloodHound/ADFind for AD enumeration. Exploit AD vulnerabilities (Zerologon, PrintNightmare) if needed.' },
      { phase: '4. Data Exfiltration', detail: 'ExMatter tool for data staging. SFTP exfiltration. Terabytes of data stolen for double-extortion leverage.' },
      { phase: '5. ESXi Mass Encryption', detail: 'Unique capability: directly encrypts VMware ESXi VMs, VMDK files. All VMs encrypted simultaneously = catastrophic impact.' },
      { phase: '6. Windows + Linux Encryption', detail: 'Multi-platform ransomware (Rust): encrypts Windows, Linux, and ESXi without recompilation. AES-128 + RSA-4096.' },
      { phase: '7. Triple Extortion', detail: 'Data leak threat + DDoS threat + contacting victim\'s customers/partners as additional pressure.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1078', name: 'Valid Accounts' },
      { tactic: 'Execution', technique: 'T1059', name: 'Command and Scripting Interpreter' },
      { tactic: 'Defense Evasion', technique: 'T1027', name: 'Obfuscated Files (Rust)' },
      { tactic: 'Discovery', technique: 'T1482', name: 'Domain Trust Discovery' },
      { tactic: 'Exfiltration', technique: 'T1048', name: 'ExMatter Exfiltration' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted (ESXi + Windows + Linux)' },
    ],
    tools: ['BlackCat payload (Rust)', 'ExMatter', 'Cobalt Strike', 'BloodHound', 'AdFind', 'MEGAsync'],
    detection_tips: [
      'Hunt ESXi attacks: unusual SSH access to ESXi hosts, esxcli commands',
      'Alert on ExMatter: SFTP large file transfers from internal hosts',
      'Monitor Rust-compiled executables with high entropy in temp paths',
      'Alert on Change Healthcare pattern: Citrix AAD exploit without MFA',
    ],
    hunt_queries: {
      splunk: 'index=* (source="vmware_esxi" action=login user!="root") OR (EventCode=4688 CommandLine="*vmware*" CommandLine="*esxcli*") | stats count by host, user, CommandLine',
      sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("esxcli","vmkfstools","vim-cmd") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'clop', name: 'Cl0p Ransomware', aliases: ['TA505', 'FIN11', 'Lace Tempest'],
    icon: '🦞', origin: 'Russia', sponsor: 'Criminal', motivation: 'Financial',
    active: true, severity: 'CRIT', type: 'Ransomware',
    targets: ['Healthcare', 'Finance', 'Higher Education', 'Energy', 'Manufacturing'],
    campaigns: ['MOVEit Transfer Zero-Day (CVE-2023-34362) - 600+ victims', 'GoAnywhere MFT Zero-Day (CVE-2023-0669) - 130 victims', 'Accellion FTA Exploit (2021)', 'SolarWinds Serv-U Exploit'],
    attack_workflow: [
      { phase: '1. Zero-Day Exploitation', detail: 'Cl0p specializes in exploiting managed file transfer (MFT) zero-days. MOVEit, GoAnywhere, Accellion FTA all targeted. No phishing - direct exploitation.' },
      { phase: '2. Web Shell Deployment', detail: 'Deploy LEMURLOOT web shell in MOVEit webroot. Persistent access even after patching.' },
      { phase: '3. Bulk Data Theft', detail: 'LEMURLOOT queries MOVEit database, extracts ALL stored files. Automated mass exfiltration - thousands of files in hours.' },
      { phase: '4. No Encryption (Data-Only)', detail: 'Cl0p often skips encryption in MFT campaigns - data theft alone provides leverage. Faster, less detectable.' },
      { phase: '5. Mass Extortion', detail: 'Simultaneously threatens hundreds of organizations. Public leak site with countdown timers. Individual negotiations with each victim.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit Public-Facing MFT Application' },
      { tactic: 'Persistence', technique: 'T1505.003', name: 'Web Shell (LEMURLOOT)' },
      { tactic: 'Collection', technique: 'T1005', name: 'Data from Local System' },
      { tactic: 'Exfiltration', technique: 'T1567', name: 'Exfiltration to Web Service' },
      { tactic: 'Impact', technique: 'T1657', name: 'Financial Theft via Extortion' },
    ],
    tools: ['LEMURLOOT web shell', 'DEWMODE', 'MISDEED', 'Truebot', 'FlawedGrace'],
    detection_tips: [
      'CRITICAL: Hunt MOVEit: /moveitisapi/moveitisapi.dll unusual POST requests',
      'Alert on LEMURLOOT: guestaccess.aspx or human2.aspx files in MOVEit webroot',
      'Monitor GoAnywhere admin portal: /goanywhere/lic/accept unauthorized access',
      'Alert on mass database queries from web application accounts',
      'Scan for web shells: .aspx/.php files in MFT application directories',
    ],
    hunt_queries: {
      splunk: 'index=web_logs uri_path IN ("*/human2.aspx*","*/guestaccess.aspx*","*/moveitisapi/*") method=POST | stats count by src_ip, uri_path | sort -count',
      sentinel: 'CommonSecurityLog | where RequestURL has_any ("human2.aspx","guestaccess.aspx","moveitisapi") | where RequestMethod == "POST" | summarize count() by SourceIP, RequestURL | order by count_ desc'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'scattered-spider', name: 'Scattered Spider', aliases: ['Oktapus', 'UNC3944', 'Muddled Libra', '0ktapus', 'Starfraud'],
    icon: '🕷️', origin: 'USA/UK (English-speaking)', sponsor: 'Criminal', motivation: 'Financial',
    active: true, severity: 'CRIT', type: 'Criminal',
    targets: ['Casinos', 'Hotels', 'Telecom', 'Tech Companies', 'Retail'],
    campaigns: ['MGM Resorts (Sep 2023) $100M+ in damages', 'Caesars Entertainment $15M ransom paid', 'Coinbase Social Engineering (2023)', 'Riot Games Social Engineering', 'Reddit Breach', 'Microsoft Entra ID Attacks (2024)'],
    attack_workflow: [
      { phase: '1. Social Engineering', detail: 'Native English speakers call IT help desks impersonating employees. Bypass MFA through vishing. "I lost my phone, can you reset my MFA?" Extremely convincing.' },
      { phase: '2. SIM Swapping', detail: 'SIM swap target employee\'s phone number to receive MFA codes. Purchase insider at telecom for SIM swap capability.' },
      { phase: '3. Okta/Azure AD Takeover', detail: 'Use social engineering to enroll attacker MFA device. Exploit Okta customer support for password reset. Full IdP takeover.' },
      { phase: '4. Azure / Cloud Pivot', detail: 'From IdP access, pivot to Azure, AWS, Google Workspace. Create new service principals, disable MFA for target accounts.' },
      { phase: '5. ALPHV/BlackCat Deployment', detail: 'Partner with BlackCat/ALPHV for ransomware payload. Scattered Spider handles access, ALPHV handles encryption and extortion.' },
      { phase: '6. Exfiltration & Extortion', detail: 'Data theft before encryption. Direct negotiation with executives via encrypted messaging. Use Telegram for communication.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1656', name: 'Impersonation (Help Desk Vishing)' },
      { tactic: 'Initial Access', technique: 'T1621', name: 'Multi-Factor Authentication Request Generation' },
      { tactic: 'Persistence', technique: 'T1078.004', name: 'Valid Cloud Accounts' },
      { tactic: 'Persistence', technique: 'T1556.006', name: 'Modify MFA' },
      { tactic: 'Defense Evasion', technique: 'T1550.001', name: 'Application Access Token' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted (via ALPHV)' },
    ],
    tools: ['Stealthy phishing kits (EvilProxy, Evilginx2)', 'ScreenConnect', 'AnyDesk', 'Telegram', 'ALPHV/BlackCat ransomware'],
    detection_tips: [
      'CRITICAL: Alert on MFA device enrollment after help desk call in same session',
      'Monitor for Okta: "Authentication policy bypassed" events',
      'Alert on new MFA device registration from new IP within 1 hour of password reset',
      'Hunt for impossible travel: logon from different country within minutes',
      'Alert on service principal creation from interactive user sessions (not CI/CD)',
      'Monitor help desk tickets for MFA reset requests - call back verification required',
    ],
    hunt_queries: {
      splunk: 'index=okta eventType="user.authentication.auth_via_mfa" outcome.result=FAILURE | stats count, dc(client.ipAddress) as ips by user.login | where count > 5',
      sentinel: 'AuditLogs | where OperationName == "Update user" | where TargetResources[0].modifiedProperties has "StrongAuthenticationPhoneAppDetail" | join SigninLogs on $left.CorrelationId == $right.CorrelationId | project TimeGenerated, UserPrincipalName, IPAddress, OperationName'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'rhysida', name: 'Rhysida Ransomware', aliases: ['Rhysida'],
    icon: '🐛', origin: 'Unknown (likely Russia-linked)', sponsor: 'Criminal (RaaS)', motivation: 'Financial',
    active: true, severity: 'HIGH', type: 'Ransomware',
    targets: ['Healthcare', 'Education', 'Government', 'Manufacturing'],
    campaigns: ['British Library Attack (2023)', 'Chilean Army (2023)', 'Lurie Children\'s Hospital (2024)', 'MarineMax (2024)'],
    attack_workflow: [
      { phase: '1. Initial Access', detail: 'Phishing emails, valid credentials via credential theft or IAB. VPN vulnerability exploitation. RDP brute force.' },
      { phase: '2. Cobalt Strike Deployment', detail: 'Cobalt Strike or similar RAT deployed for persistent C2. Living-off-the-land techniques for evasion.' },
      { phase: '3. Privilege Escalation', detail: 'Kerberoasting, AS-REP Roasting, or DCSync for domain admin credentials. BloodHound for AD path mapping.' },
      { phase: '4. Data Staging & Exfil', detail: 'WinSCP, MEGAsync, or rclone for data staging. 10-100s of GBs exfiltrated before encryption.' },
      { phase: '5. Encryption', detail: 'ChaCha20 encryption (unique among ransomware). RSA-4096 key protection. Targets NAS devices and shared drives specifically.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1078', name: 'Valid Accounts' },
      { tactic: 'Execution', technique: 'T1059.001', name: 'PowerShell' },
      { tactic: 'Lateral Movement', technique: 'T1021.002', name: 'SMB/Admin Shares' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted (ChaCha20)' },
    ],
    tools: ['Cobalt Strike', 'PsExec', 'BloodHound', 'MEGAsync', 'WinSCP', 'PowerShell Empire'],
    detection_tips: [
      'Hunt ChaCha20 encrypted files: look for new file extensions and ransom notes "CriticalBreachDetected"',
      'Alert on NAS device file enumeration from domain accounts',
      'Monitor MEGAsync and WinSCP installations by non-IT accounts',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4663 Object_Name="\\\\*\\*\\*" | stats count by user, host | where count > 1000 | sort -count',
      sentinel: 'DeviceFileEvents | where ActionType == "FileModified" | where FileName endswith ".rhysida" | summarize count() by DeviceName, AccountName | order by count_ desc'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'play', name: 'Play Ransomware', aliases: ['Play', 'PlayCrypt', 'Fiddling Scorpius'],
    icon: '▶️', origin: 'Unknown', sponsor: 'Criminal', motivation: 'Financial',
    active: true, severity: 'HIGH', type: 'Ransomware',
    targets: ['Government', 'Media', 'Healthcare', 'Technology', 'Finance'],
    campaigns: ['City of Oakland (2023)', 'Dallas County (2023)', 'Rackspace Cloud (2022)', 'Arnold Clark UK (2023)'],
    attack_workflow: [
      { phase: '1. Initial Access', detail: 'Exploit FortiOS SSL-VPN (CVE-2018-13379, CVE-2022-42475), Microsoft Exchange ProxyNotShell (CVE-2022-41082), or RDP.' },
      { phase: '2. AV Bypass', detail: 'Unique: uses BYOVD (Bring Your Own Vulnerable Driver) to disable AV/EDR. Deploys legitimate signed vulnerable drivers (gmer.sys, iqvm64.sys) to kill security tools.' },
      { phase: '3. Lateral Movement', detail: 'Cobalt Strike beacons, Mimikatz, BloodHound. WinRM for lateral movement to avoid SMB-based detections.' },
      { phase: '4. Dual Exfiltration', detail: 'WinSCP and WinRAR for data staging. Exfiltrates to MEGA or attacker FTP. Splits files into 1GB chunks.' },
      { phase: '5. Encryption', detail: 'AES encryption. Files renamed with .PLAY extension. Drops "ReadMe.txt" ransom note. Volume Shadow Copy deletion via custom tool.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit FortiOS/Exchange' },
      { tactic: 'Defense Evasion', technique: 'T1014', name: 'BYOVD - Vulnerable Driver' },
      { tactic: 'Lateral Movement', technique: 'T1021.006', name: 'WinRM' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted (.PLAY)' },
    ],
    tools: ['Cobalt Strike', 'BYOVD (gmer.sys)', 'Mimikatz', 'BloodHound', 'WinSCP', 'WinRAR', 'MEGAsync'],
    detection_tips: [
      'CRITICAL: Hunt BYOVD - alert on loading of known vulnerable drivers (gmer.sys, iqvm64.sys)',
      'Monitor FortiOS/Exchange authentication logs for exploitation patterns',
      'Alert on WinRM usage from non-admin accounts for lateral movement',
      'Hunt .PLAY file extension or ReadMe.txt ransom note drops',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=6 (ImageLoaded="*gmer*" OR ImageLoaded="*iqvm64*" OR ImageLoaded="*KProcessHacker*") | stats count by host, ImageLoaded',
      sentinel: 'DeviceEvents | where ActionType == "DriverLoad" | where FileName has_any ("gmer","iqvm64","KProcessHacker") | project TimeGenerated, DeviceName, FileName, SHA256'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'akira', name: 'Akira Ransomware', aliases: ['Akira'],
    icon: '🎌', origin: 'Russia-linked', sponsor: 'Criminal (RaaS)', motivation: 'Financial',
    active: true, severity: 'HIGH', type: 'Ransomware',
    targets: ['SMB', 'Healthcare', 'Education', 'Manufacturing'],
    campaigns: ['Cisco AnyConnect VPN Exploitation Campaign (2023)', '240+ victims since March 2023', 'Stanford University (2023)'],
    attack_workflow: [
      { phase: '1. Initial Access', detail: 'Exploit Cisco AnyConnect VPN (CVE-2023-20269) or use stolen VPN credentials. Also RDP and phishing. No MFA on VPN = primary attack path.' },
      { phase: '2. Persistence', detail: 'AnyDesk remote access tool deployed. New admin accounts created. RDP persistence established.' },
      { phase: '3. Disable Security', detail: 'Windows Defender disabled via PowerShell/registry. EDR processes terminated. Windows Firewall rules modified.' },
      { phase: '4. Data Exfil', detail: 'FileZilla, WinRAR, RClone for data staging. Upload to Mega.nz or attacker SFTP.' },
      { phase: '5. Dual Encryption', detail: 'Windows: AES-256-CBC. Linux/ESXi: ChaCha20. Files renamed .akira. ESXi VMs targeted directly.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1078', name: 'Valid VPN Credentials' },
      { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit Cisco VPN CVE-2023-20269' },
      { tactic: 'Defense Evasion', technique: 'T1562.001', name: 'Disable Windows Defender' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted (.akira)' },
    ],
    tools: ['AnyDesk', 'FileZilla', 'RClone', 'WinRAR', 'PowerShell', 'Chisel', 'MobaXterm'],
    detection_tips: [
      'Critical: Alert on Cisco AnyConnect auth without MFA from new IPs',
      'Hunt .akira file extension or "akira_readme.txt" ransom notes',
      'Alert on Windows Defender disabled via registry: SpynetReporting=0',
      'Monitor AnyDesk installs by non-IT accounts',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 (CommandLine="*Set-MpPreference*DisableRealtimeMonitoring*" OR CommandLine="*sc*stop*WinDefend*" OR CommandLine="*akira*") | stats count by host, user, CommandLine',
      sentinel: 'DeviceRegistryEvents | where RegistryKey has "Windows Defender" | where RegistryValueName in ("DisableRealtimeMonitoring","SpynetReporting") | where RegistryValueData == "1" | project TimeGenerated, DeviceName, InitiatingProcessAccountName'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'conti', name: 'Conti (Defunct)', aliases: ['Conti', 'Ryuk successor', 'Wizard Spider'],
    icon: '🐺', origin: 'Russia', sponsor: 'Criminal', motivation: 'Financial',
    active: false, severity: 'HIGH', type: 'Ransomware',
    targets: ['Healthcare', 'Government', 'Critical Infrastructure', 'All Sectors'],
    campaigns: ['Irish HSE Attack (2021) - €100M recovery cost', 'Costa Rica Government ($20M ransom 2022)', 'Conti Leaks - internal chat logs published (2022)'],
    attack_workflow: [
      { phase: '1. TrickBot/BazarLoader', detail: 'Initial access via TrickBot banking trojan or BazarLoader. Spearphishing with malicious Excel attachments. TrickBot does recon.' },
      { phase: '2. Cobalt Strike', detail: 'After TrickBot establishes foothold, Cobalt Strike beacon deployed for flexible C2.' },
      { phase: '3. AD Compromise', detail: 'Mimikatz, BloodHound, Zerologon (CVE-2020-1472) exploit. Domain admin in hours.' },
      { phase: '4. Backup Destruction', detail: 'Systematically identify and destroy all backup systems before encryption. Immutable backups required to survive Conti.' },
      { phase: '5. Conti Encryption', detail: 'AES-256 + RSA-4096. Encrypts all files except specific extensions. 100+ encryption threads for speed.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566.001', name: 'Spearphishing (TrickBot)' },
      { tactic: 'Execution', technique: 'T1204.002', name: 'Malicious File' },
      { tactic: 'Privilege Escalation', technique: 'T1210', name: 'Zerologon Exploit' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted (AES-256)' },
    ],
    tools: ['TrickBot', 'BazarLoader', 'Cobalt Strike', 'Mimikatz', 'BloodHound', 'AnyDesk', 'Rclone'],
    detection_tips: [
      'Conti disbanded 2022 but playbook reused by Royal, Black Basta, Karakurt',
      'Hunt TrickBot: wermgr.exe spawned from WINWORD.EXE with network connections',
      'Alert on Zerologon: EventID 4742 computer account password change without interactive logon',
      'Conti playbook now used by successors - same TTPs apply',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4742 | where NOT (EventCode=4624) | stats count by user, host',
      sentinel: 'SecurityEvent | where EventID == 4742 | where SubjectLogonId != "0x3e7" | project TimeGenerated, Computer, SubjectAccount, TargetAccount'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'blackbasta', name: 'Black Basta', aliases: ['Black Basta'],
    icon: '⬛', origin: 'Russia', sponsor: 'Criminal (Conti successor)', motivation: 'Financial',
    active: true, severity: 'CRIT', type: 'Ransomware',
    targets: ['Healthcare', 'Manufacturing', 'Finance', 'Technology'],
    campaigns: ['Ascension Health (2024) - major US hospital disruption', 'ABB (2023)', 'Yellow Pages Canada (2023)', 'Capita UK (2023)', '500+ victims since April 2022'],
    attack_workflow: [
      { phase: '1. QakBot / Phishing', detail: 'Initial access via QakBot malware or direct phishing. QakBot distributes Black Basta ransomware. Also buying access via IABs.' },
      { phase: '2. Cobalt Strike C2', detail: 'Cobalt Strike beacon deployed within hours. Named pipe communication. Fast escalation timeline (sometimes within 2-6 hours).' },
      { phase: '3. AD Takeover', detail: 'BloodHound, ADExplorer for AD mapping. PrintNightmare or ZeroLogon for privilege escalation. Domain admin obtained rapidly.' },
      { phase: '4. Backup Targeting', detail: 'Identify Veeam, Backup Exec, Windows Backup servers. Delete or encrypt backups. Change backup service account passwords.' },
      { phase: '5. Mass Encryption', detail: 'ChaCha20_poly1305 encryption. .basta extension. Targets network shares, NAS, ESXi hosts. Very fast encryption speed.' },
    ],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566', name: 'Phishing / QakBot' },
      { tactic: 'Privilege Escalation', technique: 'T1068', name: 'PrintNightmare / ZeroLogon' },
      { tactic: 'Defense Evasion', technique: 'T1562', name: 'Disable Security Tools' },
      { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted (.basta / ChaCha20)' },
    ],
    tools: ['QakBot', 'Cobalt Strike', 'BloodHound', 'ADExplorer', 'Rclone', 'PowerShell'],
    detection_tips: [
      'Alert on QakBot: wermgr.exe or regsvr32.exe spawning unusual child processes',
      'Monitor Veeam and backup service account logons from unusual IPs',
      'Hunt .basta extension or "readme.txt" ransom note containing Black Basta markers',
      'Alert on mass SMB file modifications - ChaCha20 encryption is fast',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 ParentImage IN ("*wermgr.exe","*regsvr32.exe") Image IN ("*cmd.exe","*powershell.exe","*net.exe") | stats count by host, CommandLine',
      sentinel: 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("wermgr.exe","regsvr32.exe") | where FileName in~ ("cmd.exe","powershell.exe","net.exe") | project TimeGenerated, DeviceName, ProcessCommandLine'
    },
    iocs: { domains: [], ips: [] }
  },

  // ═══════════════════════════════════════════════════════
  // 🕵️ CRIMINAL THREAT ACTORS
  // ═══════════════════════════════════════════════════════
  {
    id: 'fin7', name: 'FIN7 / Carbanak', aliases: ['Carbanak', 'Navigator Group', 'ELBRUS', 'Sangria Tempest'],
    icon: '💳', origin: 'Russia/Ukraine', sponsor: 'Criminal', motivation: 'Financial - Banking & Retail',
    active: true, severity: 'CRIT', type: 'Criminal',
    targets: ['Retail', 'Restaurants', 'Hospitality', 'POS Systems', 'Banks', 'Casinos'],
    campaigns: ['$1B+ stolen from banks via ATM jackpotting (2013-2018)', 'Verizon Data Breach (2021)', 'CISA Advisory FIN7 (2022)', 'Microsoft and Okta supply chain targeting (2023)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566.001', name: 'Spearphishing (fake OSHA/SEC docs)' },
      { tactic: 'Execution', technique: 'T1204.002', name: 'Malicious Macro Documents' },
      { tactic: 'Persistence', technique: 'T1543.003', name: 'Windows Service' },
      { tactic: 'Collection', technique: 'T1056.001', name: 'Keylogging' },
      { tactic: 'Impact', technique: 'T1657', name: 'Financial Theft / ATM Cash-Out' },
    ],
    tools: ['Carbanak', 'GRIFFON', 'BOOSTWRITE', 'RDFSNIFFER', 'Pillowmint', 'PowerPlant', 'Lizar/Tirion'],
    detection_tips: [
      'Hunt fake OSHA compliance docs: macros spawning WMIC or PowerShell',
      'Alert on ATM jackpotting: KAL software or TYUPKIN malware on ATM OS',
      'Monitor POS systems: unusual process spawning or network connections',
      'Alert on RDFSNIFFER: modifications to rdp session hosts',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 ParentImage="*EXCEL.EXE*" Image IN ("*wmic.exe","*powershell.exe","*cmd.exe") | stats count by host, CommandLine | sort -count',
      sentinel: 'DeviceProcessEvents | where InitiatingProcessFileName =~ "EXCEL.EXE" | where FileName in~ ("wmic.exe","powershell.exe","cmd.exe","mshta.exe") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine'
    },
    iocs: { domains: [], ips: [] }
  },

  {
    id: 'ta505', name: 'TA505 / Evil Corp', aliases: ['TA505', 'Evil Corp', 'Indrik Spider', 'Gold Drake'],
    icon: '💰', origin: 'Russia', sponsor: 'Criminal', motivation: 'Financial - Dridex Banking Trojan',
    active: true, severity: 'HIGH', type: 'Criminal',
    targets: ['Financial Institutions', 'Retail', 'Healthcare', 'Energy'],
    campaigns: ['Dridex Banking Trojan ($100M+ stolen)', 'Locky Ransomware', 'BitPaymer Ransomware', 'WastedLocker Ransomware', 'US Treasury OFAC Sanctions (2019)'],
    ttps: [
      { tactic: 'Initial Access', technique: 'T1566', name: 'Phishing - Malicious Excel/Word' },
      { tactic: 'Execution', technique: 'T1059', name: 'PowerShell / VBScript' },
      { tactic: 'Impact', technique: 'T1486', name: 'Ransomware (WastedLocker/BitPaymer)' },
      { tactic: 'Impact', technique: 'T1657', name: 'Financial Theft (Dridex)' },
    ],
    tools: ['Dridex', 'FlawedAmmyy', 'ServHelper', 'SDBbot', 'WastedLocker', 'BitPaymer', 'Hades'],
    detection_tips: [
      'Evil Corp sanctioned by US Treasury - ransom payments may violate OFAC',
      'Hunt Dridex: injected into legitimate processes, steals banking credentials',
      'Alert on WastedLocker: files encrypted with victim-specific extension',
    ],
    hunt_queries: {
      splunk: 'index=* EventCode=4688 (CommandLine="*cmd /c echo*" OR CommandLine="*wscript*//e:vbscript*") | stats count by host, CommandLine',
      sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("cmd /c echo","wscript //e:vbscript") | project TimeGenerated, DeviceName, ProcessCommandLine'
    },
    iocs: { domains: [], ips: [] }
  }

];

// GET /api/actors - Return all actors
router.get('/', (req, res) => {
  try {
    res.json({ actors: ACTORS });
  } catch (error) {
    console.error('Error in GET /api/actors:', error);
    res.status(500).json({ error: error.message });
  }
});
// This should be at line ~169 in your actors.js
router.get('/stats', (req, res) => {
  try {
    const stats = {
      total: ACTORS.length,
      active: ACTORS.filter(a => a.active).length,
      inactive: ACTORS.filter(a => !a.active).length,
      byOrigin: {},
      bySeverity: {},
      byType: {}
    };
    
    ACTORS.forEach(actor => {
      stats.byOrigin[actor.origin] = (stats.byOrigin[actor.origin] || 0) + 1;
      stats.bySeverity[actor.severity] = (stats.bySeverity[actor.severity] || 0) + 1;
      stats.byType[actor.type] = (stats.byType[actor.type] || 0) + 1;
    });
    
    res.json(stats);
  } catch (error) {
    console.error('Error in GET /api/actors/stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/actors/:id - Return specific actor by ID
router.get('/:id', (req, res) => {
  try {
    const actor = ACTORS.find(x => x.id === req.params.id);
    
    if (!actor) {
      return res.status(404).json({ error: 'Actor not found' });
    }
    
    res.json(actor);
  } catch (error) {
    console.error('Error in GET /api/actors/:id:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/actors/search/:term - Search actors by name or alias
router.get('/search/:term', (req, res) => {
  try {
    const searchTerm = req.params.term.toLowerCase();
    
    const results = ACTORS.filter(actor => 
      actor.name.toLowerCase().includes(searchTerm) ||
      actor.aliases.some(alias => alias.toLowerCase().includes(searchTerm)) ||
      actor.origin.toLowerCase().includes(searchTerm)
    );
    
    res.json({ 
      results,
      count: results.length 
    });
  } catch (error) {
    console.error('Error in GET /api/actors/search/:term:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/actors/stats - Get actor statistics
router.get('/stats', (req, res) => {
  try {
    const stats = {
      total: ACTORS.length,
      active: ACTORS.filter(a => a.active).length,
      inactive: ACTORS.filter(a => !a.active).length,
      byOrigin: {},
      bySeverity: {},
      byType: {}
    };
    
    ACTORS.forEach(actor => {
      // Count by origin
      stats.byOrigin[actor.origin] = (stats.byOrigin[actor.origin] || 0) + 1;
      
      // Count by severity
      stats.bySeverity[actor.severity] = (stats.bySeverity[actor.severity] || 0) + 1;
      
      // Count by type
      stats.byType[actor.type] = (stats.byType[actor.type] || 0) + 1;
    });
    
    res.json(stats);
  } catch (error) {
    console.error('Error in GET /api/actors/stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/actors/origin/:origin - Filter actors by origin
router.get('/origin/:origin', (req, res) => {
  try {
    const origin = req.params.origin;
    const filtered = ACTORS.filter(actor => 
      actor.origin.toLowerCase().includes(origin.toLowerCase())
    );
    
    res.json({ 
      origin,
      actors: filtered,
      count: filtered.length 
    });
  } catch (error) {
    console.error('Error in GET /api/actors/origin/:origin:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/actors/type/:type - Filter actors by type
router.get('/type/:type', (req, res) => {
  try {
    const type = req.params.type;
    const filtered = ACTORS.filter(actor => 
      actor.type.toLowerCase() === type.toLowerCase()
    );
    
    res.json({ 
      type,
      actors: filtered,
      count: filtered.length 
    });
  } catch (error) {
    console.error('Error in GET /api/actors/type/:type:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;