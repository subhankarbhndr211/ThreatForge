'use strict';
const express = require('express');
const router = express.Router();

// Full MITRE ATT&CK Enterprise Framework
const TACTICS = [
  { id: 'TA0001', name: 'Reconnaissance', icon: '👁', color: '#7c3aed', desc: 'Attacker gathers info to plan future operations.' },
  { id: 'TA0002', name: 'Resource Development', icon: '🔧', color: '#6d28d9', desc: 'Attacker establishes resources to support operations.' },
  { id: 'TA0003', name: 'Initial Access', icon: '🚪', color: '#dc2626', desc: 'Attacker tries to get into your network.' },
  { id: 'TA0004', name: 'Execution', icon: '⚡', color: '#ea580c', desc: 'Attacker tries to run malicious code.' },
  { id: 'TA0005', name: 'Persistence', icon: '⚓', color: '#d97706', desc: 'Attacker tries to maintain their foothold.' },
  { id: 'TA0006', name: 'Privilege Escalation', icon: '⬆️', color: '#ca8a04', desc: 'Attacker tries to gain higher-level permissions.' },
  { id: 'TA0007', name: 'Defense Evasion', icon: '🛡', color: '#16a34a', desc: 'Attacker tries to avoid being detected.' },
  { id: 'TA0008', name: 'Credential Access', icon: '🔑', color: '#0891b2', desc: 'Attacker tries to steal account credentials.' },
  { id: 'TA0009', name: 'Discovery', icon: '🔭', color: '#2563eb', desc: 'Attacker tries to figure out your environment.' },
  { id: 'TA0010', name: 'Lateral Movement', icon: '↔️', color: '#7c3aed', desc: 'Attacker tries to move through your environment.' },
  { id: 'TA0011', name: 'Collection', icon: '📦', color: '#be185d', desc: 'Attacker tries to gather data of interest.' },
  { id: 'TA0012', name: 'Command & Control', icon: '📡', color: '#dc2626', desc: 'Attacker communicates with compromised systems.' },
  { id: 'TA0013', name: 'Exfiltration', icon: '📤', color: '#b45309', desc: 'Attacker tries to steal data.' },
  { id: 'TA0014', name: 'Impact', icon: '💥', color: '#7f1d1d', desc: 'Attacker tries to manipulate, interrupt, or destroy systems.' },
];

const TECHNIQUES = {
  TA0001: [
    { id: 'T1595', name: 'Active Scanning', sub: ['T1595.001 IP Scanning', 'T1595.002 Vulnerability Scanning', 'T1595.003 Wordlist Scanning'], detect: 'Detect port scans in firewall logs. Unusual inbound SYN packets from single source.', splunk: 'index=network sourcetype=firewall | stats count by src_ip | where count > 100 | sort -count', sentinel: 'CommonSecurityLog | where DeviceAction == "Deny" | summarize count() by SourceIP | where count_ > 50', severity: 'LOW' },
    { id: 'T1592', name: 'Gather Victim Host Info', sub: ['T1592.001 Hardware', 'T1592.002 Software', 'T1592.004 Client Configs'], detect: 'Monitor for credential harvesting phishing. Check for unusual web fingerprinting activity.', splunk: '', sentinel: '', severity: 'LOW' },
    { id: 'T1589', name: 'Gather Victim Identity Info', sub: ['T1589.001 Credentials', 'T1589.002 Email Addresses', 'T1589.003 Employee Names'], detect: 'Monitor breach notification services. Check for corporate email harvesting.', splunk: '', sentinel: '', severity: 'LOW' },
    { id: 'T1590', name: 'Gather Victim Network Info', sub: ['T1590.001 Domain Properties', 'T1590.004 Network Topology', 'T1590.005 IP Addresses'], detect: 'Monitor DNS queries for zone transfer attempts. Watch for WHOIS lookups.', splunk: 'index=dns | search "AXFR" | stats count by src_ip', sentinel: 'DnsEvents | where QueryType == "AXFR"', severity: 'MED' },
  ],
  TA0003: [
    { id: 'T1566', name: 'Phishing', sub: ['T1566.001 Spearphishing Attachment', 'T1566.002 Spearphishing Link', 'T1566.003 Spearphishing via Service', 'T1566.004 Spearphishing Voice'], detect: 'Email gateway logs. Look for malicious attachments. Monitor for credential harvesting URLs.', splunk: 'index=email | search (attachment="*.exe" OR attachment="*.js" OR attachment="*.hta") | stats count by sender, recipient', sentinel: 'EmailEvents | where AttachmentCount > 0 | where ThreatTypes has "Malware"', severity: 'HIGH' },
    { id: 'T1190', name: 'Exploit Public-Facing App', sub: ['CVE exploitation of web apps, VPNs, Exchange, Citrix'], detect: 'WAF logs. Web server errors spike. Unusual HTTP methods or payloads.', splunk: 'index=web | search (status=500 OR status=400) | stats count by src_ip, uri | where count > 20', sentinel: 'CommonSecurityLog | where DeviceEventClassID contains "exploit" or ApplicationProtocol == "HTTP" and AdditionalExtensions contains "attack"', severity: 'CRIT' },
    { id: 'T1133', name: 'External Remote Services', sub: ['T1133 VPN', 'RDP', 'Citrix', 'SSH exposed'], detect: 'Auth logs for VPN/RDP. Monitor for logins from unusual IPs or countries.', splunk: 'index=* sourcetype=vpn OR EventCode=4624 Logon_Type=10 | stats count by user, src_ip | sort -count', sentinel: 'SigninLogs | where AppDisplayName has_any ("VPN","Remote Desktop","Citrix") | where ResultType != 0', severity: 'HIGH' },
    { id: 'T1078', name: 'Valid Accounts', sub: ['T1078.001 Default Accounts', 'T1078.002 Domain Accounts', 'T1078.003 Local Accounts', 'T1078.004 Cloud Accounts'], detect: 'Baseline normal user behavior. Alert on logins from new geos, devices, times.', splunk: 'index=* (EventCode=4624 OR EventCode=4625) | stats count(eval(EventCode=4625)) as fails, count(eval(EventCode=4624)) as success by user | where fails > 10', sentinel: 'SigninLogs | extend isRisky = RiskLevelDuringSignIn | where isRisky has_any ("high","medium")', severity: 'HIGH' },
    { id: 'T1195', name: 'Supply Chain Compromise', sub: ['T1195.001 Compromise Software Dependencies', 'T1195.002 Compromise Software Supply Chain', 'T1195.003 Compromise Hardware Supply Chain'], detect: 'Monitor software update processes. Hash verification of packages. SolarWinds-style detection.', splunk: 'index=* process_name="*update*" | where NOT (publisher="Microsoft" OR publisher="Adobe") | stats count by process_name, hash', sentinel: 'DeviceProcessEvents | where InitiatingProcessFileName contains "update" | where InitiatingProcessSHA256 !in (known_good_hashes)', severity: 'CRIT' },
  ],
  TA0004: [
    { id: 'T1059', name: 'Command & Scripting Interpreter', sub: ['T1059.001 PowerShell', 'T1059.003 Windows Command Shell', 'T1059.004 Unix Shell', 'T1059.005 Visual Basic', 'T1059.006 Python', 'T1059.007 JavaScript'], detect: 'Script block logging. Command line auditing. Monitor interpreter spawning from unusual parents.', splunk: 'index=* source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 | search (EncodedCommand OR DownloadString OR IEX OR WebClient) | stats count by user, host', sentinel: 'DeviceProcessEvents | where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","bash","sh","python.exe") | where ProcessCommandLine has_any ("-enc","IEX","DownloadString","wget","curl -s")', severity: 'HIGH' },
    { id: 'T1106', name: 'Native API', sub: ['Direct syscall abuse to bypass userland hooks'], detect: 'EDR telemetry. Unusual API call sequences. Process hollowing indicators.', splunk: 'index=* sourcetype=edr api_call IN ("VirtualAllocEx","WriteProcessMemory","CreateRemoteThread") | stats count by process_name, target_process', sentinel: 'DeviceEvents | where ActionType == "CreateRemoteThreadApiCall" or ActionType == "VirtualAllocApiCall"', severity: 'HIGH' },
    { id: 'T1204', name: 'User Execution', sub: ['T1204.001 Malicious Link', 'T1204.002 Malicious File', 'T1204.003 Malicious Image'], detect: 'Email attachment execution. Browser download execution. Monitor LOLBins spawned from Office.', splunk: 'index=* EventCode=1 (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*OUTLOOK.EXE") | stats count by Image, CommandLine, ParentImage', sentinel: 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE") | where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")', severity: 'HIGH' },
    { id: 'T1569', name: 'System Services', sub: ['T1569.001 Launchctl', 'T1569.002 Service Execution'], detect: 'Monitor service creation and modification. EventID 7045 and 4697.', splunk: 'index=* (EventCode=7045 OR EventCode=4697) | stats count by ServiceName, ServiceFileName, user', sentinel: 'SecurityEvent | where EventID in (4697, 7045) | project TimeGenerated, Computer, ServiceName=extract(@"ServiceName: (.+)",1,EventData)', severity: 'HIGH' },
  ],
  TA0005: [
    { id: 'T1547', name: 'Boot/Logon Autostart', sub: ['T1547.001 Registry Run Keys', 'T1547.004 Winlogon Helper', 'T1547.009 Shortcut Modification', 'T1547.014 Active Setup'], detect: 'Monitor registry Run/RunOnce keys. Startup folder changes. EventID 13 (registry set).', splunk: 'index=* EventCode=13 (TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*") | stats count by TargetObject, Details, Image, user', sentinel: 'DeviceRegistryEvents | where RegistryKey has_any ("\\Run\\","\\RunOnce\\","\\RunServices\\") | summarize count() by DeviceName, RegistryKey, RegistryValueData', severity: 'HIGH' },
    { id: 'T1053', name: 'Scheduled Task/Job', sub: ['T1053.002 At', 'T1053.003 Cron', 'T1053.005 Scheduled Task'], detect: 'EventID 4698/4702. schtasks.exe execution. Monitor task XML for encoded commands.', splunk: 'index=* (EventCode=4698 OR EventCode=4702) | rex field=TaskContent "Command>(?<cmd>[^<]+)" | where match(cmd,"(?i)powershell|cmd|wscript|mshta") | stats count by TaskName, cmd, user', sentinel: 'SecurityEvent | where EventID in (4698,4702) | parse EventData with * "<Command>" cmd "</Command>" * | where cmd has_any ("powershell","cmd.exe","wscript","mshta")', severity: 'HIGH' },
    { id: 'T1543', name: 'Create/Modify System Process', sub: ['T1543.002 Systemd Service', 'T1543.003 Windows Service', 'T1543.004 Launch Daemon'], detect: 'Monitor new service creation. Check service binary paths for suspicious locations.', splunk: 'index=* EventCode=4697 | where NOT ServiceFileName LIKE "C:\\Windows\\%" | stats count by ServiceName, ServiceFileName, user', sentinel: 'SecurityEvent | where EventID == 4697 | extend path = extract(@"File Name: (.+)",1,EventData) | where path !startswith "C:\\Windows"', severity: 'HIGH' },
    { id: 'T1098', name: 'Account Manipulation', sub: ['T1098.001 Additional Cloud Credentials', 'T1098.002 Additional Email Delegate Permissions', 'T1098.003 Additional Cloud Roles', 'T1098.004 SSH Authorized Keys', 'T1098.005 Device Registration'], detect: 'Monitor account changes. New admin group adds. SSH authorized_keys file modification.', splunk: 'index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756) group="Administrators" | stats count by user, MemberName, host', sentinel: 'SecurityEvent | where EventID in (4728,4732,4756) | extend grp=extract(@"Group Name: (.+)",1,EventData) | where grp has "Admin"', severity: 'CRIT' },
  ],
  TA0006: [
    { id: 'T1068', name: 'Exploitation for Privilege Escalation', sub: ['Kernel exploits', 'Driver exploits', 'CVE-based escalation'], detect: 'Monitor for unusual kernel driver loads. Process spawning with elevated privileges from non-admin.', splunk: 'index=* EventCode=7045 | where ServiceType="kernel mode driver" | stats count by ServiceName, ServiceFileName', sentinel: 'DeviceEvents | where ActionType == "DriverLoad" | where not(InitiatingProcessFileName in~ ("system","services.exe"))', severity: 'CRIT' },
    { id: 'T1548', name: 'Abuse Elevation Control', sub: ['T1548.001 SUID/SGID', 'T1548.002 Bypass UAC', 'T1548.003 Sudo/Sudo Caching', 'T1548.004 Elevated Execution with Prompt'], detect: 'UAC bypass via known techniques (fodhelper, eventvwr). Linux SUID binary execution.', splunk: 'index=* EventCode=4624 ElevatedToken=1 | where NOT (user="SYSTEM" OR user="NETWORK SERVICE") | stats count by user, LogonType, src_ip', sentinel: 'DeviceProcessEvents | where ProcessTokenElevationType == "TokenElevationTypeFull" | where AccountName !in ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE")', severity: 'HIGH' },
    { id: 'T1055', name: 'Process Injection', sub: ['T1055.001 Dynamic-link Library Injection', 'T1055.002 Portable Executable Injection', 'T1055.003 Thread Execution Hijacking', 'T1055.012 Process Hollowing', 'T1055.013 Process Doppelgänging'], detect: 'Sysmon Event 8 (CreateRemoteThread). Unusual cross-process memory access. Process anomalies.', splunk: 'index=* EventCode=8 | where NOT (SourceImage="C:\\Windows\\System32\\*" AND TargetImage="C:\\Windows\\System32\\*") | stats count by SourceImage, TargetImage', sentinel: 'DeviceEvents | where ActionType in ("CreateRemoteThreadApiCall","ProcessInjection") | summarize count() by InitiatingProcessFileName, FileName', severity: 'CRIT' },
  ],
  TA0007: [
    { id: 'T1562', name: 'Impair Defenses', sub: ['T1562.001 Disable/Modify Tools', 'T1562.002 Disable Windows Event Logging', 'T1562.004 Disable Firewall', 'T1562.006 Indicator Blocking', 'T1562.008 Disable Cloud Logs'], detect: 'Monitor security tool process termination. Event log cleared (1102). AV disabled.', splunk: 'index=* (EventCode=1102 OR EventCode=104) | stats count by host, user | sort -count', sentinel: 'SecurityEvent | where EventID in (1100,1102,104) | project TimeGenerated, Computer, Account', severity: 'CRIT' },
    { id: 'T1070', name: 'Indicator Removal', sub: ['T1070.001 Clear Windows Event Logs', 'T1070.002 Clear Linux/Mac Logs', 'T1070.003 Clear Command History', 'T1070.004 File Deletion', 'T1070.006 Timestomp'], detect: 'Event log cleared (1102). File deletion bursts. Bash history cleared. Timestomping via file dates.', splunk: 'index=* EventCode=1102 | stats count by host, user', sentinel: 'SecurityEvent | where EventID == 1102 | project TimeGenerated, Computer, Account', severity: 'CRIT' },
    { id: 'T1036', name: 'Masquerading', sub: ['T1036.001 Invalid Code Signature', 'T1036.003 Rename System Utilities', 'T1036.004 Masquerade Task/Service', 'T1036.005 Match Legitimate Name/Location'], detect: 'Process name vs path mismatch. svchost.exe running from non-system32. Unsigned code in system dirs.', splunk: 'index=* process_name="svchost.exe" | where NOT (process_path="C:\\Windows\\System32\\svchost.exe") | stats count by process_path, host', sentinel: 'DeviceProcessEvents | where FileName =~ "svchost.exe" | where not(FolderPath =~ "C:\\Windows\\System32")', severity: 'HIGH' },
    { id: 'T1027', name: 'Obfuscated Files/Information', sub: ['T1027.001 Binary Padding', 'T1027.002 Software Packing', 'T1027.004 Compile After Delivery', 'T1027.009 Embedded Payloads', 'T1027.010 Command Obfuscation'], detect: 'High entropy file detection. Base64/XOR in command lines. Packed executable analysis.', splunk: 'index=* EventCode=4104 | eval b64_count=len(replace(CommandLine,"[^A-Za-z0-9+/=]","")) | where b64_count > 500 | stats count by CommandLine, user', sentinel: 'DeviceProcessEvents | where ProcessCommandLine matches regex @"[A-Za-z0-9+/]{100,}={0,2}" | summarize count() by DeviceName, ProcessCommandLine', severity: 'HIGH' },
  ],
  TA0008: [
    { id: 'T1003', name: 'OS Credential Dumping', sub: ['T1003.001 LSASS Memory', 'T1003.002 Security Account Manager', 'T1003.003 NTDS', 'T1003.004 LSA Secrets', 'T1003.006 DCSync', 'T1003.008 /etc/passwd and /etc/shadow'], detect: 'LSASS access (Sysmon 10). SAM/NTDS access. Mimikatz signatures. DCSync (EventID 4662).', splunk: 'index=* EventCode=10 TargetImage="C:\\Windows\\System32\\lsass.exe" | where NOT (SourceImage="C:\\Windows\\System32\\*") | stats count by SourceImage, host', sentinel: 'DeviceEvents | where ActionType == "OpenProcessApiCall" | where FileName =~ "lsass.exe" | where not(InitiatingProcessFileName in~ ("MsMpEng.exe","csrss.exe"))', severity: 'CRIT' },
    { id: 'T1110', name: 'Brute Force', sub: ['T1110.001 Password Guessing', 'T1110.002 Password Cracking', 'T1110.003 Password Spraying', 'T1110.004 Credential Stuffing'], detect: 'High auth failure rate. Same password across many accounts (spray). NTLM Error 0xC000006A.', splunk: 'index=* EventCode=4625 | stats count by user, src_ip | where count > 10 | sort -count', sentinel: 'SecurityEvent | where EventID == 4625 | summarize failures=count() by TargetUserName, IpAddress | where failures > 5', severity: 'HIGH' },
    { id: 'T1558', name: 'Steal/Forge Kerberos Tickets', sub: ['T1558.001 Golden Ticket', 'T1558.002 Silver Ticket', 'T1558.003 Kerberoasting', 'T1558.004 AS-REP Roasting'], detect: 'RC4 TGS requests. High volume TGS requests. Forged ticket anomalies.', splunk: 'index=* EventCode=4769 TicketEncryptionType=0x17 | stats count by user, ServiceName | where count > 5', sentinel: 'SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17" | summarize count() by Account, ServiceName | where count_ > 3', severity: 'HIGH' },
    { id: 'T1552', name: 'Unsecured Credentials', sub: ['T1552.001 Credentials in Files', 'T1552.002 Credentials in Registry', 'T1552.004 Private Keys', 'T1552.005 Cloud Instance Metadata', 'T1552.006 Group Policy Preferences'], detect: 'Monitor access to credential files. Registry reads of password keys. Metadata server SSRF.', splunk: 'index=* process_name IN ("findstr.exe","grep","cat") | search (password OR passwd OR credential OR secret) | stats count by user, CommandLine', sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("password","passwd","credential","secret") | where FileName in~ ("findstr.exe","grep","cat","type")', severity: 'HIGH' },
  ],
  TA0009: [
    { id: 'T1087', name: 'Account Discovery', sub: ['T1087.001 Local Account', 'T1087.002 Domain Account', 'T1087.003 Email Account', 'T1087.004 Cloud Account'], detect: 'net user / net group commands. LDAP queries for user enumeration. cat /etc/passwd.', splunk: 'index=* EventCode=4688 (CommandLine="*net user*" OR CommandLine="*net group*" OR CommandLine="*whoami*") | stats count by user, CommandLine, host', sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("net user","net group","whoami","id","getent passwd") | summarize count() by DeviceName, AccountName, ProcessCommandLine', severity: 'MED' },
    { id: 'T1046', name: 'Network Service Discovery', sub: ['Port scanning', 'Service enumeration via nmap, masscan'], detect: 'High rate sequential port connections. Nmap/masscan process execution.', splunk: 'index=network | stats count by src_ip, dest_port | where count > 50 | sort -count', sentinel: 'DeviceNetworkEvents | summarize ports=dcount(RemotePort) by DeviceName, RemoteIP, bin(Timestamp,5m) | where ports > 20', severity: 'MED' },
    { id: 'T1083', name: 'File and Directory Discovery', sub: ['dir /s', 'find /', 'ls -la recursive'], detect: 'Rapid file system traversal. dir /s on multiple drives. find / execution.', splunk: 'index=* EventCode=4688 (CommandLine="*dir /s*" OR CommandLine="*dir /b*") | stats count by user, host, CommandLine', sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("dir /s","dir /b","find /","ls -la","ls -R") | summarize count() by DeviceName, AccountName', severity: 'MED' },
  ],
  TA0010: [
    { id: 'T1021', name: 'Remote Services', sub: ['T1021.001 Remote Desktop Protocol', 'T1021.002 SMB/Windows Admin Shares', 'T1021.003 DCOM', 'T1021.004 SSH', 'T1021.005 VNC', 'T1021.006 Windows Remote Management'], detect: 'RDP from unusual sources. Net use to admin shares. WinRM activation. Lateral movement chains.', splunk: 'index=* EventCode=4624 Logon_Type=10 | stats count, values(src_ip) by user, host | where count > 3', sentinel: 'SecurityEvent | where EventID == 4624 and LogonType in (3,10) | summarize count() by TargetUserName, IpAddress, Computer | where count_ > 2', severity: 'HIGH' },
    { id: 'T1550', name: 'Use Alternate Auth Material', sub: ['T1550.001 App Access Token', 'T1550.002 Pass the Hash', 'T1550.003 Pass the Ticket', 'T1550.004 Web Session Cookie'], detect: 'NTLM auth from non-domain systems. Unusual Kerberos ticket usage. Cookie replay detection.', splunk: 'index=* EventCode=4624 AuthPackage=NTLM | where NOT (src_ip LIKE "10.*" OR src_ip LIKE "192.168.*") | stats count by user, src_ip', sentinel: 'SecurityEvent | where EventID == 4624 | where AuthenticationPackageName == "NTLM" | where IpAddress !startswith "10." and IpAddress !startswith "192.168."', severity: 'CRIT' },
    { id: 'T1570', name: 'Lateral Tool Transfer', sub: ['T1570 File copy via SMB, RDP clipboard, BITS, certutil'], detect: 'File copies via SMB shares. BITS jobs to lateral hosts. certutil download to remote hosts.', splunk: 'index=* EventCode=5145 ShareName="\\\\*\\C$" | stats count by user, src_ip, RelativeTargetName | sort -count', sentinel: 'DeviceFileEvents | where FolderPath startswith "\\\\\\\\.*\\\\(C|ADMIN|IPC)\\$" | summarize count() by DeviceName, InitiatingProcessAccountName', severity: 'HIGH' },
  ],
  TA0011: [
    { id: 'T1071', name: 'Application Layer Protocol', sub: ['T1071.001 Web Protocols (HTTP/S)', 'T1071.002 File Transfer Protocols', 'T1071.003 Mail Protocols', 'T1071.004 DNS'], detect: 'Beaconing patterns (regular intervals). Unusual processes making HTTP connections. DNS tunneling.', splunk: 'index=network | stats count, stdev(bytes) as jitter by src_ip, dest_ip, dest_port | where count > 10 AND jitter < 100', sentinel: 'DeviceNetworkEvents | where RemotePort in (80,443,53) | summarize count(), stdev(timestamp) by DeviceName, RemoteIP, bin(Timestamp, 1h) | where stdev_timestamp < 60', severity: 'HIGH' },
    { id: 'T1095', name: 'Non-Application Layer Protocol', sub: ['ICMP C2', 'DNS-over-HTTPS', 'Custom protocol C2'], detect: 'Unusual ICMP payloads. Non-standard protocol usage on unusual ports.', splunk: 'index=network protocol=icmp | where len(payload) > 64 | stats count by src_ip, dest_ip', sentinel: 'DeviceNetworkEvents | where Protocol == "Icmp" | where RemotePort == 0 | summarize count() by DeviceName, RemoteIP', severity: 'HIGH' },
    { id: 'T1572', name: 'Protocol Tunneling', sub: ['DNS tunneling', 'ICMP tunneling', 'HTTP tunneling', 'SSH tunneling'], detect: 'High volume DNS TXT records. Unusual DNS query lengths. SSH tunneling on non-22 ports.', splunk: 'index=dns | eval qlen=len(query) | where qlen > 100 | stats count, avg(qlen) by src_ip | where count > 50', sentinel: 'DnsEvents | extend querylen=strlen(Name) | where querylen > 80 | summarize count() by ClientIP, bin(TimeGenerated, 5m)', severity: 'HIGH' },
  ],
  TA0013: [
    { id: 'T1041', name: 'Exfiltration Over C2 Channel', sub: ['Data exfil over existing C2'], detect: 'Large outbound transfers on C2 channels. Data-to-C2 correlation.', splunk: 'index=network | stats sum(bytes_out) as total_out by src_ip, dest_ip | where total_out > 100000000 | sort -total_out', sentinel: 'DeviceNetworkEvents | where ActionType == "ConnectionSuccess" | summarize totalBytes=sum(SentBytes) by DeviceName, RemoteIP | where totalBytes > 50000000', severity: 'HIGH' },
    { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', sub: ['T1048.001 Exfil over Symmetric Encrypted Non-C2', 'T1048.002 Exfil over Asymmetric Encrypted Non-C2', 'T1048.003 Exfil over Unencrypted Non-C2'], detect: 'Large DNS transfers. FTP/SCP to external hosts. Unusual email attachment sizes.', splunk: 'index=network (dest_port=53 OR dest_port=21 OR dest_port=22) | stats sum(bytes) by src_ip, dest_ip | where sum(bytes) > 10000000', sentinel: 'DeviceNetworkEvents | where RemotePort in (21,22,53,25) | summarize totalBytes=sum(SentBytes) by DeviceName, RemoteIP | where totalBytes > 5000000', severity: 'HIGH' },
    { id: 'T1567', name: 'Exfiltration Over Web Service', sub: ['T1567.001 Exfil to Code Repository', 'T1567.002 Exfil to Cloud Storage', 'T1567.003 Exfil to Text Storage Sites', 'T1567.004 Exfil to File Sharing'], detect: 'Uploads to OneDrive/Dropbox/GitHub from unusual sources. Browser/process uploads.', splunk: 'index=proxy | search (domain="*dropbox.com" OR domain="*onedrive.com" OR domain="*github.com") bytes_out > 10000000 | stats sum(bytes_out) by user, domain', sentinel: 'DeviceNetworkEvents | where RemoteUrl has_any ("dropbox.com","onedrive.com","drive.google.com","github.com") | summarize uploaded=sum(SentBytes) by DeviceName, AccountName, RemoteUrl | where uploaded > 1000000', severity: 'HIGH' },
  ],
  TA0014: [
    { id: 'T1486', name: 'Data Encrypted for Impact', sub: ['Ransomware encryption of files'], detect: 'Mass file extension changes. Shadow copy deletion. Backup killing. Rapid write activity.', splunk: 'index=* EventCode=4688 CommandLine IN ("*vssadmin delete*","*bcdedit /set recoveryenabled*","*wbadmin delete*") | stats count by user, CommandLine, host', sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("vssadmin delete","bcdedit /set recoveryenabled","wbadmin delete","wmic shadowcopy delete") | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine', severity: 'CRIT' },
    { id: 'T1490', name: 'Inhibit System Recovery', sub: ['Shadow copy deletion', 'Backup deletion', 'Boot config modification'], detect: 'vssadmin, wmic shadowcopy, bcdedit /set recoveryenabled No execution.', splunk: 'index=* EventCode=4688 (CommandLine="*vssadmin*delete*" OR CommandLine="*shadowcopy*delete*") | stats count by user, host', sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("shadowcopy","vssadmin","bcdedit") | where ProcessCommandLine has_any ("delete","off","No")', severity: 'CRIT' },
    { id: 'T1499', name: 'Endpoint Denial of Service', sub: ['T1499.001 OS Exhaustion Flood', 'T1499.002 Service Exhaustion Flood', 'T1499.003 Application Exhaustion', 'T1499.004 Application or System Exploitation'], detect: 'Resource exhaustion monitoring. CPU/memory spikes. Service unavailability correlation.', splunk: 'index=* | stats count by host | eventstats avg(count) as avg_count | where count > avg_count * 5', sentinel: 'Perf | where CounterName in ("% Processor Time","Available MBytes") | where CounterValue > 95 or CounterValue < 100', severity: 'HIGH' },
    { id: 'T1485', name: 'Data Destruction', sub: ['Wiping files, MBR, partition tables'], detect: 'Mass file deletion. dd/shred on Linux. Format commands. MBR write detection.', splunk: 'index=* EventCode=4688 (CommandLine="*del /f /s*" OR CommandLine="*format*" OR CommandLine="*cipher /w*") | stats count by user, CommandLine', sentinel: 'DeviceProcessEvents | where ProcessCommandLine has_any ("del /f /s","format","cipher /w","shred","dd if=/dev/zero") | summarize count() by DeviceName, AccountName', severity: 'CRIT' },
  ],
};

// GET /api/mitre — all tactics summary
router.get('/', (req, res) => {
  try {
    const result = TACTICS.map(t => ({
      ...t,
      techniqueCount: (TECHNIQUES[t.id] || []).length
    }));
    res.json({ version: 'ATT&CK v14', tactics: result });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/mitre/stats
router.get('/stats', (req, res) => {
  try {
    const totalTechniques = Object.values(TECHNIQUES).flat().length;
    const stats = {
      tactics: TACTICS.length,
      techniques: totalTechniques,
      version: 'ATT&CK v14',
      lastUpdated: new Date().toISOString(),
      byTactic: TACTICS.map(t => ({
        id: t.id,
        name: t.name,
        techniqueCount: (TECHNIQUES[t.id] || []).length
      }))
    };
    res.json(stats);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/mitre/tactic/:id — techniques for a tactic
router.get('/tactic/:id', (req, res) => {
  try {
    const tacticId = req.params.id.toUpperCase();
    const tactic = TACTICS.find(t => t.id === tacticId);
    
    if (!tactic) {
      return res.status(404).json({ error: 'Tactic not found' });
    }
    
    const techniques = TECHNIQUES[tacticId] || [];
    res.json({ tactic, techniques });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;