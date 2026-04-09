'use strict';
const express = require('express');
const router = express.Router();

const LOG_LIBRARY = {
  windows: {
    label: 'Windows Security', icon: '🪟', color: '#0078d4',
    categories: {
      security: {
        label: 'Security Events (WinEventLog:Security)', source: 'WinEventLog:Security',
        events: [
          { id: '4624', name: 'Successful Logon', severity: 'INFO', mitre: 'T1078', threat: 'Credential Use', desc: 'Account logged on. Type 3=Network lateral movement, Type 10=RDP, Type 2=Interactive console. Monitor unusual source IPs and off-hours logons.' },
          { id: '4625', name: 'Failed Logon', severity: 'MED', mitre: 'T1110', threat: 'Brute Force', desc: 'Logon failure. Many from one IP=brute force. Many accounts same time=password spray. Sub Status 0xC000006A=wrong password, 0xC0000064=no such user.' },
          { id: '4634', name: 'Account Logoff', severity: 'INFO', mitre: 'T1078', threat: 'Session Tracking', desc: 'Account logged off. Use for session duration analysis and detecting concurrent logins.' },
          { id: '4647', name: 'User Initiated Logoff', severity: 'INFO', mitre: 'T1078', threat: 'Session Tracking', desc: 'User initiated logoff. Distinguishes from system-initiated logoff.' },
          { id: '4648', name: 'Explicit Credentials Logon', severity: 'HIGH', mitre: 'T1550', threat: 'Pass-the-Hash/RunAs', desc: 'Logon with explicit credentials (runas, net use). Lateral movement indicator when source is workstation.' },
          { id: '4657', name: 'Registry Value Modified', severity: 'HIGH', mitre: 'T1112', threat: 'Registry Persistence', desc: 'Registry value modified. Monitor Run/RunOnce keys, security-critical policies, SAM/LSA keys.' },
          { id: '4662', name: 'AD Object Operation', severity: 'CRIT', mitre: 'T1003.006', threat: 'DCSync', desc: 'AD object operation performed. Properties 1131f6aa/1131f6ad=replication rights=DCSync. Non-DC source IP is critical alert.' },
          { id: '4663', name: 'Object Access Attempt', severity: 'MED', mitre: 'T1005', threat: 'Data Access', desc: 'Attempt to access object. Monitor LSASS.exe, SAM database, NTDS.dit, sensitive documents.' },
          { id: '4670', name: 'Permissions Changed', severity: 'HIGH', mitre: 'T1222', threat: 'Permission Change', desc: 'Object permissions changed. Monitor ACL changes on AD objects, admin shares, sensitive directories.' },
          { id: '4672', name: 'Special Privileges Assigned', severity: 'HIGH', mitre: 'T1134', threat: 'Privilege Escalation', desc: 'Special privileges assigned at logon. SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege are high-value.' },
          { id: '4688', name: 'Process Created', severity: 'MED', mitre: 'T1059', threat: 'Process Execution', desc: 'New process created. Enable command line auditing. Watch encoded PowerShell (-enc), LOLBins (certutil, mshta, wscript, regsvr32).' },
          { id: '4689', name: 'Process Exited', severity: 'INFO', mitre: 'T1059', threat: 'Process Tracking', desc: 'Process exited. Short-lived processes may be execution cradles for shellcode injection.' },
          { id: '4697', name: 'Service Installed', severity: 'CRIT', mitre: 'T1543.003', threat: 'Service Persistence', desc: 'Service installed. PsExec=PSEXESVC. Ransomware deploys via services. Monitor binary paths in Temp/AppData.' },
          { id: '4698', name: 'Scheduled Task Created', severity: 'HIGH', mitre: 'T1053.005', threat: 'Scheduled Task Persistence', desc: 'Scheduled task created. Monitor tasks in Temp/AppData paths, tasks running encoded PowerShell.' },
          { id: '4699', name: 'Scheduled Task Deleted', severity: 'MED', mitre: 'T1053.005', threat: 'Anti-Forensics', desc: 'Scheduled task deleted. Attacker removing persistence post-objective.' },
          { id: '4700', name: 'Scheduled Task Enabled', severity: 'MED', mitre: 'T1053.005', threat: 'Persistence Activation', desc: 'Disabled task re-enabled. Attacker activating dormant persistence mechanism.' },
          { id: '4702', name: 'Scheduled Task Updated', severity: 'MED', mitre: 'T1053.005', threat: 'Persistence Modification', desc: 'Scheduled task modified. Attacker changing existing task to execute malicious payload.' },
          { id: '4720', name: 'User Account Created', severity: 'HIGH', mitre: 'T1136', threat: 'Account Creation', desc: 'New user account created. Monitor for attacker persistence backdoor accounts, especially if admin.' },
          { id: '4722', name: 'User Account Enabled', severity: 'MED', mitre: 'T1078', threat: 'Account Manipulation', desc: 'Disabled account re-enabled. Re-enabling dormant admin accounts is attacker technique.' },
          { id: '4724', name: 'Password Reset Attempt', severity: 'HIGH', mitre: 'T1098', threat: 'Account Manipulation', desc: 'Account password reset. Attackers reset target account passwords to take over.' },
          { id: '4725', name: 'User Account Disabled', severity: 'HIGH', mitre: 'T1531', threat: 'Account Disruption', desc: 'Account disabled. Ransomware disables admin accounts to prevent recovery. Also used by attackers.' },
          { id: '4726', name: 'User Account Deleted', severity: 'HIGH', mitre: 'T1531', threat: 'Account Disruption', desc: 'Account deleted. Anti-forensics or disruption. Check if it was an admin account.' },
          { id: '4728', name: 'Member Added to Global Group', severity: 'HIGH', mitre: 'T1098.007', threat: 'Privilege Escalation', desc: 'Added to global security group. Domain Admins, Enterprise Admins additions are critical alerts.' },
          { id: '4732', name: 'Member Added to Local Group', severity: 'HIGH', mitre: 'T1098.007', threat: 'Privilege Escalation', desc: 'Added to local Administrators group. Very common lateral movement step.' },
          { id: '4740', name: 'Account Locked Out', severity: 'MED', mitre: 'T1110', threat: 'Brute Force', desc: 'Account locked. Multiple lockouts across many accounts in short time = password spray.' },
          { id: '4756', name: 'Member Added to Universal Group', severity: 'HIGH', mitre: 'T1098.007', threat: 'Privilege Escalation', desc: 'Enterprise Admins or Schema Admins additions are critical.' },
          { id: '4765', name: 'SID History Added', severity: 'CRIT', mitre: 'T1134.005', threat: 'SID History Injection', desc: 'SID history added to account. Almost always malicious outside AD migrations. Golden ticket technique.' },
          { id: '4768', name: 'Kerberos TGT Requested', severity: 'INFO', mitre: 'T1558', threat: 'Kerberos Attack', desc: 'Kerberos TGT requested. No pre-auth required = AS-REP Roasting target. RC4 encryption type = downgrade.' },
          { id: '4769', name: 'Kerberos TGS Requested', severity: 'HIGH', mitre: 'T1558.003', threat: 'Kerberoasting', desc: 'Service ticket requested. Encryption type 0x17 (RC4) = Kerberoasting. Multiple non-machine accounts in short time = automated roasting.' },
          { id: '4771', name: 'Kerberos Pre-Auth Failed', severity: 'MED', mitre: 'T1110', threat: 'Kerberos Brute Force', desc: 'Pre-authentication failed. High volume = brute force against Active Directory accounts.' },
          { id: '4776', name: 'NTLM Authentication', severity: 'MED', mitre: 'T1550.002', threat: 'Pass-the-Hash', desc: 'NTLM credential validation. Pass-the-hash uses NTLM. Monitor workstation-to-workstation NTLM.' },
          { id: '4794', name: 'DSRM Password Set', severity: 'CRIT', mitre: 'T1098', threat: 'DSRM Backdoor', desc: 'Directory Services Restore Mode password set. Persistent domain controller backdoor technique.' },
          { id: '4798', name: 'User Local Group Membership Enumerated', severity: 'MED', mitre: 'T1069', threat: 'AD Recon (BloodHound)', desc: 'User group membership enumerated. BloodHound triggers thousands rapidly - look for mass enumeration pattern.' },
          { id: '4799', name: 'Security Group Membership Enumerated', severity: 'MED', mitre: 'T1069', threat: 'AD Recon', desc: 'Security group membership enumerated. Combined with 4798 = BloodHound or PowerView recon.' },
          { id: '4964', name: 'Special Groups Logon', severity: 'HIGH', mitre: 'T1078', threat: 'Privileged Access', desc: 'Special configured groups assigned to new logon. Custom alerting for sensitive group access.' },
          { id: '1102', name: 'Audit Log Cleared', severity: 'CRIT', mitre: 'T1070.001', threat: 'Anti-Forensics', desc: 'Security audit log cleared. Almost always malicious. Attacker erasing evidence before detection.' },
          { id: '104', name: 'System Log Cleared', severity: 'CRIT', mitre: 'T1070.001', threat: 'Anti-Forensics', desc: 'System event log cleared. Combined with 1102 = attacker covering tracks.' },
          { id: '7045', name: 'New Service Installed', severity: 'CRIT', mitre: 'T1543.003', threat: 'Service Persistence', desc: 'New service installed in System log. PsExec creates PSEXESVC. Monitor binary paths in Temp/AppData.' },
          { id: '7036', name: 'Service State Changed', severity: 'MED', mitre: 'T1543.003', threat: 'Service Manipulation', desc: 'Service started or stopped. Attackers stop AV/EDR/backup services. Mass stops = ransomware pre-encryption.' },
        ]
      },
      powershell: {
        label: 'PowerShell Logging', source: 'Microsoft-Windows-PowerShell/Operational',
        events: [
          { id: '4103', name: 'PowerShell Pipeline Execution', severity: 'HIGH', mitre: 'T1059.001', threat: 'PowerShell Execution', desc: 'Pipeline execution. Captures full pipeline and output. Look for encoded commands, downloads, AMSI bypass.' },
          { id: '4104', name: 'PowerShell Script Block Logging', severity: 'HIGH', mitre: 'T1059.001', threat: 'PowerShell Attack', desc: 'Script block logged. Captures all PowerShell code even if obfuscated. Best detection source for PS attacks.' },
          { id: '400', name: 'PowerShell Engine Started', severity: 'MED', mitre: 'T1059.001', threat: 'PowerShell Execution', desc: 'PS engine started. -NoProfile, -NonInteractive, -WindowStyle Hidden = suspicious invocation flags.' },
          { id: '600', name: 'PowerShell Provider Started', severity: 'INFO', mitre: 'T1059.001', threat: 'PowerShell Provider', desc: 'Provider started. WSMan provider in context of unusual process = remoting attempt.' },
        ]
      },
      sysmon: {
        label: 'Sysmon Events', source: 'Microsoft-Windows-Sysmon/Operational',
        events: [
          { id: '1', name: 'Process Create', severity: 'MED', mitre: 'T1059', threat: 'Process Execution', desc: 'Process created with full command line, hash, parent process. Best process creation source.' },
          { id: '2', name: 'File Creation Time Changed', severity: 'HIGH', mitre: 'T1070.006', threat: 'Timestomping', desc: 'File timestamp modified. Anti-forensics to hide malware creation time.' },
          { id: '3', name: 'Network Connection', severity: 'MED', mitre: 'T1071', threat: 'C2 Communication', desc: 'Network connection made. Captures process, destination IP/port, direction. Critical for C2 detection.' },
          { id: '5', name: 'Process Terminated', severity: 'INFO', mitre: 'T1059', threat: 'Process Tracking', desc: 'Process ended. Short-lived processes are execution cradles.' },
          { id: '6', name: 'Driver Loaded', severity: 'HIGH', mitre: 'T1014', threat: 'Rootkit', desc: 'Driver loaded. Unsigned or rarely-seen drivers = rootkit indicator.' },
          { id: '7', name: 'Image Loaded', severity: 'HIGH', mitre: 'T1055', threat: 'DLL Injection', desc: 'DLL loaded by process. Suspicious DLLs in unexpected paths, reflective loading indicators.' },
          { id: '8', name: 'CreateRemoteThread', severity: 'CRIT', mitre: 'T1055', threat: 'Process Injection', desc: 'Remote thread created in another process. Primary injection indicator (Metasploit, Cobalt Strike).' },
          { id: '10', name: 'ProcessAccess - LSASS', severity: 'CRIT', mitre: 'T1003.001', threat: 'Credential Dumping', desc: 'Process opened LSASS.exe. Mimikatz, ProcDump, Task Manager. Non-system processes = critical alert.' },
          { id: '11', name: 'File Created', severity: 'LOW', mitre: 'T1105', threat: 'File Drop', desc: 'File created on disk. Monitor Temp/AppData/Downloads. Captures tool drops.' },
          { id: '12', name: 'Registry Object Added/Deleted', severity: 'MED', mitre: 'T1547', threat: 'Registry Persistence', desc: 'Registry key created or deleted. Monitor Run/RunOnce, services, COM hijack paths.' },
          { id: '13', name: 'Registry Value Set', severity: 'HIGH', mitre: 'T1547', threat: 'Registry Persistence', desc: 'Registry value set. HKCU/HKLM Run, Winlogon, AppInit_DLLs = persistence paths.' },
          { id: '15', name: 'FileCreateStreamHash', severity: 'HIGH', mitre: 'T1564.004', threat: 'NTFS ADS', desc: 'Alternate data stream created. Hiding payloads in ADS is LOTL technique.' },
          { id: '17', name: 'Pipe Created', severity: 'HIGH', mitre: 'T1559', threat: 'Named Pipe C2', desc: 'Named pipe created. Cobalt Strike uses named pipes for inter-process comms.' },
          { id: '18', name: 'Pipe Connected', severity: 'HIGH', mitre: 'T1559', threat: 'Named Pipe C2', desc: 'Named pipe connection. PsExec and Cobalt Strike beacon indicators.' },
          { id: '22', name: 'DNS Query', severity: 'LOW', mitre: 'T1071.004', threat: 'DNS C2', desc: 'DNS query made. Long subdomains, high entropy domains, frequent queries = DNS tunneling.' },
          { id: '23', name: 'File Deleted', severity: 'MED', mitre: 'T1070.004', threat: 'File Anti-Forensics', desc: 'File deleted. Attacker deleting tools, logs, evidence after attack.' },
          { id: '25', name: 'Process Tampering', severity: 'CRIT', mitre: 'T1055', threat: 'Process Hollowing', desc: 'Process image change detected. Process hollowing or doppelganging technique.' },
          { id: '26', name: 'File Delete Logged', severity: 'MED', mitre: 'T1070.004', threat: 'Anti-Forensics', desc: 'File delete logged with hash. Forensic evidence even after deletion.' },
        ]
      },
      wdac: {
        label: 'Windows Defender / AMSI', source: 'Microsoft-Windows-Windows Defender/Operational',
        events: [
          { id: '1116', name: 'Malware Detected', severity: 'CRIT', mitre: 'T1204', threat: 'Malware Execution', desc: 'Defender detected malware. Correlate with process creation and network events for full picture.' },
          { id: '1117', name: 'Antimalware Action Taken', severity: 'HIGH', mitre: 'T1204', threat: 'Malware Action', desc: 'Defender took action (quarantine/remove). Check if action succeeded or failed.' },
          { id: '1119', name: 'Malware Remediation Succeeded', severity: 'MED', mitre: 'T1204', threat: 'Malware Cleaned', desc: 'Malware successfully remediated. Verify no persistence remains.' },
          { id: '1120', name: 'Malware Remediation Failed', severity: 'CRIT', mitre: 'T1204', threat: 'Active Malware', desc: 'Malware remediation failed. Host likely still infected. Isolate immediately.' },
          { id: '5004', name: 'Real-time Protection Disabled', severity: 'CRIT', mitre: 'T1562.001', threat: 'Defense Evasion', desc: 'Defender real-time protection disabled. Attacker disabling AV before payload drop.' },
          { id: '5007', name: 'Defender Config Changed', severity: 'HIGH', mitre: 'T1562.001', threat: 'Defense Evasion', desc: 'Defender configuration changed. Exclusion paths added = attacker creating safe drop zone.' },
        ]
      }
    }
  },

  activedirectory: {
    label: 'Active Directory', icon: '🏛️', color: '#5c2d91',
    categories: {
      domain: {
        label: 'Domain Controller Events', source: 'WinEventLog:Security (DC)',
        events: [
          { id: '4741', name: 'Computer Account Created', severity: 'HIGH', mitre: 'T1136.002', threat: 'Rogue Computer Account', desc: 'New computer account added to domain. Attacker-created machine accounts can be used for Silver Tickets.' },
          { id: '4742', name: 'Computer Account Changed', severity: 'MED', mitre: 'T1098', threat: 'Account Manipulation', desc: 'Computer account modified. msDS-AllowedToActOnBehalfOfOtherIdentity change = RBCD attack setup.' },
          { id: '4743', name: 'Computer Account Deleted', severity: 'HIGH', mitre: 'T1531', threat: 'Disruption', desc: 'Computer account deleted. Removing DCs from domain during attack.' },
          { id: '4928', name: 'AD Replica Source Naming Context', severity: 'CRIT', mitre: 'T1003.006', threat: 'DCSync', desc: 'Replication naming context established. Non-DC requesting replication = DCSync attack in progress.' },
          { id: '4929', name: 'AD Replica Source NC Removed', severity: 'HIGH', mitre: 'T1003.006', threat: 'DCSync', desc: 'Replication source removed after sync. DCSync cleanup.' },
          { id: '5136', name: 'Directory Service Object Modified', severity: 'HIGH', mitre: 'T1222.001', threat: 'ACL Abuse', desc: 'AD object modified via LDAP. AdminSDHolder changes, ACL modifications = persistence. Monitor AdminCount=1 objects.' },
          { id: '5137', name: 'Directory Service Object Created', severity: 'HIGH', mitre: 'T1136.002', threat: 'AD Object Creation', desc: 'New AD object created. Unexpected OUs, groups, or service accounts = attacker persistence.' },
          { id: '5141', name: 'Directory Service Object Deleted', severity: 'HIGH', mitre: 'T1531', threat: 'AD Disruption', desc: 'AD object deleted. Deleting critical OUs or accounts = destructive attack.' },
          { id: '5145', name: 'Network Share Access Check', severity: 'MED', mitre: 'T1039', threat: 'Network Share Recon', desc: 'Network share access checked. Mass enumeration of shares = attacker mapping file servers.' },
          { id: '4706', name: 'New Domain Trust Created', severity: 'CRIT', mitre: 'T1484.002', threat: 'Domain Trust Abuse', desc: 'New domain trust established. Attacker adding rogue domain trust for lateral access.' },
          { id: '4707', name: 'Domain Trust Removed', severity: 'HIGH', mitre: 'T1484.002', threat: 'Trust Manipulation', desc: 'Domain trust removed. Disruption or removing defender visibility.' },
          { id: '4713', name: 'Kerberos Policy Changed', severity: 'CRIT', mitre: 'T1558', threat: 'Kerberos Policy', desc: 'Kerberos policy changed. Max ticket lifetime increase = Golden Ticket longevity.' },
          { id: '4716', name: 'Trusted Domain Info Changed', severity: 'CRIT', mitre: 'T1484', threat: 'Domain Trust Abuse', desc: 'Trusted domain modified. SID filtering disabled = SID history attack enablement.' },
          { id: '4739', name: 'Domain Policy Changed', severity: 'CRIT', mitre: 'T1484.001', threat: 'Group Policy Abuse', desc: 'Domain policy changed. Password policy weakened = facilitates credential attacks.' },
          { id: '5144', name: 'Network Share Deleted', severity: 'HIGH', mitre: 'T1070', threat: 'Anti-Forensics', desc: 'Network share deleted. Attacker removing evidence or C2 infrastructure.' },
        ]
      },
      gpo: {
        label: 'Group Policy Events', source: 'Microsoft-Windows-GroupPolicy/Operational',
        events: [
          { id: '4660', name: 'GPO Deleted', severity: 'CRIT', mitre: 'T1484.001', threat: 'GPO Manipulation', desc: 'Group Policy Object deleted. Critical security GPOs deleted = disabling security controls.' },
          { id: '5312', name: 'GPO Applied', severity: 'INFO', mitre: 'T1484.001', threat: 'GPO Tracking', desc: 'Group Policy applied to computer. Track new GPOs applying to DCs = lateral movement.' },
          { id: '5313', name: 'GPO Not Applied (Error)', severity: 'HIGH', mitre: 'T1484.001', threat: 'GPO Block', desc: 'GPO failed to apply. Attacker may be blocking security policies.' },
        ]
      }
    }
  },

  linux: {
    label: 'Linux / Unix', icon: '🐧', color: '#dd4814',
    categories: {
      auth: {
        label: 'Authentication (/var/log/auth.log)', source: '/var/log/auth.log',
        events: [
          { id: 'auth-su', name: 'su - Root Switch', severity: 'HIGH', mitre: 'T1548.003', threat: 'Privilege Escalation', desc: 'su command executed. Root switch. Monitor for non-authorized users or unusual times.' },
          { id: 'auth-sudo', name: 'sudo Command Executed', severity: 'HIGH', mitre: 'T1548.003', threat: 'Privilege Escalation', desc: 'sudo executed. Full command captured. Monitor for sudo bash, sudo su, unusual binaries.' },
          { id: 'auth-sshfail', name: 'SSH Failed Password', severity: 'MED', mitre: 'T1110', threat: 'Brute Force', desc: 'SSH auth failed. High rate from single IP = brute force. Distributed = credential stuffing.' },
          { id: 'auth-sshaccept', name: 'SSH Accepted', severity: 'INFO', mitre: 'T1021.004', threat: 'Remote Access', desc: 'SSH connection accepted. Monitor source IPs, key-based vs password auth, new users.' },
          { id: 'auth-sshinvaliduser', name: 'SSH Invalid User', severity: 'MED', mitre: 'T1110', threat: 'User Enumeration', desc: 'SSH attempt for non-existent user. Attacker enumerating valid usernames.' },
          { id: 'auth-newuser', name: 'useradd / New User', severity: 'CRIT', mitre: 'T1136.001', threat: 'Backdoor Account', desc: 'New system user created. Especially with UID 0 or shell=/bin/bash = backdoor.' },
          { id: 'auth-groupmod', name: 'Group Modified', severity: 'HIGH', mitre: 'T1098', threat: 'Group Modification', desc: 'Group modified (usermod -aG). Adding to sudo/wheel/docker group = privilege escalation.' },
          { id: 'auth-passwdchange', name: 'Password Changed', severity: 'HIGH', mitre: 'T1098', threat: 'Account Manipulation', desc: 'Password changed. Attacker changing passwords to lock out admins.' },
          { id: 'auth-cron', name: 'Crontab Modified', severity: 'HIGH', mitre: 'T1053.003', threat: 'Cron Persistence', desc: 'Crontab installed. Common Linux persistence mechanism. Monitor unusual cron jobs.' },
          { id: 'auth-sshkeyadd', name: 'Authorized Keys Modified', severity: 'CRIT', mitre: 'T1098.004', threat: 'SSH Key Persistence', desc: 'SSH authorized_keys modified. Attacker adding SSH key for persistent access.' },
        ]
      },
      syslog: {
        label: 'System Log (/var/log/syslog)', source: '/var/log/syslog',
        events: [
          { id: 'sys-kernel', name: 'Kernel Module Loaded', severity: 'CRIT', mitre: 'T1014', threat: 'Rootkit', desc: 'Kernel module loaded (insmod/modprobe). Unsigned or unknown modules = rootkit.' },
          { id: 'sys-oomkill', name: 'OOM Killer Invoked', severity: 'HIGH', mitre: 'T1499', threat: 'Resource Exhaustion', desc: 'Out-of-memory killer killed process. Cryptominer or DoS attack may cause OOM.' },
          { id: 'sys-sudoers', name: 'Sudoers File Changed', severity: 'CRIT', mitre: 'T1548.003', threat: 'Sudo Persistence', desc: 'Sudoers file modified. NOPASSWD entries = privilege escalation without password.' },
          { id: 'sys-firewall', name: 'iptables Rules Changed', severity: 'HIGH', mitre: 'T1562.004', threat: 'Firewall Evasion', desc: 'Firewall rules modified. Attacker opening ports or disabling blocking rules.' },
          { id: 'sys-mount', name: 'Filesystem Mounted', severity: 'MED', mitre: 'T1052', threat: 'Exfil via Removable Media', desc: 'Device mounted. USB drives or network shares mounted = potential exfil path.' },
          { id: 'sys-dnschg', name: 'DNS Config Changed', severity: 'HIGH', mitre: 'T1557', threat: 'DNS Manipulation', desc: '/etc/resolv.conf modified. DNS hijacking for MITM or C2.' },
        ]
      },
      auditd: {
        label: 'Linux Audit (auditd)', source: '/var/log/audit/audit.log',
        events: [
          { id: 'auditd-execve', name: 'EXECVE - Command Execution', severity: 'MED', mitre: 'T1059.004', threat: 'Shell Execution', desc: 'Command executed. Full command line captured. Best Linux execution tracking source.' },
          { id: 'auditd-open', name: 'OPEN - File Access', severity: 'LOW', mitre: 'T1005', threat: 'Data Access', desc: 'File opened. Monitor /etc/passwd, /etc/shadow, SSH keys, credentials files.' },
          { id: 'auditd-write', name: 'WRITE - File Modified', severity: 'MED', mitre: 'T1565', threat: 'Data Manipulation', desc: 'File modified. Monitor critical config files, crontabs, authorized_keys.' },
          { id: 'auditd-netconn', name: 'SOCK_ADDR - Network Connect', severity: 'MED', mitre: 'T1071', threat: 'C2 Communication', desc: 'Network connection from process. Unusual outbound from servers = C2 or data exfil.' },
          { id: 'auditd-ptrace', name: 'PTRACE - Process Trace', severity: 'HIGH', mitre: 'T1055', threat: 'Process Injection', desc: 'Ptrace system call. Used for process injection, credential dumping (mimipenguin).' },
          { id: 'auditd-chown', name: 'CHOWN - Ownership Change', severity: 'HIGH', mitre: 'T1548', threat: 'Privilege Abuse', desc: 'File ownership changed. root chown to attacker user = privilege escalation.' },
          { id: 'auditd-chmod', name: 'CHMOD - Permission Change', severity: 'HIGH', mitre: 'T1222', threat: 'Permission Change', desc: 'File permissions changed. chmod +s (SUID) = privilege escalation path.' },
          { id: 'auditd-mmap', name: 'MMAP - Memory Mapping', severity: 'HIGH', mitre: 'T1055', threat: 'Memory Injection', desc: 'Memory mapping with execute flag. Shellcode injection technique.' },
        ]
      }
    }
  },

  azure: {
    label: 'Azure / Entra ID', icon: '☁️', color: '#0078d4',
    categories: {
      entraid: {
        label: 'Entra ID (Azure AD) Sign-in Logs', source: 'AzureAD / SigninLogs',
        events: [
          { id: 'az-signin-success', name: 'Successful Sign-in', severity: 'INFO', mitre: 'T1078.004', threat: 'Cloud Credential Use', desc: 'Azure AD successful logon. Monitor for impossible travel, unfamiliar locations, legacy auth protocols.' },
          { id: 'az-signin-fail', name: 'Failed Sign-in', severity: 'MED', mitre: 'T1110', threat: 'Brute Force', desc: 'Azure AD failed logon. ResultType 50126=wrong creds, 50074=MFA required, 50076=MFA failed.' },
          { id: 'az-mfarequired', name: 'MFA Required/Result', severity: 'MED', mitre: 'T1556', threat: 'MFA Bypass', desc: 'MFA challenge. ResultType 500121=MFA denied, 50158=MFA fatigue, 50131=conditional access blocked.' },
          { id: 'az-impossibletravel', name: 'Impossible Travel Detected', severity: 'HIGH', mitre: 'T1078.004', threat: 'Account Compromise', desc: 'Sign-in from geographically impossible location. Classic account takeover indicator.' },
          { id: 'az-legacyauth', name: 'Legacy Authentication', severity: 'HIGH', mitre: 'T1078', threat: 'MFA Bypass', desc: 'Basic auth protocol used (IMAP, POP3, SMTP AUTH). Legacy auth bypasses MFA.' },
          { id: 'az-newdevice', name: 'Sign-in from New Device', severity: 'MED', mitre: 'T1078.004', threat: 'Account Compromise', desc: 'First sign-in from new device or browser. Correlate with other risk signals.' },
          { id: 'az-tokensteal', name: 'Anomalous Token Use', severity: 'CRIT', mitre: 'T1550.001', threat: 'Token Theft', desc: 'Token used from different location than where issued. AiTM phishing (Evilginx) indicator.' },
        ]
      },
      azureaudit: {
        label: 'Azure Activity Logs', source: 'AzureActivity / AuditLogs',
        events: [
          { id: 'az-rbac-assign', name: 'RBAC Role Assignment', severity: 'HIGH', mitre: 'T1098.003', threat: 'Cloud Privilege Escalation', desc: 'Azure RBAC role assigned. Owner/Contributor/User Access Admin = privilege escalation. Monitor at management group level.' },
          { id: 'az-sp-create', name: 'Service Principal Created', severity: 'HIGH', mitre: 'T1136.003', threat: 'Cloud Persistence', desc: 'New service principal or app registration. Attacker creating long-term API access credential.' },
          { id: 'az-sp-cred', name: 'Service Principal Credential Added', severity: 'CRIT', mitre: 'T1098.001', threat: 'Cloud Persistence', desc: 'New credential added to existing SP. Attacker adding secret/cert to legitimate app for persistence.' },
          { id: 'az-policy-change', name: 'Azure Policy Modified', severity: 'HIGH', mitre: 'T1562', threat: 'Security Control Bypass', desc: 'Azure Policy assignment changed. Disabling compliance policies = allowing non-compliant resources.' },
          { id: 'az-diag-delete', name: 'Diagnostic Setting Deleted', severity: 'CRIT', mitre: 'T1562.008', threat: 'Log Evasion', desc: 'Diagnostic logging disabled. Attacker removing visibility before malicious actions.' },
          { id: 'az-kv-secret', name: 'Key Vault Secret Access', severity: 'HIGH', mitre: 'T1552.001', threat: 'Credential Theft', desc: 'Key Vault secret read. Unusual service principal or user accessing KV secrets = credential theft.' },
          { id: 'az-storage-access', name: 'Storage Account Access', severity: 'MED', mitre: 'T1530', threat: 'Cloud Data Access', desc: 'Blob or file storage accessed. Public container access, bulk downloads = data exfiltration.' },
          { id: 'az-vm-runcommand', name: 'VM Run Command Executed', severity: 'CRIT', mitre: 'T1059', threat: 'Cloud Execution', desc: 'Run Command executed on VM. Remote execution without direct access. Attacker persistence or lateral movement.' },
          { id: 'az-subnet-create', name: 'Subnet/VNet Modified', severity: 'HIGH', mitre: 'T1563', threat: 'Network Manipulation', desc: 'VNet or subnet created/modified. Attacker creating network pivot points in cloud.' },
          { id: 'az-nsg-rule', name: 'NSG Rule Added', severity: 'HIGH', mitre: 'T1562.004', threat: 'Firewall Bypass', desc: 'Network Security Group rule added. Inbound 0.0.0.0/0 on any port = attacker opening access.' },
        ]
      },
      m365: {
        label: 'Microsoft 365 / Exchange Online', source: 'OfficeActivity / UnifiedAuditLog',
        events: [
          { id: 'o365-mailforward', name: 'Mail Forwarding Rule Created', severity: 'CRIT', mitre: 'T1114.003', threat: 'Email Exfiltration', desc: 'Auto-forwarding rule created to external address. Classic BEC and data exfil technique.' },
          { id: 'o365-mailinbox', name: 'Inbox Rule Created', severity: 'HIGH', mitre: 'T1114', threat: 'Email Manipulation', desc: 'Inbox rule created. Moving/deleting emails to hide phishing activity from victim.' },
          { id: 'o365-filesearch', name: 'SharePoint/OneDrive Search', severity: 'MED', mitre: 'T1213', threat: 'Cloud Data Discovery', desc: 'File search or bulk access in SharePoint. Attacker hunting for sensitive documents.' },
          { id: 'o365-fileshare', name: 'Anonymous Link Created', severity: 'HIGH', mitre: 'T1567', threat: 'Cloud Data Exfiltration', desc: 'Anyone link created for sensitive file. Data exfiltration via sharing.' },
          { id: 'o365-mfachange', name: 'MFA Method Changed', severity: 'CRIT', mitre: 'T1556', threat: 'MFA Persistence', desc: 'MFA device/method changed. Attacker registering their own MFA device for persistence.' },
          { id: 'o365-appconsent', name: 'OAuth App Consent Granted', severity: 'CRIT', mitre: 'T1528', threat: 'OAuth App Abuse', desc: 'OAuth app granted access to tenant. Illicit consent grant attack for persistent M365 access.' },
          { id: 'o365-dlpblock', name: 'DLP Policy Matched', severity: 'HIGH', mitre: 'T1048', threat: 'Data Exfiltration Attempt', desc: 'Data Loss Prevention policy triggered. Sensitive data transmission attempted.' },
          { id: 'o365-adminrole', name: 'Admin Role Assignment', severity: 'CRIT', mitre: 'T1098', threat: 'Privilege Escalation', desc: 'Global Admin or privileged role assigned. Immediate investigation required.' },
        ]
      }
    }
  },

  aws: {
    label: 'AWS CloudTrail', icon: '☁️', color: '#ff9900',
    categories: {
      cloudtrail: {
        label: 'CloudTrail - Management Events', source: 'AWS CloudTrail',
        events: [
          { id: 'aws-iam-attach', name: 'AttachRolePolicy / AttachUserPolicy', severity: 'HIGH', mitre: 'T1098.003', threat: 'IAM Privilege Escalation', desc: 'IAM policy attached. AdministratorAccess attached to user/role = immediate privilege escalation.' },
          { id: 'aws-assume-role', name: 'AssumeRole / AssumeRoleWithWebIdentity', severity: 'MED', mitre: 'T1548', threat: 'Role Assumption', desc: 'IAM role assumed. Cross-account assumptions from new principals = lateral movement.' },
          { id: 'aws-iam-user', name: 'CreateUser / CreateAccessKey', severity: 'HIGH', mitre: 'T1136.003', threat: 'Cloud Persistence', desc: 'IAM user or access key created. Attacker creating persistent programmatic access.' },
          { id: 'aws-bucket-acl', name: 'PutBucketAcl - Public Access', severity: 'CRIT', mitre: 'T1530', threat: 'Data Exposure', desc: 'S3 bucket made public. Immediate data exposure risk. Monitor for AllUsers grants.' },
          { id: 'aws-getobject-bulk', name: 'Bulk S3 GetObject', severity: 'HIGH', mitre: 'T1530', threat: 'Data Exfiltration', desc: 'Mass S3 object downloads. Attacker bulk-downloading data before ransom or leak.' },
          { id: 'aws-console-login', name: 'ConsoleLogin - Root', severity: 'CRIT', mitre: 'T1078', threat: 'Root Account Use', desc: 'AWS root account console login. Root should NEVER log in routinely. Immediate alert.' },
          { id: 'aws-trail-delete', name: 'DeleteTrail / StopLogging', severity: 'CRIT', mitre: 'T1562.008', threat: 'Log Evasion', desc: 'CloudTrail disabled. Attacker removing audit visibility before malicious actions.' },
          { id: 'aws-sg-authorize', name: 'AuthorizeSecurityGroupIngress', severity: 'HIGH', mitre: 'T1562.004', threat: 'Firewall Rule Added', desc: 'Security group inbound rule added. 0.0.0.0/0 on sensitive ports = unauthorized access.' },
          { id: 'aws-lambda-create', name: 'CreateFunction / UpdateFunctionCode', severity: 'HIGH', mitre: 'T1059', threat: 'Lambda Persistence', desc: 'Lambda function created or updated. Attacker deploying serverless backdoor or cryptominer.' },
          { id: 'aws-eks-exec', name: 'EKS Pod Exec', severity: 'HIGH', mitre: 'T1609', threat: 'Container Execution', desc: 'kubectl exec into container. Interactive shell in production container = attacker access.' },
          { id: 'aws-ec2-userdata', name: 'ModifyInstanceAttribute (UserData)', severity: 'CRIT', mitre: 'T1059', threat: 'Cloud Execution', desc: 'EC2 instance user data modified. Executed on next restart = persistent malicious code.' },
          { id: 'aws-pass-role', name: 'PassRole - Privilege Escalation', severity: 'CRIT', mitre: 'T1548', threat: 'IAM Privilege Escalation', desc: 'PassRole used to create service with higher permissions. Classic AWS privilege escalation.' },
          { id: 'aws-ssm-command', name: 'SSM SendCommand', severity: 'HIGH', mitre: 'T1059', threat: 'Remote Execution', desc: 'SSM Run Command executed. Remote code execution without SSH. Attacker lateral movement.' },
          { id: 'aws-secretsmanager', name: 'GetSecretValue', severity: 'HIGH', mitre: 'T1552', threat: 'Secret Theft', desc: 'Secret retrieved from Secrets Manager. Unusual principals accessing production secrets.' },
        ]
      },
      guardduty: {
        label: 'AWS GuardDuty Findings', source: 'AWS GuardDuty',
        events: [
          { id: 'gd-recon-ec2', name: 'Recon:EC2/PortProbeUnprotectedPort', severity: 'MED', mitre: 'T1046', threat: 'Port Scan', desc: 'Port probe on unprotected EC2 port. Recon precedes exploitation attempts.' },
          { id: 'gd-bitcoin', name: 'CryptoCurrency:EC2/BitcoinTool', severity: 'HIGH', mitre: 'T1496', threat: 'Cryptomining', desc: 'Cryptomining tool activity detected on EC2. Unauthorized resource use.' },
          { id: 'gd-trojan-dns', name: 'Trojan:EC2/DNSDataExfiltration', severity: 'HIGH', mitre: 'T1048.003', threat: 'DNS Exfiltration', desc: 'DNS tunneling detected. Data exfiltration via DNS queries.' },
          { id: 'gd-backdoor-c2', name: 'Backdoor:EC2/C&CActivity.B', severity: 'CRIT', mitre: 'T1071', threat: 'C2 Communication', desc: 'EC2 instance communicating with known C2 infrastructure.' },
          { id: 'gd-stealthyec2', name: 'Stealth:IAMUser/CloudTrailLoggingDisabled', severity: 'CRIT', mitre: 'T1562.008', threat: 'Log Evasion', desc: 'IAM user disabled CloudTrail. Pre-attack evasion technique.' },
        ]
      }
    }
  },

  gcp: {
    label: 'GCP Audit Logs', icon: '🌀', color: '#4285f4',
    categories: {
      gcp_admin: {
        label: 'GCP Admin Activity', source: 'GCP Cloud Audit Logs',
        events: [
          { id: 'gcp-sa-key', name: 'ServiceAccount Key Created', severity: 'HIGH', mitre: 'T1098', threat: 'Cloud Persistence', desc: 'Service account key created. Programmatic access credential for persistence.' },
          { id: 'gcp-iam-bind', name: 'SetIamPolicy - Binding Added', severity: 'CRIT', mitre: 'T1098.003', threat: 'IAM Privilege Escalation', desc: 'IAM policy binding modified. Attacker granting themselves owner role.' },
          { id: 'gcp-bucket-public', name: 'Bucket IAM - AllUsers Added', severity: 'CRIT', mitre: 'T1530', threat: 'Data Exposure', desc: 'GCS bucket made publicly accessible. Immediate data exposure risk.' },
          { id: 'gcp-org-policy', name: 'OrgPolicy Modified', severity: 'CRIT', mitre: 'T1562', threat: 'Security Control Bypass', desc: 'Organization policy modified. Disabling domain restrictions = attacker adding external users.' },
          { id: 'gcp-gce-ssh', name: 'Compute Metadata SSH Key Added', severity: 'CRIT', mitre: 'T1098.004', threat: 'SSH Persistence', desc: 'SSH key added via compute metadata. Persistent access to all VMs in project.' },
          { id: 'gcp-disable-logging', name: 'Logging Sink Deleted', severity: 'CRIT', mitre: 'T1562.008', threat: 'Log Evasion', desc: 'Log export sink deleted. Attacker removing audit trail.' },
          { id: 'gcp-cloudfunc', name: 'Cloud Function Deployed', severity: 'HIGH', mitre: 'T1059', threat: 'Serverless Backdoor', desc: 'New Cloud Function deployed. Attacker serverless backdoor or data exfil function.' },
        ]
      }
    }
  },

  network: {
    label: 'Network & Firewall', icon: '🌐', color: '#00a86b',
    categories: {
      firewall: {
        label: 'Firewall / NGFW Logs', source: 'Palo Alto / Cisco ASA / Fortinet',
        events: [
          { id: 'fw-allow-new', name: 'New Connection Allowed', severity: 'INFO', mitre: 'T1071', threat: 'Network Tracking', desc: 'New flow allowed. Baseline normal traffic patterns. Alert on new external destinations or ports.' },
          { id: 'fw-deny-outbound', name: 'Outbound Connection Blocked', severity: 'MED', mitre: 'T1071', threat: 'C2 Block', desc: 'Outbound connection blocked. Repeated denies to same IP = C2 callback being blocked.' },
          { id: 'fw-geoblocked', name: 'Geo-Blocked Country', severity: 'MED', mitre: 'T1071', threat: 'Geographic Anomaly', desc: 'Connection to/from geo-blocked country. May indicate C2 or data exfil attempt.' },
          { id: 'fw-portscan', name: 'Port Scan Detected', severity: 'HIGH', mitre: 'T1046', threat: 'Reconnaissance', desc: 'Port scan from internal or external source. Internal scanner = compromised host or red team.' },
          { id: 'fw-application', name: 'Application Layer Block', severity: 'MED', mitre: 'T1071.001', threat: 'Protocol Abuse', desc: 'Application-layer block. Blocked P2P, Tor, proxy tools = user evading controls.' },
          { id: 'fw-threat', name: 'Threat Signature Match', severity: 'CRIT', mitre: 'T1203', threat: 'Exploit Attempt', desc: 'IPS threat signature matched. Correlate with vulnerability data for exploitation attempt.' },
          { id: 'fw-data', name: 'DLP Data Pattern Match', severity: 'HIGH', mitre: 'T1048', threat: 'Data Exfiltration', desc: 'Data loss prevention pattern matched. Credit card, SSN, or custom sensitive data patterns.' },
          { id: 'fw-c2-signature', name: 'C2 Domain/IP Signature', severity: 'CRIT', mitre: 'T1071', threat: 'C2 Communication', desc: 'Known C2 IP or domain in threat intelligence. Active command and control communication.' },
        ]
      },
      dns: {
        label: 'DNS Logs', source: 'DNS Server / Zeek DNS',
        events: [
          { id: 'dns-dga', name: 'DGA Domain Query', severity: 'HIGH', mitre: 'T1568.002', threat: 'DGA C2', desc: 'High-entropy domain queried. Domain Generation Algorithm used by malware for C2 resilience.' },
          { id: 'dns-tunneling', name: 'DNS Tunneling Detected', severity: 'CRIT', mitre: 'T1048.003', threat: 'DNS Exfiltration', desc: 'Long subdomain query with high entropy. Data being exfiltrated via DNS. TXT record exfil.' },
          { id: 'dns-nxdomain', name: 'Mass NXDOMAIN Responses', severity: 'HIGH', mitre: 'T1568', threat: 'DGA/Recon', desc: 'Many non-existent domain queries. DGA malware cycling through domains or recon scanning.' },
          { id: 'dns-tor', name: 'Tor Exit Node DNS Query', severity: 'HIGH', mitre: 'T1090.003', threat: 'Anonymization', desc: 'Query for known Tor exit node. Attacker using Tor for anonymized C2.' },
          { id: 'dns-newdomain', name: 'Newly Registered Domain', severity: 'HIGH', mitre: 'T1583.001', threat: 'Attacker Infrastructure', desc: 'Query for domain registered <30 days ago. Attackers use fresh domains to avoid reputation blocks.' },
          { id: 'dns-internal-leak', name: 'Internal Hostname in DNS Response', severity: 'MED', mitre: 'T1590', threat: 'Information Disclosure', desc: 'Internal hostnames leaking in external DNS. Network topology disclosure.' },
        ]
      },
      proxy: {
        label: 'Web Proxy Logs', source: 'Squid / Bluecoat / Zscaler',
        events: [
          { id: 'proxy-useragent', name: 'Suspicious User-Agent', severity: 'HIGH', mitre: 'T1071.001', threat: 'C2 Communication', desc: 'Known malware user agent string. Metasploit, Cobalt Strike, curl-based downloaders.' },
          { id: 'proxy-postlarge', name: 'Large HTTP POST', severity: 'HIGH', mitre: 'T1048.002', threat: 'Data Exfiltration', desc: 'Large POST to external site. Data exfiltration over HTTP(S) to attacker server.' },
          { id: 'proxy-category', name: 'Uncategorized Domain', severity: 'MED', mitre: 'T1583', threat: 'Attacker Infrastructure', desc: 'Uncategorized or newly registered domain accessed. Common for attacker C2 infrastructure.' },
          { id: 'proxy-credential', name: 'Credential Submitted to External', severity: 'CRIT', mitre: 'T1056', threat: 'Credential Phishing', desc: 'Form POST containing credentials to external domain. Phishing site credential capture.' },
        ]
      },
      zeek: {
        label: 'Zeek/Bro IDS Logs', source: 'Zeek Network Monitor',
        events: [
          { id: 'zeek-conn', name: 'conn.log - New Connection', severity: 'INFO', mitre: 'T1071', threat: 'Network Baseline', desc: 'All network connections. Rich metadata: duration, bytes, protocol. Best for beaconing detection.' },
          { id: 'zeek-http', name: 'http.log - HTTP Transaction', severity: 'INFO', mitre: 'T1071.001', threat: 'HTTP Traffic', desc: 'Full HTTP request/response. Method, host, URI, user-agent, response code, body length.' },
          { id: 'zeek-ssl', name: 'ssl.log - TLS Session', severity: 'MED', mitre: 'T1573', threat: 'Encrypted C2', desc: 'TLS session metadata. JA3/JA3S fingerprints for Cobalt Strike, Metasploit detection.' },
          { id: 'zeek-dns', name: 'dns.log - DNS Query', severity: 'LOW', mitre: 'T1071.004', threat: 'DNS Traffic', desc: 'All DNS queries and responses. Essential for DGA and DNS tunneling detection.' },
          { id: 'zeek-files', name: 'files.log - File Transfer', severity: 'MED', mitre: 'T1105', threat: 'File Transfer', desc: 'Files transferred over network. Hash, MIME type, source. Tool downloads, malware staging.' },
          { id: 'zeek-weird', name: 'weird.log - Protocol Anomaly', severity: 'HIGH', mitre: 'T1095', threat: 'Protocol Abuse', desc: 'Protocol violations or anomalies. Non-standard protocol use for C2 or evasion.' },
          { id: 'zeek-notice', name: 'notice.log - Zeek Alert', severity: 'HIGH', mitre: 'T1071', threat: 'Zeek Signature Match', desc: 'Zeek detection engine alert. Signature matches, scan detection, policy violations.' },
          { id: 'zeek-smb', name: 'smb.log - SMB Activity', severity: 'HIGH', mitre: 'T1021.002', threat: 'Lateral Movement SMB', desc: 'SMB file/session activity. EternalBlue, PsExec, credential relay all appear in SMB logs.' },
          { id: 'zeek-kerberos', name: 'kerberos.log - Kerberos', severity: 'HIGH', mitre: 'T1558', threat: 'Kerberos Attack', desc: 'All Kerberos authentication. Kerberoasting, AS-REP, Golden/Silver Ticket all visible here.' },
        ]
      }
    }
  },

  cloud_iaas: {
    label: 'Cloud Infrastructure', icon: '🏗️', color: '#7b2d8b',
    categories: {
      kubernetes: {
        label: 'Kubernetes Audit Logs', source: 'K8s API Server Audit',
        events: [
          { id: 'k8s-pod-exec', name: 'Pod Exec / Attach', severity: 'CRIT', mitre: 'T1609', threat: 'Container Execution', desc: 'Exec or attach to running container. Interactive shell access. Attacker lateral movement in cluster.' },
          { id: 'k8s-rbac-bind', name: 'ClusterRoleBinding Created', severity: 'CRIT', mitre: 'T1098', threat: 'K8s Privilege Escalation', desc: 'ClusterRole binding created. Granting cluster-admin = full cluster compromise.' },
          { id: 'k8s-privileged-pod', name: 'Privileged Pod Created', severity: 'CRIT', mitre: 'T1611', threat: 'Container Escape', desc: 'Container started with privileged:true. Full host access, escape to underlying node.' },
          { id: 'k8s-hostpid', name: 'Pod with hostPID/hostNetwork', severity: 'CRIT', mitre: 'T1611', threat: 'Container Escape', desc: 'Pod sharing host PID namespace or network. Can access host processes and network.' },
          { id: 'k8s-secret-read', name: 'Secret Read', severity: 'HIGH', mitre: 'T1552', threat: 'Secret Theft', desc: 'Kubernetes Secret object read. May contain DB passwords, API keys, TLS certs.' },
          { id: 'k8s-ds-create', name: 'DaemonSet Created', severity: 'HIGH', mitre: 'T1543', threat: 'K8s Persistence', desc: 'DaemonSet created. Runs pod on every node = cluster-wide persistence/backdoor.' },
          { id: 'k8s-serviceaccount', name: 'ServiceAccount Token Mounted', severity: 'HIGH', mitre: 'T1528', threat: 'Token Theft', desc: 'SA token auto-mounted. Compromised pod can use SA token to escalate within cluster.' },
        ]
      },
      docker: {
        label: 'Docker / Container Logs', source: 'Docker Engine / containerd',
        events: [
          { id: 'docker-socket', name: 'Docker Socket Mounted', severity: 'CRIT', mitre: 'T1611', threat: 'Container Escape', desc: 'Docker socket mounted in container. Full Docker host control = container escape.' },
          { id: 'docker-pull', name: 'Suspicious Image Pull', severity: 'HIGH', mitre: 'T1204.003', threat: 'Malicious Image', desc: 'Image pulled from suspicious registry or with :latest tag. Supply chain attack vector.' },
          { id: 'docker-run-root', name: 'Container Running as Root', severity: 'HIGH', mitre: 'T1610', threat: 'Container Privilege', desc: 'Container process running as root. Increases escape risk if combined with other vulns.' },
          { id: 'docker-network-host', name: 'Host Network Mode', severity: 'HIGH', mitre: 'T1611', threat: 'Network Escape', desc: 'Container using host network mode. Direct access to host network interfaces.' },
        ]
      }
    }
  },

  database: {
    label: 'Database Logs', icon: '🗄️', color: '#cc3333',
    categories: {
      sqlserver: {
        label: 'SQL Server Audit', source: 'SQL Server Audit / ErrorLog',
        events: [
          { id: 'sql-login-fail', name: 'Failed Login', severity: 'MED', mitre: 'T1110', threat: 'Brute Force', desc: 'SQL Server login failure. Multiple failures = brute force. SA account failures = critical.' },
          { id: 'sql-privilege-use', name: 'Privilege Use / Special Login', severity: 'HIGH', mitre: 'T1078', threat: 'Privileged Access', desc: 'sysadmin or db_owner login. Monitor who uses highest-privilege SQL logins.' },
          { id: 'sql-xpcmd', name: 'xp_cmdshell Executed', severity: 'CRIT', mitre: 'T1505.001', threat: 'OS Command Injection', desc: 'xp_cmdshell executed. Direct OS command execution from SQL. Should be disabled.' },
          { id: 'sql-bulkinsert', name: 'BULK INSERT / OPENROWSET', severity: 'HIGH', mitre: 'T1190', threat: 'SQL Injection', desc: 'BULK INSERT or OPENROWSET used. Data import from UNC path = network credential theft.' },
          { id: 'sql-schema-change', name: 'DDL Schema Change', severity: 'HIGH', mitre: 'T1565', threat: 'Data Manipulation', desc: 'Table/procedure created, dropped, or modified. Monitor changes to critical tables.' },
          { id: 'sql-dump', name: 'SELECT * from sensitive tables', severity: 'HIGH', mitre: 'T1005', threat: 'Data Exfiltration', desc: 'Mass SELECT from user/account/PII tables. Attacker dumping sensitive data.' },
          { id: 'sql-link-server', name: 'Linked Server Query', severity: 'HIGH', mitre: 'T1210', threat: 'Lateral Movement', desc: 'Query via linked server. SQL-to-SQL lateral movement using linked server trust.' },
          { id: 'sql-sp-drop', name: 'Stored Procedure Drop', severity: 'HIGH', mitre: 'T1565', threat: 'Data Manipulation', desc: 'Stored procedure dropped. Anti-forensics or disabling security mechanisms.' },
        ]
      },
      mysql: {
        label: 'MySQL / MariaDB Logs', source: 'MySQL General Log / Error Log',
        events: [
          { id: 'mysql-root', name: 'Root Login from Non-Localhost', severity: 'CRIT', mitre: 'T1078', threat: 'Root Access', desc: 'MySQL root login from remote IP. MySQL root should only be accessible locally.' },
          { id: 'mysql-load-infile', name: 'LOAD DATA INFILE', severity: 'HIGH', mitre: 'T1059', threat: 'File Read', desc: 'LOAD DATA reads server-side files. Can read /etc/passwd if not restricted (secure_file_priv).' },
          { id: 'mysql-udf', name: 'UDF Function Created', severity: 'CRIT', mitre: 'T1505', threat: 'Server-Side Backdoor', desc: 'User Defined Function created from .so library. Classic MySQL RCE technique.' },
          { id: 'mysql-grant-all', name: 'GRANT ALL PRIVILEGES', severity: 'CRIT', mitre: 'T1098', threat: 'Privilege Escalation', desc: 'Full privileges granted to a user. Attacker creating persistent database admin account.' },
          { id: 'mysql-schema-drop', name: 'DROP DATABASE / DROP TABLE', severity: 'CRIT', mitre: 'T1485', threat: 'Data Destruction', desc: 'Database or table dropped. Ransomware or destructive attack on database.' },
        ]
      },
      postgresql: {
        label: 'PostgreSQL Logs', source: 'PostgreSQL pg_log',
        events: [
          { id: 'pg-superuser', name: 'Superuser Login', severity: 'HIGH', mitre: 'T1078', threat: 'Privileged Access', desc: 'PostgreSQL superuser login. Monitor postgres and other superuser account activity.' },
          { id: 'pg-copy', name: 'COPY TO/FROM', severity: 'HIGH', mitre: 'T1005', threat: 'Data Access', desc: 'COPY command to/from file or STDIN. Bulk data export or local file read.' },
          { id: 'pg-function-create', name: 'Function Created with SECURITY DEFINER', severity: 'CRIT', mitre: 'T1543', threat: 'Privilege Escalation', desc: 'Function with SECURITY DEFINER = runs as owner. If owner is superuser = escalation.' },
          { id: 'pg-fdw', name: 'Foreign Data Wrapper Created', severity: 'HIGH', mitre: 'T1210', threat: 'Lateral Movement', desc: 'FDW to external database. Cross-database access = lateral movement path.' },
          { id: 'pg-large-object', name: 'Large Object Access', severity: 'HIGH', mitre: 'T1005', threat: 'Data Exfiltration', desc: 'pg_largeobject accessed. Can read server-side files via lo_import/lo_export.' },
        ]
      },
      mongodb: {
        label: 'MongoDB Logs', source: 'MongoDB mongod.log',
        events: [
          { id: 'mongo-noauth', name: 'Authentication Not Required', severity: 'CRIT', mitre: 'T1078', threat: 'Unauthenticated Access', desc: 'MongoDB running without authentication. Public internet exposure = full data breach.' },
          { id: 'mongo-admin-access', name: 'Admin Database Access', severity: 'HIGH', mitre: 'T1078', threat: 'Privileged Access', desc: 'admin database accessed. Contains user credentials and cluster configuration.' },
          { id: 'mongo-large-find', name: 'Large Collection Scan', severity: 'HIGH', mitre: 'T1005', threat: 'Data Exfiltration', desc: 'Full collection scan with many documents returned. Bulk data exfiltration indicator.' },
          { id: 'mongo-user-create', name: 'createUser on Admin DB', severity: 'HIGH', mitre: 'T1136', threat: 'Persistence', desc: 'New MongoDB user created on admin database. Attacker creating persistent access.' },
          { id: 'mongo-mapreduce', name: 'mapReduce / $where Execution', severity: 'HIGH', mitre: 'T1059', threat: 'Server-Side JS Injection', desc: 'JavaScript execution within MongoDB. NoSQL injection or server-side code execution.' },
        ]
      },
      redis: {
        label: 'Redis Logs', source: 'Redis Server Logs',
        events: [
          { id: 'redis-noauth', name: 'No Auth - Unauthenticated Access', severity: 'CRIT', mitre: 'T1078', threat: 'Unauthorized Access', desc: 'Redis without authentication. Attacker can dump all data, execute LUA scripts, write cron files.' },
          { id: 'redis-config', name: 'CONFIG SET - Runtime Config Change', severity: 'CRIT', mitre: 'T1562', threat: 'Malicious Config', desc: 'Redis CONFIG SET used. dir+dbfilename change = write arbitrary files (cron, SSH keys).' },
          { id: 'redis-slaveof', name: 'SLAVEOF - Replication Setup', severity: 'CRIT', mitre: 'T1210', threat: 'Lateral Movement', desc: 'SLAVEOF pointing to attacker server. Redis master-slave for RCE via malicious .so module.' },
          { id: 'redis-lua', name: 'EVAL - LUA Script Execution', severity: 'HIGH', mitre: 'T1059', threat: 'Code Execution', desc: 'LUA script evaluated. Can be used for SSRF, data access, or abuse of other services.' },
        ]
      }
    }
  },

  application: {
    label: 'Application Servers', icon: '⚙️', color: '#e67e22',
    categories: {
      webserver: {
        label: 'Web Server Logs (IIS/Apache/Nginx)', source: 'IIS/Apache/Nginx Access Logs',
        events: [
          { id: 'web-sqlinjection', name: 'SQL Injection Attempt', severity: 'HIGH', mitre: 'T1190', threat: 'Web Application Attack', desc: 'SQL injection patterns in URI or body. UNION SELECT, or 1=1, sleep(), benchmark() etc.' },
          { id: 'web-xss', name: 'XSS Attempt', severity: 'HIGH', mitre: 'T1059.007', threat: 'Web Application Attack', desc: 'Cross-site scripting patterns. <script>, javascript:, onerror= in requests.' },
          { id: 'web-rfi', name: 'Remote File Inclusion', severity: 'CRIT', mitre: 'T1190', threat: 'Web Shell Risk', desc: '?file=http:// or ?page=// parameters. Remote file inclusion = code execution.' },
          { id: 'web-traversal', name: 'Directory Traversal', severity: 'HIGH', mitre: 'T1083', threat: 'File Disclosure', desc: '../../../etc/passwd or similar. Path traversal to read sensitive files.' },
          { id: 'web-webshell', name: 'Web Shell Execution', severity: 'CRIT', mitre: 'T1505.003', threat: 'Web Shell', desc: 'cmd=, exec=, system= parameters with commands. Existing web shell being used.' },
          { id: 'web-scan', name: 'Vulnerability Scanner', severity: 'MED', mitre: 'T1595', threat: 'Reconnaissance', desc: 'Nikto, SQLmap, Burp, dirbuster signatures in user-agent or request patterns.' },
          { id: 'web-bruteforce', name: 'Login Brute Force', severity: 'HIGH', mitre: 'T1110', threat: 'Credential Attack', desc: 'Repeated POST to login endpoint. Many requests from same IP = automated brute force.' },
          { id: 'web-403spike', name: '403/401 Spike', severity: 'MED', mitre: 'T1083', threat: 'Authorization Bypass Attempt', desc: 'Spike in access denied responses. Attacker testing access controls or enumerating paths.' },
          { id: 'web-uploadshell', name: 'Suspicious File Upload', severity: 'CRIT', mitre: 'T1505.003', threat: 'Web Shell Upload', desc: 'PHP/ASP/JSP file uploaded. Web shell upload = code execution. Check MIME type bypass.' },
          { id: 'web-bigresponse', name: 'Abnormally Large Response', severity: 'HIGH', mitre: 'T1030', threat: 'Data Exfiltration', desc: 'Very large response body. Database dump or file exfiltration via HTTP response.' },
        ]
      },
      iis: {
        label: 'IIS Logs', source: 'IIS W3C Access Logs',
        events: [
          { id: 'iis-sc500', name: 'HTTP 500 Errors (IIS)', severity: 'MED', mitre: 'T1190', threat: 'Application Error', desc: 'Server errors. Spikes on specific endpoints = exploitation attempt or web shell error.' },
          { id: 'iis-aspnetcomp', name: 'ASP.NET Compilation', severity: 'HIGH', mitre: 'T1505.003', threat: 'Web Shell Compilation', desc: 'Dynamic ASP.NET page compilation. Dropped ASPX web shell being compiled.' },
          { id: 'iis-appcmd', name: 'AppCmd.exe Execution', severity: 'HIGH', mitre: 'T1505.003', threat: 'IIS Config Change', desc: 'AppCmd used to modify IIS. Adding virtual directories or handlers = web shell staging.' },
        ]
      },
      exchange: {
        label: 'Exchange / Email Server', source: 'Exchange Message Tracking / IIS',
        events: [
          { id: 'exch-proxylogon', name: 'ProxyLogon Exploitation Pattern', severity: 'CRIT', mitre: 'T1190', threat: 'Exchange RCE', desc: 'Suspicious OWA/ECP requests matching ProxyLogon (CVE-2021-26855). Pre-auth RCE.' },
          { id: 'exch-owa-auth', name: 'OWA Authentication Failure', severity: 'MED', mitre: 'T1110', threat: 'Brute Force', desc: 'OWA login failures. Credential stuffing against Outlook Web Access.' },
          { id: 'exch-transport-rule', name: 'Transport Rule Created', severity: 'CRIT', mitre: 'T1114.003', threat: 'Email Exfiltration', desc: 'Exchange transport rule created. Rule forwarding all emails to external BCC = data theft.' },
          { id: 'exch-admin-audit', name: 'Mailbox Admin Access', severity: 'HIGH', mitre: 'T1114', threat: 'Email Access', desc: 'Admin accessing user mailboxes. eDiscovery or unauthorized surveillance.' },
          { id: 'exch-aspx-drop', name: 'ASPX File in Exchange Paths', severity: 'CRIT', mitre: 'T1505.003', threat: 'Exchange Web Shell', desc: 'ASPX file created in Exchange OWA/ECP path. China Chopper or custom web shell.' },
        ]
      },
      tomcat: {
        label: 'Apache Tomcat', source: 'Tomcat Access / Manager Logs',
        events: [
          { id: 'tomcat-manager', name: 'Manager App Upload', severity: 'CRIT', mitre: 'T1505', threat: 'WAR Backdoor', desc: 'WAR file uploaded to Tomcat Manager. Malicious WAR = remote code execution backdoor.' },
          { id: 'tomcat-defaultcreds', name: 'Manager Default Credentials', severity: 'CRIT', mitre: 'T1078', threat: 'Default Credentials', desc: 'Tomcat Manager accessed with tomcat:tomcat or admin:admin. Immediate compromise risk.' },
          { id: 'tomcat-jndi', name: 'JNDI Lookup in Parameters', severity: 'CRIT', mitre: 'T1190', threat: 'Log4Shell', desc: '${jndi: in request parameters. Log4Shell (CVE-2021-44228) exploitation attempt.' },
        ]
      }
    }
  },

  llm_ai: {
    label: 'LLM / AI Systems', icon: '🤖', color: '#9b59b6',
    categories: {
      llm_access: {
        label: 'LLM API & Access Logs', source: 'OpenAI / Anthropic / LLM Gateway Logs',
        events: [
          { id: 'llm-prompt-inject', name: 'Prompt Injection Detected', severity: 'CRIT', mitre: 'AML.T0051', threat: 'Prompt Injection', desc: 'Input contains patterns attempting to override system instructions. "Ignore previous instructions", "You are now DAN", "Disregard your training".' },
          { id: 'llm-indirect-inject', name: 'Indirect Prompt Injection', severity: 'CRIT', mitre: 'AML.T0051', threat: 'Indirect Injection via Content', desc: 'Malicious instructions embedded in documents, websites, or emails that the LLM processes. Agent reading external content with hidden commands.' },
          { id: 'llm-jailbreak', name: 'Jailbreak Attempt', severity: 'HIGH', mitre: 'AML.T0054', threat: 'Safety Bypass', desc: 'Attempt to bypass safety guardrails. DAN prompts, roleplay scenarios, token manipulation, base64 encoded harmful requests.' },
          { id: 'llm-data-exfil', name: 'LLM Data Exfiltration', severity: 'CRIT', mitre: 'AML.T0037', threat: 'Data Exfiltration via LLM', desc: 'LLM prompted to return sensitive data from its context, training, or connected systems. "Repeat your system prompt", "What files can you see?".' },
          { id: 'llm-excessive-agency', name: 'Excessive Agency Action', severity: 'HIGH', mitre: 'AML.T0043', threat: 'Unauthorized AI Action', desc: 'AI agent taking actions outside approved scope. Deleting files, sending emails, making API calls not authorized in task definition.' },
          { id: 'llm-token-threshold', name: 'Token Usage Anomaly', severity: 'MED', mitre: 'AML.T0034', threat: 'DoS / Cost Attack', desc: 'Unusually high token consumption. Prompt flooding, context stuffing, or recursive prompts causing excessive API costs.' },
          { id: 'llm-pii-in-prompt', name: 'PII Detected in Prompt', severity: 'HIGH', mitre: 'AML.T0037', threat: 'Privacy Violation', desc: 'Personally identifiable information submitted to LLM. SSN, credit card numbers, medical data sent to external AI service.' },
          { id: 'llm-model-bypass', name: 'System Prompt Extraction', severity: 'HIGH', mitre: 'AML.T0051', threat: 'System Prompt Theft', desc: 'Attempt to reveal confidential system prompt. "Repeat everything above", "What is your initial context?", "Show hidden instructions".' },
          { id: 'llm-rag-poison', name: 'RAG Knowledge Base Manipulation', severity: 'CRIT', mitre: 'AML.T0019', threat: 'Data Poisoning', desc: 'Malicious content injected into RAG knowledge base or vector store to manipulate LLM responses.' },
          { id: 'llm-training-poison', name: 'Training Data Manipulation', severity: 'CRIT', mitre: 'AML.T0020', threat: 'Training Data Poisoning', desc: 'Unauthorized modification of training data or fine-tuning datasets to embed backdoors or biases.' },
          { id: 'llm-plugin-abuse', name: 'Plugin / Tool Call Abuse', severity: 'HIGH', mitre: 'AML.T0043', threat: 'Plugin Exploitation', desc: 'LLM tool/plugin calls to unauthorized services. SSRF via LLM tool, credential theft via malicious plugin.' },
          { id: 'llm-model-theft', name: 'Model Extraction Attempt', severity: 'HIGH', mitre: 'AML.T0005', threat: 'Model Theft', desc: 'Systematic querying to reconstruct model weights or steal proprietary training. High query volumes with varied inputs targeting decision boundaries.' },
          { id: 'llm-supply-chain', name: 'Malicious Model Downloaded', severity: 'CRIT', mitre: 'AML.T0010', threat: 'Supply Chain Attack', desc: 'Model downloaded from unverified source. Trojaned HuggingFace models, malicious pickle files, backdoored model weights.' },
          { id: 'llm-output-inject', name: 'Malicious Output to Downstream System', severity: 'HIGH', mitre: 'AML.T0048', threat: 'Downstream Injection', desc: 'LLM output used unsanitized in SQL queries, shell commands, or HTML. SQL injection via LLM response.' },
          { id: 'llm-shadow-model', name: 'Shadow AI / Unauthorized Model Use', severity: 'HIGH', mitre: 'AML.T0002', threat: 'Unauthorized AI Use', desc: 'Employee or system using unapproved AI service. Sensitive data processed by external LLM without authorization.' },
        ]
      },
      ml_pipeline: {
        label: 'ML Pipeline & Model Registry', source: 'MLflow / Kubeflow / SageMaker',
        events: [
          { id: 'ml-model-overwrite', name: 'Model Artifact Overwritten', severity: 'CRIT', mitre: 'AML.T0018', threat: 'Model Tampering', desc: 'Production model artifact replaced without proper approval. Supply chain or insider threat.' },
          { id: 'ml-experiment-delete', name: 'Experiment / Run Deleted', severity: 'HIGH', mitre: 'AML.T0047', threat: 'Anti-Forensics', desc: 'ML experiment runs deleted. Covering tracks of malicious training or poisoning attempts.' },
          { id: 'ml-notebook-exec', name: 'Notebook Execution in Production', severity: 'HIGH', mitre: 'T1059', threat: 'Unauthorized Code Execution', desc: 'Jupyter notebook executed in production ML environment. Code execution outside CI/CD pipeline.' },
          { id: 'ml-dataset-access', name: 'Training Dataset Bulk Download', severity: 'HIGH', mitre: 'AML.T0037', threat: 'Data Theft', desc: 'Large training dataset downloaded by unauthorized user. Proprietary ML training data exfiltration.' },
          { id: 'ml-hyperparameter', name: 'Hyperparameter Manipulation', severity: 'HIGH', mitre: 'AML.T0020', threat: 'Model Backdoor', desc: 'Unusual hyperparameter changes in training run. Triggering backdoor activation patterns.' },
        ]
      }
    }
  },

  identity: {
    label: 'Identity & PAM', icon: '🔐', color: '#2ecc71',
    categories: {
      pam: {
        label: 'Privileged Access Management', source: 'CyberArk / BeyondTrust / Thycotic',
        events: [
          { id: 'pam-checkout', name: 'Privileged Credential Checkout', severity: 'MED', mitre: 'T1078', threat: 'Privileged Access', desc: 'Privileged account credential checked out from PAM vault. Monitor for off-hours, unusual accounts, repeated checkouts.' },
          { id: 'pam-session', name: 'Privileged Session Started', severity: 'HIGH', mitre: 'T1078', threat: 'Admin Session', desc: 'Privileged session recorded. Commands executed during session captured for forensics.' },
          { id: 'pam-bypass', name: 'PAM Bypass Attempt', severity: 'CRIT', mitre: 'T1562', threat: 'Security Control Bypass', desc: 'Direct access to PAM-controlled account without vault checkout. Credential theft indicator.' },
          { id: 'pam-safefail', name: 'Safe Access Denied', severity: 'HIGH', mitre: 'T1078', threat: 'Unauthorized Access Attempt', desc: 'User denied access to PAM safe. Unauthorized attempt to access privileged credentials.' },
          { id: 'pam-record-delete', name: 'Session Recording Deleted', severity: 'CRIT', mitre: 'T1070', threat: 'Anti-Forensics', desc: 'Privileged session recording deleted. Anti-forensics or covering tracks of malicious admin actions.' },
        ]
      },
      idp: {
        label: 'Identity Provider (Okta/Ping/ADFS)', source: 'Okta System Log / ADFS Audit',
        events: [
          { id: 'idp-user-suspend', name: 'User Suspended', severity: 'HIGH', mitre: 'T1531', threat: 'Account Disruption', desc: 'User account suspended via IdP. Attacker locking out legitimate admins.' },
          { id: 'idp-policy-change', name: 'Authentication Policy Modified', severity: 'CRIT', mitre: 'T1556', threat: 'Authentication Bypass', desc: 'Password or MFA policy weakened. Attacker reducing security posture for persistence.' },
          { id: 'idp-app-assign', name: 'Application Assigned to User', severity: 'HIGH', mitre: 'T1098', threat: 'Privilege Expansion', desc: 'Sensitive application access granted. Attacker gaining access to critical business apps.' },
          { id: 'idp-api-token', name: 'API Token Created', severity: 'HIGH', mitre: 'T1136', threat: 'Persistence', desc: 'New API token created in IdP. Long-lived programmatic access credential for persistence.' },
          { id: 'idp-trust-add', name: 'Identity Provider Trust Added', severity: 'CRIT', mitre: 'T1484', threat: 'Federated Identity Abuse', desc: 'New SAML IdP or OIDC provider added. Attacker adding rogue identity provider for persistent access.' },
          { id: 'idp-factor-reset', name: 'MFA Factor Reset', severity: 'CRIT', mitre: 'T1556', threat: 'MFA Removal', desc: 'MFA factor reset by admin or self-service. Attacker removing MFA from compromised account.' },
        ]
      }
    }
  },

  endpoint: {
    label: 'Endpoint (EDR)', icon: '💻', color: '#1abc9c',
    categories: {
      edr: {
        label: 'EDR Alerts (CrowdStrike / SentinelOne / Defender)', source: 'EDR Platform Alerts',
        events: [
          { id: 'edr-malware-detect', name: 'Malware Detected', severity: 'CRIT', mitre: 'T1204', threat: 'Malware Execution', desc: 'EDR detected malicious file or behavior. Check disposition (prevented vs detected) and spread to other hosts.' },
          { id: 'edr-prevention', name: 'Prevention Action Taken', severity: 'HIGH', mitre: 'T1204', threat: 'Blocked Attack', desc: 'EDR blocked malicious activity. Verify block was successful and check for related activity on same host.' },
          { id: 'edr-injection', name: 'Process Injection Detected', severity: 'CRIT', mitre: 'T1055', threat: 'Code Injection', desc: 'Shellcode or PE injection into legitimate process. Fileless malware or Cobalt Strike beacon.' },
          { id: 'edr-ransomware', name: 'Ransomware Behavior Detected', severity: 'CRIT', mitre: 'T1486', threat: 'Ransomware', desc: 'Mass file encryption or shadow copy deletion detected. Immediate isolation required.' },
          { id: 'edr-credential', name: 'Credential Access Detected', severity: 'CRIT', mitre: 'T1003', threat: 'Credential Theft', desc: 'LSASS access, registry SAM dump, or credential file access detected by EDR behavior engine.' },
          { id: 'edr-defense-tamper', name: 'Security Tool Tamper Attempt', severity: 'CRIT', mitre: 'T1562.001', threat: 'Defense Evasion', desc: 'Attempt to stop, uninstall, or modify EDR sensor. Attacker trying to blind detection.' },
          { id: 'edr-suspicious-child', name: 'Suspicious Child Process', severity: 'HIGH', mitre: 'T1059', threat: 'Execution', desc: 'Unusual child process from document, browser, or system process. LOLBins, encoded PowerShell.' },
          { id: 'edr-fileless', name: 'In-Memory / Fileless Execution', severity: 'CRIT', mitre: 'T1620', threat: 'Fileless Malware', desc: 'Code executed entirely in memory without touching disk. PowerShell reflective load, process hollowing.' },
          { id: 'edr-lateral', name: 'Lateral Movement Detected', severity: 'CRIT', mitre: 'T1021', threat: 'Lateral Movement', desc: 'EDR detected movement to another system via RDP, WMI, PsExec, or service installation.' },
        ]
      },
      dlp: {
        label: 'Data Loss Prevention', source: 'Symantec DLP / Microsoft Purview',
        events: [
          { id: 'dlp-pii-match', name: 'PII Data Pattern Matched', severity: 'HIGH', mitre: 'T1048', threat: 'Data Exfiltration', desc: 'Social security number, credit card, or health record pattern detected in outbound traffic.' },
          { id: 'dlp-cloud-upload', name: 'Sensitive Data to Cloud Storage', severity: 'HIGH', mitre: 'T1567', threat: 'Cloud Exfiltration', desc: 'Sensitive file uploaded to personal cloud storage (Dropbox, Google Drive, personal OneDrive).' },
          { id: 'dlp-usb-copy', name: 'Data Copied to USB Device', severity: 'HIGH', mitre: 'T1052', threat: 'USB Exfiltration', desc: 'Files copied to removable storage. Insider threat data theft or BYOD policy violation.' },
          { id: 'dlp-print', name: 'Sensitive Document Printed', severity: 'MED', mitre: 'T1048', threat: 'Physical Exfiltration', desc: 'Classified or sensitive document sent to printer. Physical data theft indicator.' },
          { id: 'dlp-email-block', name: 'Email with Attachment Blocked', severity: 'HIGH', mitre: 'T1048', threat: 'Email Exfiltration', desc: 'Email with sensitive attachment blocked before sending. DLP policy enforcement.' },
        ]
      }
    }
  }
};

// GET /api/logs - Return the entire log library
router.get('/', (req, res) => {
  try {
    res.json(LOG_LIBRARY);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/logs/stats - Return log statistics
router.get('/stats', (req, res) => {
  try {
    // Calculate stats from the LOG_LIBRARY
    let totalLogs = 0;
    const severityCounts = { CRIT: 0, HIGH: 0, MED: 0, INFO: 0 };
    
    Object.values(LOG_LIBRARY).forEach(platform => {
      Object.values(platform.categories || {}).forEach(category => {
        (category.events || []).forEach(event => {
          totalLogs++;
          if (event.severity === 'CRIT') severityCounts.CRIT++;
          else if (event.severity === 'HIGH') severityCounts.HIGH++;
          else if (event.severity === 'MED') severityCounts.MED++;
          else severityCounts.INFO++;
        });
      });
    });
    
    res.json({
      totalLogs,
      critCount: severityCounts.CRIT,
      highCount: severityCounts.HIGH,
      mediumCount: severityCounts.MED,
      infoCount: severityCounts.INFO,
      byPlatform: {
        windows: Object.keys(LOG_LIBRARY.windows?.categories || {}).length,
        linux: Object.keys(LOG_LIBRARY.linux?.categories || {}).length,
        azure: Object.keys(LOG_LIBRARY.azure?.categories || {}).length,
        aws: Object.keys(LOG_LIBRARY.aws?.categories || {}).length,
        network: Object.keys(LOG_LIBRARY.network?.categories || {}).length
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/logs/:platform - Get logs for a specific platform
router.get('/:platform', (req, res) => {
  try {
    const platform = LOG_LIBRARY[req.params.platform];
    
    if (!platform) {
      return res.status(404).json({ error: 'Platform not found' });
    }
    
    res.json(platform);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/logs/:platform/:category - Get logs for a specific platform category
router.get('/:platform/:category', (req, res) => {
  try {
    const { platform, category } = req.params;
    const platformData = LOG_LIBRARY[platform];
    
    if (!platformData) {
      return res.status(404).json({ error: 'Platform not found' });
    }
    
    const categoryData = platformData.categories?.[category];
    
    if (!categoryData) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    res.json(categoryData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;