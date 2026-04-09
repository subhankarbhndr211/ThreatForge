"""
ThreatForge Advanced Packet Analysis Engine v3
Enhanced with ML models, YARA rules, entropy analysis, and advanced detection
"""

import os
import sys
import json
import math
import struct
import hashlib
import zlib
import base64
import gzip
import re
import time
import pickle
import warnings
from datetime import datetime
from collections import defaultdict, Counter
from io import BytesIO

import numpy as np
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import *
from scapy.layers.tls.all import *

warnings.filterwarnings("ignore")
load_contrib("tls")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class EntropyAnalyzer:
    @staticmethod
    def calculate_entropy(data):
        if not data:
            return 0
        entropy = 0
        byte_counts = Counter(data)
        data_len = len(data)
        for count in byte_counts.values():
            p = count / data_len
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def detect_high_entropy(data, threshold=7.0):
        entropy = EntropyAnalyzer.calculate_entropy(data)
        return {
            "entropy": entropy,
            "high_entropy": entropy > threshold,
            "likely_encrypted": entropy > 7.5,
            "likely_compressed": 6.5 < entropy < 7.5,
            "likely_plaintext": entropy < 6.5,
        }


class FileCarver:
    SIGNATURES = {
        b"%PDF": ("pdf", "Adobe PDF"),
        b"PK\x03\x04": ("zip", "ZIP Archive"),
        b"MZ": ("exe", "Windows Executable"),
        b"\x89PNG": ("png", "PNG Image"),
        b"\xff\xd8\xff": ("jpg", "JPEG Image"),
        b"GIF87a": ("gif", "GIF Image"),
        b"GIF89a": ("gif", "GIF Image"),
        b"Rar!": ("rar", "RAR Archive"),
        b"\x1f\x8b": ("gz", "GZIP Archive"),
        b"BM": ("bmp", "Bitmap Image"),
        b"\x00\x00\x01\x00": ("ico", "Icon File"),
        b"PK\x05\x06": ("zip_end", "ZIP End Marker"),
        b"\x7fELF": ("elf", "ELF Executable"),
        b"\xca\xfe\xba\xbe": ("macho", "Mach-O Binary"),
        b"dex\n": ("dex", "Android DEX"),
        b"OTTO": ("apk", "Android APK"),
        b"\xfe\xed\xfa\xce": ("macho32", "Mach-O 32-bit"),
        b"\xfe\xed\xfa\xcf": ("macho64", "Mach-O 64-bit"),
        b"#!": ("script", "Script File"),
        b"#!/": ("script", "Shebang Script"),
    }

    @staticmethod
    def detect_filetype(data):
        if not data or len(data) < 4:
            return None
        for signature, (ftype, fdesc) in FileCarver.SIGNATURES.items():
            if data.startswith(signature):
                return {
                    "type": ftype,
                    "description": fdesc,
                    "signature": signature.hex(),
                }
        return None

    @staticmethod
    def carve_files(data, min_size=100, max_size=104857600):
        files = []
        for signature, (ftype, fdesc) in FileCarver.SIGNATURES.items():
            offset = 0
            while True:
                pos = data.find(signature, offset)
                if pos == -1:
                    break
                chunk = data[pos : pos + max_size]
                file_hash = hashlib.sha256(chunk).hexdigest()
                entropy = EntropyAnalyzer.calculate_entropy(chunk)
                files.append(
                    {
                        "offset": pos,
                        "type": ftype,
                        "description": fdesc,
                        "size": len(chunk),
                        "hash": file_hash,
                        "entropy": entropy,
                        "sha256": file_hash,
                        "md5": hashlib.md5(chunk).hexdigest(),
                    }
                )
                offset = pos + 1
        return files


class YARAScanner:
    def __init__(self):
        self.rules = {}
        self.compiled = None
        if YARA_AVAILABLE:
            self._load_builtin_rules()

    def _load_builtin_rules(self):
        self.rules = {
            "generic_malware": """
                rule generic_malware {
                    strings:
                        $a = "CreateRemoteThread" fullword
                        $b = "VirtualAlloc" fullword
                        $c = "WinExec" fullword
                        $d = "ShellExecute" fullword
                        $e = /powershell.*-enc/i
                        $f = /Invoke-Expression/i
                    condition:
                        2 of them
                }
            """,
            "packed_binary": """
                rule packed_binary {
                    strings:
                        $a = "UPX0" fullword
                        $b = "UPX1" fullword
                        $c = ".aspack" fullword
                        $d = ".petite" fullword
                    condition:
                        any of them
                }
            """,
            "network_recon": """
                rule network_recon {
                    strings:
                        $a = "nmap" nocase
                        $b = "masscan" nocase
                        $c = "scanner" nocase
                        $d = "portscan" nocase
                    condition:
                        any of them
                }
            """,
            "credential_theft": """
                rule credential_theft {
                    strings:
                        $a = "mimikatz" nocase
                        $b = "lsass" fullword
                        $c = "samdump" nocase
                        $d = /WDigest/ fullword
                    condition:
                        any of them
                }
            """,
            "cobalt_strike": """
                rule cobalt_strike {
                    strings:
                        $a = "cobaltstrike" nocase
                        $b = "beacon.dll" nocase
                        $c = "x86" base64
                        $d = "META-INF" fullword
                    condition:
                        2 of them
                }
            """,
            "reverse_shell": """
                rule reverse_shell {
                    strings:
                        $a = "/bin/sh -i" nocase
                        $b = "cmd.exe /c" nocase
                        $c = /nc -e/i
                        $d = /bash -i/i
                    condition:
                        any of them
                }
            """,
        }
        try:
            self.compiled = yara.compile(sources=self.rules)
        except:
            pass

    def scan(self, data):
        results = []
        if not YARA_AVAILABLE or not self.compiled:
            return results
        try:
            matches = self.compiled.match(data=data)
            for match in matches:
                results.append(
                    {
                        "rule": match.rule,
                        "tags": list(match.tags),
                        "matches": [
                            {"offset": m.offset, "data": m.matched_data.hex()}
                            for m in match.strings
                        ],
                    }
                )
        except:
            pass
        return results


class MLThreatDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler() if ML_AVAILABLE else None
        self.trained = False
        self._init_model()

    def _init_model(self):
        if ML_AVAILABLE:
            self.model = IsolationForest(
                contamination=0.1, n_estimators=100, max_samples="auto", random_state=42
            )
            self._generate_synthetic_training_data()

    def _generate_synthetic_training_data(self):
        np.random.seed(42)
        normal_traffic = np.random.normal(
            [50, 1000, 5, 0.5], [10, 200, 2, 0.2], (500, 4)
        )
        try:
            self.model.fit(normal_traffic)
            self.trained = True
        except:
            self.trained = False

    def extract_features(self, conversation):
        features = [
            conversation.get("packet_rate", 0),
            conversation.get("byte_rate", 0),
            conversation.get("duration", 0),
            conversation.get("packet_count", 0)
            / max(conversation.get("duration", 1), 1),
        ]
        return np.array(features).reshape(1, -1)

    def detect_anomaly(self, conversation):
        if not self.trained or not ML_AVAILABLE:
            return {"anomaly": False, "score": 0, "confidence": 0}

        features = self.extract_features(conversation)
        try:
            if self.scaler:
                features = self.scaler.transform(features)
            score = self.model.score_samples(features)[0]
            anomaly = score < -0.5
            confidence = abs(score) / 2
            return {
                "anomaly": anomaly,
                "score": float(score),
                "confidence": float(min(confidence, 1.0)),
                "interpretation": "Highly anomalous"
                if anomaly
                else "Normal traffic pattern",
            }
        except:
            return {"anomaly": False, "score": 0, "confidence": 0}


class BeaconingDetector:
    def __init__(self):
        self.interval_patterns = defaultdict(list)

    def analyze_timing(self, timestamps, threshold=0.15):
        if len(timestamps) < 4:
            return {"beaconing": False, "confidence": 0}

        timestamps = sorted(timestamps)
        intervals = [
            timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
        ]

        if not intervals:
            return {"beaconing": False, "confidence": 0}

        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)

        cv = std_interval / mean_interval if mean_interval > 0 else 1

        is_periodic = cv < threshold

        common_intervals = Counter([round(i, 1) for i in intervals])
        most_common = common_intervals.most_common(1)[0]

        beacon_types = {
            (40, 70): "C2 Beacon (45-60s)",
            (85, 115): "C2 Beacon (90-110s)",
            (20, 30): "C2 Beacon (20-30s)",
            (110, 130): "C2 Beacon (120s)",
        }

        detected_type = None
        for (low, high), desc in beacon_types.items():
            if low <= mean_interval <= high:
                detected_type = desc
                break

        confidence = (1 - cv) * (len(intervals) / 20) if cv < 1 else 0
        confidence = min(confidence, 1.0)

        return {
            "beaconing": is_periodic and confidence > 0.5,
            "mean_interval": float(mean_interval),
            "std_interval": float(std_interval),
            "coefficient_of_variation": float(cv),
            "confidence": float(confidence),
            "beacon_type": detected_type,
            "interval_distribution": dict(common_intervals),
        }


class DNSExfiltrationDetector:
    def __init__(self):
        self.suspicious_tlds = {
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq",
            ".pw",
            ".top",
            ".xyz",
            ".buzz",
        }
        self.dga_patterns = re.compile(r"^[a-f0-9]{8,}\.")

    def analyze_dns(self, queries):
        results = []
        query_counts = Counter([q["query"] for q in queries])
        subdomain_analysis = []

        for domain, count in query_counts.items():
            parts = domain.split(".")
            if len(parts) > 3:
                subdomain_analysis.append(
                    {
                        "domain": domain,
                        "subdomain_depth": len(parts) - 2,
                        "query_count": count,
                    }
                )

            is_suspicious = False
            reasons = []

            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                is_suspicious = True
                reasons.append("Suspicious TLD")

            if self.dga_patterns.match(domain):
                is_suspicious = True
                reasons.append("DGA-like pattern")

            if count > 50:
                is_suspicious = True
                reasons.append("High query frequency")

            if is_suspicious:
                results.append(
                    {"domain": domain, "query_count": count, "reasons": reasons}
                )

        high_frequency = [d for d in subdomain_analysis if d["query_count"] > 30]

        return {
            "suspicious_queries": results,
            "high_frequency_domains": high_frequency,
            "total_unique_domains": len(query_counts),
        }


class PortScanDetector:
    def __init__(self):
        self.connection_attempts = defaultdict(list)

    def analyze(self, packets, threshold=15):
        for pkt in packets:
            if TCP in pkt:
                key = pkt[IP].src if IP in pkt else None
                port = pkt[TCP].dport
                self.connection_attempts[key].append(
                    {
                        "port": port,
                        "timestamp": float(pkt.time),
                        "flags": str(pkt[TCP].flags),
                    }
                )

        results = []
        for src, attempts in self.connection_attempts.items():
            attempts.sort(key=lambda x: x["timestamp"])
            ports_scanned = set(a["port"] for a in attempts)

            syn_only = all(a["flags"] == "S" for a in attempts[:10])

            if len(ports_scanned) >= threshold and syn_only:
                results.append(
                    {
                        "source_ip": src,
                        "ports_scanned": len(ports_scanned),
                        "port_list": sorted(list(ports_scanned))[:20],
                        "scan_type": "SYN" if syn_only else "TCP",
                        "severity": "HIGH" if len(ports_scanned) > 50 else "MEDIUM",
                    }
                )

        return results


class AdvancedPacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.conversations = defaultdict(
            lambda: {
                "packets": [],
                "bytes": 0,
                "first_seen": None,
                "last_seen": None,
                "protocols": set(),
                "timestamps": [],
                "ports": set(),
            }
        )
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "duration": 0,
            "protocols": defaultdict(int),
            "unique_ips": set(),
            "unique_ports": set(),
        }
        self.iocs = {"ips": set(), "domains": set(), "urls": set(), "hashes": set()}
        self.threats = []
        self.alerts = []
        self.files = []
        self.tls_sessions = {}
        self.dns_queries = []
        self.http_requests = []
        self.mitre_tactics = []

        self.entropy_analyzer = EntropyAnalyzer()
        self.file_carver = FileCarver()
        self.yara_scanner = YARAScanner()
        self.ml_detector = MLThreatDetector()
        self.beaconing_detector = BeaconingDetector()
        self.dns_exfil_detector = DNSExfiltrationDetector()
        self.portscan_detector = PortScanDetector()

    def analyze(self, pcap_path=None, buffer=None):
        start = time.time()

        if buffer:
            import tempfile

            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
                f.write(buffer)
                pcap_path = f.name

        pkts = rdpcap(pcap_path) if pcap_path else []

        for pkt in pkts:
            self._process_packet(pkt)

        self._analyze_sessions()
        self._detect_all_threats()
        self._extract_artifacts()
        self._map_mitre_attack()

        self.stats["duration"] = time.time() - start
        self.stats["unique_ips"] = len(self.stats["unique_ips"])
        self.stats["unique_ports"] = len(self.stats["unique_ports"])
        self.stats["protocols"] = dict(self.stats["protocols"])

        return self._generate_report()

    def _process_packet(self, pkt):
        self.stats["total_packets"] += 1
        self.stats["total_bytes"] += len(pkt)

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            self.stats["unique_ips"].add(src_ip)
            self.stats["unique_ips"].add(dst_ip)
            self._update_conversation(src_ip, dst_ip, pkt)

            if TCP in pkt:
                self._process_tcp(pkt, src_ip, dst_ip)
            elif UDP in pkt:
                self._process_udp(pkt, src_ip, dst_ip)
            elif ICMP in pkt:
                self._process_icmp(pkt, src_ip, dst_ip)

        elif ARP in pkt:
            self._process_arp(pkt)

        self._extract_payload_data(pkt)

    def _update_conversation(self, src, dst, pkt):
        key = tuple(sorted([src, dst]))
        conv = self.conversations[key]
        conv["packets"].append(pkt)
        conv["bytes"] += len(pkt)
        conv["protocols"].add(self._get_protocol_name(pkt))
        if TCP in pkt:
            conv["ports"].add(pkt[TCP].dport)
        if not conv.get("first_seen"):
            conv["first_seen"] = float(pkt.time)
        conv["last_seen"] = float(pkt.time)
        conv["timestamps"].append(float(pkt.time))
        conv["packet_count"] = len(conv["packets"])

    def _get_protocol_name(self, pkt):
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            services = {
                80: "HTTP",
                443: "HTTPS",
                22: "SSH",
                21: "FTP",
                25: "SMTP",
                53: "DNS",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                27017: "MongoDB",
                3389: "RDP",
                445: "SMB",
                25: "SMTP",
                110: "POP3",
                143: "IMAP",
            }
            return services.get(dport, f"TCP-{dport}")
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            services = {53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP"}
            return services.get(dport, f"UDP-{dport}")
        elif ICMP in pkt:
            return "ICMP"
        return "OTHER"

    def _process_tcp(self, pkt, src_ip, dst_ip):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        self.stats["unique_ports"].add(sport)
        self.stats["unique_ports"].add(dport)
        self.stats["protocols"]["TCP"] += 1

        flags = pkt[TCP].flags
        if flags & 0x02:
            self.stats["protocols"]["SYN"] = self.stats["protocols"].get("SYN", 0) + 1
        if flags & 0x04:
            self._add_threat("TCP_RST", "MEDIUM", src_ip, dst_ip, "TCP reset detected")

        session_key = f"{src_ip}:{sport}-{dst_ip}:{dport}"

        if dport == 80 or sport == 80:
            self._process_http(pkt, session_key)
        elif dport == 443 or sport == 443:
            self._process_tls(pkt, session_key, src_ip, dst_ip)

        if pkt.haslayer(Raw):
            self._analyze_payload(pkt[Raw].load, session_key, src_ip, dst_ip)

    def _process_udp(self, pkt, src_ip, dst_ip):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        self.stats["unique_ports"].add(sport)
        self.stats["unique_ports"].add(dport)

        if DNS in pkt:
            self._process_dns(pkt, src_ip, dst_ip)

    def _process_icmp(self, pkt, src_ip, dst_ip):
        self.stats["protocols"]["ICMP"] += 1
        if pkt.haslayer(Raw) and len(pkt[Raw].load) > 64:
            entropy_result = self.entropy_analyzer.detect_high_entropy(pkt[Raw].load)
            if entropy_result["high_entropy"]:
                self._add_threat(
                    "ICMP_TUNNEL",
                    "HIGH",
                    src_ip,
                    dst_ip,
                    f"High entropy ICMP payload: {entropy_result['entropy']:.2f}",
                )

    def _process_dns(self, pkt, src_ip, dst_ip):
        self.stats["protocols"]["DNS"] += 1
        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                self.dns_queries.append(
                    {
                        "query": qname,
                        "type": self._dns_type_name(pkt[DNSQR].qtype),
                        "src": src_ip,
                        "dst": dst_ip,
                        "timestamp": float(pkt.time),
                    }
                )
                self.iocs["domains"].add(qname)

                if self._is_suspicious_domain(qname):
                    self._add_threat(
                        "SUSPICIOUS_DNS",
                        "HIGH",
                        src_ip,
                        dst_ip,
                        f"Suspicious domain: {qname}",
                    )
            except:
                pass

    def _dns_type_name(self, qtype):
        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
        }
        return types.get(qtype, f"TYPE{qtype}")

    def _process_http(self, pkt, session_key):
        self.stats["protocols"]["HTTP"] += 1
        if pkt.haslayer(HTTPRequest):
            try:
                req = pkt[HTTPRequest]
                self.http_requests.append(
                    {
                        "method": req.Method.decode() if req.Method else "UNKNOWN",
                        "host": req.Host.decode() if req.Host else "",
                        "path": req.Path.decode() if req.Path else "/",
                        "url": f"http://{req.Host.decode()}{req.Path.decode() if req.Path else ''}",
                        "user_agent": req.User_Agent.decode()
                        if hasattr(req, "User_Agent") and req.User_Agent
                        else None,
                        "src": pkt["IP"].src if IP in pkt else None,
                        "timestamp": float(pkt.time),
                    }
                )
            except:
                pass

    def _process_tls(self, pkt, session_key, src_ip, dst_ip):
        self.stats["protocols"]["TLS"] += 1
        if pkt.haslayer(TLSClientHello):
            try:
                hello = pkt[TLSClientHello]
                ja3 = self._calculate_ja3(hello)
                self.tls_sessions[session_key] = {
                    "ja3": ja3,
                    "src": src_ip,
                    "dst": dst_ip,
                    "timestamp": float(pkt.time),
                }
                if self._check_malicious_ja3(ja3):
                    self._add_threat(
                        "MALICIOUS_JA3",
                        "CRITICAL",
                        src_ip,
                        dst_ip,
                        f"Known malicious JA3: {ja3}",
                    )
            except:
                pass

    def _calculate_ja3(self, hello):
        try:
            version = struct.pack("!H", hello.version).hex()
            ciphers = "".join(struct.pack("!H", c).hex() for c in hello.ciphers)
            ext_data = "".join(
                struct.pack("!HH", ext.type, len(ext.data)).hex() + ext.data.hex()
                for ext in hello.ext
            )
            return hashlib.md5(
                (version + ciphers + ext_data + "0").encode()
            ).hexdigest()
        except:
            return "unknown"

    def _check_malicious_ja3(self, ja3):
        malicious_ja3s = {
            "a8a8e9b0e4c3f2d1e0b9a8f7e6d5c4b3": "Cobalt Strike",
            "5d5c5b5a595857565554535251504f4e": "Metasploit",
            "151acc0e2a54c4a7b27d3c9b0e6f9d8c": "Cobalt Strike Beacon",
        }
        return malicious_ja3s.get(ja3.lower())

    def _process_arp(self, pkt):
        self.stats["protocols"]["ARP"] += 1
        if ARP in pkt and pkt[ARP].op == 2:
            pass

    def _extract_payload_data(self, pkt):
        if not pkt.haslayer(Raw):
            return
        try:
            data = pkt[Raw].load
            if len(data) < 10:
                return

            entropy = self.entropy_analyzer.calculate_entropy(data)
            self._check_encoded_data(data, entropy)

            urls = re.findall(
                r'https?://[^\s<>"{}|\\^`\[\]]+', data.decode("utf-8", errors="ignore")
            )
            for url in urls:
                self.iocs["urls"].add(url)

            hashes = re.findall(
                r"\b[a-fA-F0-9]{32}\b", data.decode("utf-8", errors="ignore")
            )
            for h in hashes:
                self.iocs["hashes"].add(h)

            filetype = self.file_carver.detect_filetype(data[:16])
            if filetype:
                self.files.append(
                    {
                        "type": filetype["type"],
                        "description": filetype["description"],
                        "entropy": entropy,
                    }
                )

        except:
            pass

    def _analyze_payload(self, payload, session_key, src_ip, dst_ip):
        entropy_result = self.entropy_analyzer.detect_high_entropy(payload)

        if entropy_result["high_entropy"]:
            yara_results = self.yara_scanner.scan(bytes(payload[:1024]))
            if yara_results:
                for result in yara_results:
                    self._add_threat(
                        "YARA_MATCH",
                        "HIGH",
                        src_ip,
                        dst_ip,
                        f"YARA rule '{result['rule']}' matched",
                    )

        self._check_credentials(payload, session_key, src_ip, dst_ip)

        base64_matches = re.findall(
            r"[A-Za-z0-9+/]{40,}={0,2}", payload.decode("utf-8", errors="ignore")
        )
        for match in base64_matches:
            try:
                decoded = base64.b64decode(match)
                if len(decoded) > 20:
                    self.alerts.append(
                        {
                            "type": "BASE64_PAYLOAD",
                            "data": match[:50],
                            "decoded_entropy": self.entropy_analyzer.calculate_entropy(
                                decoded
                            ),
                        }
                    )
            except:
                pass

    def _check_credentials(self, payload, session_key, src_ip, dst_ip):
        try:
            text = payload.decode("utf-8", errors="ignore")
            patterns = [
                (r"(?i)(password|passwd|pwd)[\s:=]+[^\s&]{4,50}", "CREDENTIAL"),
                (r"(?i)(username|user|login)[\s:=]+[^\s&]{3,50}", "CREDENTIAL"),
                (r"Bearer\s+[a-zA-Z0-9\-_.~]+", "TOKEN"),
                (r"Basic\s+[a-zA-Z0-9+/=]+", "BASIC_AUTH"),
            ]
            for pattern, cred_type in patterns:
                if re.search(pattern, text):
                    self._add_threat(
                        "CREDENTIAL_EXPOSURE",
                        "CRITICAL",
                        src_ip,
                        dst_ip,
                        f"{cred_type} in plaintext traffic",
                    )
        except:
            pass

    def _check_encoded_data(self, data, entropy):
        if entropy > 7.0:
            self.alerts.append(
                {
                    "type": "HIGH_ENTROPY_PAYLOAD",
                    "entropy": entropy,
                    "size": len(data),
                    "likely": "encrypted or compressed",
                }
            )

    def _is_suspicious_domain(self, domain):
        patterns = [
            r"[a-z0-9]{30,}\.",
            r"\d{10,}\.",
            r"\.(tk|ml|ga|cf|gq|pw)\/",
            r"^[a-f0-9]{32}\.",
        ]
        return any(re.search(p, domain, re.I) for p in patterns)

    def _analyze_sessions(self):
        for key, conv in self.conversations.items():
            conv["protocols"] = list(conv["protocols"])
            if conv.get("last_seen") and conv.get("first_seen"):
                conv["duration"] = conv["last_seen"] - conv["first_seen"]
                conv["packet_rate"] = conv["packet_count"] / max(conv["duration"], 1)
                conv["byte_rate"] = conv["bytes"] / max(conv["duration"], 1)

    def _detect_all_threats(self):
        for conv_key, conv in self.conversations.items():
            ml_result = self.ml_detector.detect_anomaly(
                {
                    "packet_rate": conv.get("packet_rate", 0),
                    "byte_rate": conv.get("byte_rate", 0),
                    "duration": conv.get("duration", 0),
                    "packet_count": conv.get("packet_count", 0),
                }
            )
            if ml_result.get("anomaly"):
                self._add_threat(
                    "ML_ANOMALY",
                    "HIGH",
                    conv_key[0],
                    conv_key[1],
                    f"ML detected anomaly: {ml_result['interpretation']}",
                )

        beacon_result = self.beaconing_detector.analyze_timing(
            [
                t
                for conv in self.conversations.values()
                for t in conv.get("timestamps", [])[:100]
            ]
        )
        if beacon_result.get("beaconing"):
            self._add_threat(
                "C2_BEACONING",
                "CRITICAL",
                None,
                None,
                f"Periodic beacon detected: {beacon_result.get('beacon_type', 'Unknown')}",
            )

        dns_result = self.dns_exfil_detector.analyze_dns(self.dns_queries)
        for sus in dns_result.get("suspicious_queries", []):
            self._add_threat(
                "DNS_EXFILTRATION",
                "HIGH",
                None,
                None,
                f"Possible DNS exfil: {sus['domain']}",
            )

        portscan_results = self.portscan_detector.analyze(
            [p for conv in self.conversations.values() for p in conv.get("packets", [])]
        )
        for scan in portscan_results:
            self._add_threat(
                "PORT_SCAN",
                scan.get("severity", "MEDIUM"),
                scan["source_ip"],
                None,
                f"Port scan detected: {scan['ports_scanned']} ports",
            )

    def _extract_artifacts(self):
        for conv_key, conv in self.conversations.items():
            for pkt in conv.get("packets", []):
                if pkt.haslayer(Raw):
                    data = bytes(pkt[Raw].load)
                    carved = self.file_carver.carve_files(data)
                    self.files.extend(carved)

    def _map_mitre_attack(self):
        mitre_map = {
            "MALICIOUS_JA3": [("T1573", "Encrypted Channel")],
            "C2_BEACONING": [
                ("T1071", "Application Layer Protocol"),
                ("T1071.001", "Web Protocols"),
            ],
            "CREDENTIAL_EXPOSURE": [
                ("T1040", "Network Sniffing"),
                ("T1552", "Unsecured Credentials"),
            ],
            "ICMP_TUNNEL": [("T1095", "Non-Standard Protocol")],
            "DNS_EXFILTRATION": [("T1048", "Exfiltration Over Alternative Protocol")],
            "PORT_SCAN": [("T1046", "Network Service Discovery")],
            "SUSPICIOUS_DNS": [("T1071", "Application Layer Protocol")],
            "YARA_MATCH": [("T1059", "Command and Scripting Interpreter")],
            "BASE64_PAYLOAD": [("T1027", "Obfuscated Files or Information")],
            "ML_ANOMALY": [("T0968", "Standard Cryptographic Protocol")],
            "TCP_RST": [("T0831", "Network Traffic Denial")],
            "HIGH_ENTROPY_PAYLOAD": [("T1027", "Obfuscated Files or Information")],
        }

        for threat in self.threats:
            threat_type = threat.get("type")
            if threat_type in mitre_map:
                for mitre_id, mitre_name in mitre_map[threat_type]:
                    self.mitre_tactics.append(
                        {
                            "threat_type": threat_type,
                            "mitre_id": mitre_id,
                            "mitre_name": mitre_name,
                            "severity": threat.get("severity"),
                            "source": threat.get("src"),
                            "destination": threat.get("dst"),
                        }
                    )

    def _add_threat(self, threat_type, severity, src, dst, detail):
        self.threats.append(
            {
                "type": threat_type,
                "severity": severity,
                "src": src,
                "dst": dst,
                "detail": detail,
                "timestamp": datetime.now().isoformat(),
            }
        )
        if severity in ["CRITICAL", "HIGH"]:
            self.alerts.append(
                {"type": threat_type, "severity": severity, "detail": detail}
            )

    def _generate_report(self):
        return {
            "metadata": {
                "total_packets": self.stats["total_packets"],
                "total_bytes": self.stats["total_bytes"],
                "duration": self.stats.get("duration", 0),
                "unique_ips": self.stats["unique_ips"],
                "unique_ports": self.stats["unique_ports"],
                "protocols": self.stats["protocols"],
                "timestamp": datetime.now().isoformat(),
                "engine_version": "3.0.0",
            },
            "conversations": [
                {
                    "src": k[0],
                    "dst": k[1],
                    "packets": v.get("packet_count", 0),
                    "bytes": v["bytes"],
                    "protocols": v["protocols"],
                    "duration": v.get("duration", 0),
                    "packet_rate": v.get("packet_rate", 0),
                    "byte_rate": v.get("byte_rate", 0),
                    "ports": list(v.get("ports", set())),
                }
                for k, v in sorted(
                    self.conversations.items(),
                    key=lambda x: x[1]["bytes"],
                    reverse=True,
                )[:50]
            ],
            "dns_queries": self.dns_queries[:200],
            "http_requests": self.http_requests[:200],
            "tls_sessions": list(self.tls_sessions.values()),
            "iocs": {
                "ips": list(self.iocs["ips"]),
                "domains": list(self.iocs["domains"]),
                "urls": list(self.iocs["urls"]),
                "hashes": list(self.iocs["hashes"]),
            },
            "threats": self.threats,
            "alerts": self.alerts,
            "files": self.files,
            "mitre_tactics": self.mitre_tactics,
            "summary": {
                "total_threats": len(self.threats),
                "critical_threats": len(
                    [t for t in self.threats if t["severity"] == "CRITICAL"]
                ),
                "high_threats": len(
                    [t for t in self.threats if t["severity"] == "HIGH"]
                ),
                "medium_threats": len(
                    [t for t in self.threats if t["severity"] == "MEDIUM"]
                ),
                "files_detected": len(self.files),
                "dns_queries": len(self.dns_queries),
                "http_requests": len(self.http_requests),
                "tls_connections": len(self.tls_sessions),
            },
            "ml_available": ML_AVAILABLE,
            "yara_available": YARA_AVAILABLE,
        }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        analyzer = AdvancedPacketAnalyzer()
        result = analyzer.analyze(sys.argv[1])
        print(json.dumps(result, indent=2))
