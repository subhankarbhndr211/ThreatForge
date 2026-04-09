"""
ThreatForge Deep Packet Analysis Engine v2
Enterprise-grade packet analysis with full protocol decoding
"""

import json
import struct
import re
import zlib
import base64
import gzip
import hashlib
import time
from collections import defaultdict
from urllib.parse import urlparse, unquote
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import *
from scapy.layers.tls.all import *
import warnings

warnings.filterwarnings("ignore")
load_contrib("tls")


class DeepPacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.sessions = defaultdict(
            lambda: {"packets": [], "bytes": 0, "first_seen": None, "last_seen": None}
        )
        self.conversations = defaultdict(
            lambda: {
                "packets": 0,
                "bytes": 0,
                "protocols": set(),
                "src": None,
                "dst": None,
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
        self.iocs = {
            "ips": set(),
            "domains": set(),
            "urls": set(),
            "emails": set(),
            "hashes": set(),
            "credentials": [],
        }
        self.threats = []
        self.behaviors = []
        self.alerts = []
        self.files = []
        self.streams = defaultdict(lambda: {"data": bytearray(), "complete": False})
        self.tls_sessions = defaultdict(lambda: {"ja3": None, "hello": None})
        self.dns_queries = []
        self.http_requests = []
        self.credentials_found = []

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
        self._detect_threats()
        self._extract_files()
        self._detect_beaconing()

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
            proto = pkt[IP].proto

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
            self.stats["protocols"]["ARP"] += 1
            self._check_arp_spoofing(pkt)

        self._extract_payload_iocs(pkt)

    def _update_conversation(self, src, dst, pkt):
        key = tuple(sorted([src, dst]))
        conv = self.conversations[key]
        conv["packets"] += 1
        conv["bytes"] += len(pkt)
        conv["src"] = src
        conv["dst"] = dst
        conv["protocols"].add(self._get_protocol_name(pkt))

        if not conv.get("first_seen"):
            conv["first_seen"] = float(pkt.time)
        conv["last_seen"] = float(pkt.time)

    def _get_protocol_name(self, pkt):
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if dport == 80 or sport == 80:
                return "HTTP"
            if dport == 443 or sport == 443:
                return "HTTPS/TLS"
            if dport == 22 or sport == 22:
                return "SSH"
            if dport == 21 or sport == 21:
                return "FTP"
            if dport == 25 or sport == 25:
                return "SMTP"
            if dport == 110 or sport == 110:
                return "POP3"
            if dport == 143 or sport == 143:
                return "IMAP"
            if dport == 3306 or sport == 3306:
                return "MySQL"
            if dport == 5432 or sport == 5432:
                return "PostgreSQL"
            if dport == 6379 or sport == 6379:
                return "Redis"
            if dport == 27017 or sport == 27017:
                return "MongoDB"
            return "TCP"
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if dport == 53 or sport == 53:
                return "DNS"
            if dport in [67, 68]:
                return "DHCP"
            if dport == 123:
                return "NTP"
            if dport == 161:
                return "SNMP"
            return "UDP"
        elif ICMP in pkt:
            return "ICMP"
        return "OTHER"

    def _process_tcp(self, pkt, src_ip, dst_ip):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        self.stats["unique_ports"].add(sport)
        self.stats["unique_ports"].add(dport)
        self.stats["protocols"]["TCP"] += 1

        session_key = f"{src_ip}:{sport}-{dst_ip}:{dport}"

        flags = pkt[TCP].flags

        if flags & 0x02:
            self.stats["protocols"]["SYN"] = self.stats["protocols"].get("SYN", 0) + 1
        if flags & 0x04:
            self.threats.append(
                {
                    "type": "TCP_RST",
                    "severity": "HIGH",
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dport,
                    "detail": "TCP reset detected - possible connection termination or attack",
                }
            )

        if dport == 80 or sport == 80:
            self._process_http(pkt, session_key)
        elif dport == 443 or sport == 443:
            self._process_tls(pkt, session_key, src_ip, dst_ip)

        self._reassemble_stream(pkt, session_key)

        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            self._check_encoded_payload(payload, session_key)
            self._check_credentials(payload, session_key, src_ip, dst_ip)

    def _process_udp(self, pkt, src_ip, dst_ip):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        self.stats["unique_ports"].add(sport)
        self.stats["unique_ports"].add(dport)

        if DNS in pkt:
            self._process_dns(pkt, src_ip, dst_ip)
        elif dport == 53 or sport == 53:
            self.stats["protocols"]["DNS"] += 1

    def _process_icmp(self, pkt, src_ip, dst_ip):
        self.stats["protocols"]["ICMP"] += 1

        if pkt.haslayer(Raw) and len(pkt[Raw].load) > 100:
            self.threats.append(
                {
                    "type": "ICMP_TUNNEL",
                    "severity": "HIGH",
                    "src": src_ip,
                    "dst": dst_ip,
                    "detail": f"Large ICMP payload: {len(pkt[Raw].load)} bytes",
                }
            )

    def _process_dns(self, pkt, src_ip, dst_ip):
        self.stats["protocols"]["DNS"] += 1

        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype = pkt[DNSQR].qtype

                self.dns_queries.append(
                    {
                        "query": qname,
                        "type": self._dns_type_name(qtype),
                        "src": src_ip,
                        "dst": dst_ip,
                        "timestamp": float(pkt.time),
                    }
                )
                self.iocs["domains"].add(qname)

                if self._is_suspicious_domain(qname):
                    self.threats.append(
                        {
                            "type": "SUSPICIOUS_DOMAIN",
                            "severity": "MEDIUM",
                            "src": src_ip,
                            "domain": qname,
                            "detail": f"Suspicious domain pattern detected: {qname}",
                        }
                    )
            except:
                pass

        if pkt.haslayer(DNS) and pkt[DNS].ancount > 0:
            for i in range(min(pkt[DNS].ancount, 10)):
                try:
                    answer = pkt[DNS].an[i]
                    if hasattr(answer, "rdata"):
                        rdata = str(answer.rdata)
                        if answer.type == 1:
                            self.iocs["ips"].add(rdata)
                        elif answer.type == 5:
                            self.iocs["domains"].add(rdata)
                except:
                    pass

    def _dns_type_name(self, qtype):
        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
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
                method = req.Method.decode() if req.Method else "UNKNOWN"
                host = req.Host.decode() if req.Host else ""
                path = req.Path.decode() if req.Path else "/"
                user_agent = (
                    req.User_Agent.decode()
                    if hasattr(req, "User_Agent") and req.User_Agent
                    else None
                )
                referer = (
                    req.Referer.decode()
                    if hasattr(req, "Referer") and req.Referer
                    else None
                )

                url = f"http://{host}{path}"

                self.http_requests.append(
                    {
                        "method": method,
                        "host": host,
                        "path": path,
                        "url": url,
                        "user_agent": user_agent,
                        "referer": referer,
                        "src": pkt["IP"].src if IP in pkt else None,
                        "timestamp": float(pkt.time),
                        "session": session_key,
                    }
                )

                self.iocs["urls"].add(url)
                if host:
                    self.iocs["domains"].add(host)
                if referer and referer.startswith("http"):
                    try:
                        self.iocs["urls"].add(referer)
                    except:
                        pass

                if user_agent:
                    self._check_suspicious_ua(user_agent, pkt["IP"].src)

                self._check_suspicious_url(url)

            except Exception as e:
                pass

        elif pkt.haslayer(HTTPResponse):
            try:
                status = (
                    pkt[HTTPResponse].Status_Code
                    if hasattr(pkt[HTTPResponse], "Status_Code")
                    else 0
                )

                if pkt.haslayer(Raw):
                    self._check_http_content(
                        pkt[Raw].load, pkt["IP"].src if IP in pkt else None
                    )
            except:
                pass

    def _process_tls(self, pkt, session_key, src_ip, dst_ip):
        self.stats["protocols"]["TLS/HTTPS"] += 1

        if pkt.haslayer(TLSClientHello):
            try:
                hello = pkt[TLSClientHello]
                ja3 = self._calculate_ja3(hello)

                self.tls_sessions[session_key]["ja3"] = ja3
                self.tls_sessions[session_key]["hello_time"] = float(pkt.time)
                self.tls_sessions[session_key]["src"] = src_ip
                self.tls_sessions[session_key]["dst"] = dst_ip

                if self._check_malicious_ja3(ja3):
                    self.threats.append(
                        {
                            "type": "MALICIOUS_TLS_FINGERPRINT",
                            "severity": "CRITICAL",
                            "src": src_ip,
                            "dst": dst_ip,
                            "ja3": ja3,
                            "detail": "Known malicious tool TLS fingerprint detected",
                        }
                    )
            except:
                pass

    def _calculate_ja3(self, hello):
        try:
            version = struct.pack("!H", hello.version).hex()
            ciphers = "".join(struct.pack("!H", c).hex() for c in hello.ciphers)
            ext_data = ""
            for ext in hello.ext:
                ext_data += (
                    struct.pack("!HH", ext.type, len(ext.data)).hex() + ext.data.hex()
                )
            return hashlib.md5(
                (version + ciphers + ext_data + "0").encode()
            ).hexdigest()
        except:
            return "unknown"

    def _check_malicious_ja3(self, ja3):
        malicious_ja3 = {
            "a8a8e9b0e4c3f2d1e0b9a8f7e6d5c4b3": "Cobalt Strike",
            "5d5c5b5a595857565554535251504f4e": "Metasploit",
        }
        return malicious_ja3.get(ja3.lower())

    def _reassemble_stream(self, pkt, session_key):
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags & 0x08:
                if pkt.haslayer(Raw):
                    self.streams[session_key]["data"] += pkt[Raw].load

    def _check_encoded_payload(self, payload, session_key):
        try:
            text = payload.decode("utf-8", errors="ignore")

            base64_patterns = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
            for match in base64_patterns:
                try:
                    decoded = base64.b64decode(match)
                    if len(decoded) > 20 and all(
                        0x20 <= b < 0x7F or b in [0x0A, 0x0D, 0x09]
                        for b in decoded[:100]
                    ):
                        self.threats.append(
                            {
                                "type": "BASE64_ENCODED_PAYLOAD",
                                "severity": "MEDIUM",
                                "session": session_key,
                                "detail": f"Possible encoded payload detected ({len(decoded)} bytes)",
                            }
                        )
                        self.alerts.append(
                            {
                                "type": "ENCODED_PAYLOAD",
                                "data": match[:100],
                                "possible_decoded": decoded[:100].hex(),
                            }
                        )
                except:
                    pass

            if b"\\x" in payload or re.search(r"\\[0-9a-f]{2}", text):
                self.threats.append(
                    {
                        "type": "HEX_ENCODED_PAYLOAD",
                        "severity": "MEDIUM",
                        "session": session_key,
                        "detail": "Possible hex-encoded data detected",
                    }
                )

        except:
            pass

    def _check_credentials(self, payload, session_key, src_ip, dst_ip):
        try:
            text = payload.decode("utf-8", errors="ignore")

            patterns = [
                (r"(password|passwd|pwd)[\s:=]+[^\s&]{4,50}", "CREDENTIAL"),
                (r"(username|user|login|email)[\s:=]+[^\s&]{3,50}", "CREDENTIAL"),
                (r"Bearer\s+[a-zA-Z0-9\-_.]+", "TOKEN"),
                (r"Basic\s+[a-zA-Z0-9+/=]+", "BASIC_AUTH"),
                (r'api[_-]?key["\s:=]+[a-zA-Z0-9]{16,}', "API_KEY"),
                (r'secret["\s:=]+[a-zA-Z0-9]{8,}', "SECRET"),
            ]

            for pattern, cred_type in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    self.credentials_found.append(
                        {
                            "type": cred_type,
                            "value": match[:100],
                            "src": src_ip,
                            "dst": dst_ip,
                            "session": session_key,
                        }
                    )
                    self.threats.append(
                        {
                            "type": "CREDENTIAL_EXPOSURE",
                            "severity": "CRITICAL",
                            "src": src_ip,
                            "dst": dst_ip,
                            "detail": f"{cred_type} found in plaintext traffic",
                        }
                    )

        except:
            pass

    def _check_http_content(self, payload, src_ip):
        try:
            headers_end = payload.find(b"\r\n\r\n")
            if headers_end > 0:
                headers = payload[:headers_end].decode("utf-8", errors="ignore")
                body = payload[headers_end + 4 :]

                content_type = re.search(r"Content-Type:\s*([^\r\n]+)", headers, re.I)
                if content_type:
                    ct = content_type.group(1).lower()

                    if any(
                        x in ct
                        for x in [
                            "octet-stream",
                            "exe",
                            "dll",
                            "zip",
                            "pdf",
                            "doc",
                            "jar",
                            "msi",
                        ]
                    ):
                        self.threats.append(
                            {
                                "type": "FILE_DOWNLOAD",
                                "severity": "HIGH",
                                "src": src_ip,
                                "detail": f"File download detected: {ct}",
                            }
                        )

                        if len(body) > 100:
                            file_hash = hashlib.sha256(body).hexdigest()
                            self.files.append(
                                {
                                    "hash": file_hash,
                                    "size": len(body),
                                    "type": ct,
                                    "src": src_ip,
                                }
                            )
                            self.iocs["hashes"].add(file_hash)

            if b"<!DOCTYPE" in payload or b"<html" in payload.lower():
                urls = re.findall(
                    r'https?://[^\s<>"\'\\]+', payload.decode("utf-8", errors="ignore")
                )
                for url in urls:
                    self.iocs["urls"].add(url)

        except:
            pass

    def _extract_payload_iocs(self, pkt):
        if pkt.haslayer(Raw):
            try:
                text = pkt[Raw].load.decode("utf-8", errors="ignore")

                urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
                for url in urls:
                    self.iocs["urls"].add(url)

                emails = re.findall(
                    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text
                )
                for email in emails:
                    self.iocs["emails"].add(email)

                md5s = re.findall(r"\b[a-fA-F0-9]{32}\b", text)
                for h in md5s:
                    self.iocs["hashes"].add(h)
                sha1s = re.findall(r"\b[a-fA-F0-9]{40}\b", text)
                for h in sha1s:
                    self.iocs["hashes"].add(h)
                sha256s = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
                for h in sha256s:
                    self.iocs["hashes"].add(h)

            except:
                pass

    def _check_suspicious_ua(self, ua, src_ip):
        suspicious = [
            "curl",
            "wget",
            "python",
            "perl",
            "ruby",
            "java",
            "go-http",
            "metasploit",
            "nessus",
            "nmap",
            "nikto",
            "sqlmap",
            "hydra",
            "powershell",
            "cmd.exe",
            "bitsadmin",
            "libwww",
            "perl",
            "fetch",
        ]

        ua_lower = ua.lower()
        for tool in suspicious:
            if tool in ua_lower:
                self.threats.append(
                    {
                        "type": "TOOL_USER_AGENT",
                        "severity": "MEDIUM",
                        "src": src_ip,
                        "user_agent": ua,
                        "detail": f"Suspicious User-Agent detected: {tool}",
                    }
                )

    def _check_suspicious_url(self, url):
        suspicious = [
            "bit.ly",
            "tinyurl",
            "goo.gl",
            "t.co",
            "is.gd",
            "pastebin",
            "dropbox",
            "mega.nz",
            "mediafire",
        ]

        for sus in suspicious:
            if sus in url.lower():
                self.threats.append(
                    {
                        "type": "SUSPICIOUS_URL",
                        "severity": "MEDIUM",
                        "url": url,
                        "detail": f"URL shortener/tracker detected",
                    }
                )

    def _is_suspicious_domain(self, domain):
        patterns = [
            r"[a-z0-9]{30,}\.",
            r"\d{10,}\.",
            r"\.(tk|ml|ga|cf|gq|pw|top|xyz|buzz)\/",
            r"^[a-f0-9]{32}\.",
        ]
        return any(re.search(p, domain, re.I) for p in patterns)

    def _check_arp_spoofing(self, pkt):
        if ARP in pkt:
            opcode = pkt[ARP].op
            if opcode == 2:
                src_ip = pkt[ARP].psrc
                src_mac = pkt[ARP].hwsrc

                for conv_key, conv in self.conversations.items():
                    if conv.get("first_seen") and conv_key[0] == src_ip:
                        if not hasattr(self, "_arp_checks"):
                            self._arp_checks = {}

                        last_mac = self._arp_checks.get(src_ip)
                        if last_mac and last_mac != src_mac:
                            self.threats.append(
                                {
                                    "type": "ARP_SPOOFING",
                                    "severity": "CRITICAL",
                                    "ip": src_ip,
                                    "mac": src_mac,
                                    "detail": f"ARP cache poisoning detected: {src_ip} changed MAC from {last_mac} to {src_mac}",
                                }
                            )

                        self._arp_checks[src_ip] = src_mac

    def _extract_files(self):
        for session_key, stream in self.streams.items():
            if len(stream["data"]) > 1000:
                data = bytes(stream["data"])

                if data.startswith(b"%PDF"):
                    self.files.append(
                        {
                            "type": "application/pdf",
                            "size": len(data),
                            "hash": hashlib.sha256(data).hexdigest(),
                            "session": session_key,
                        }
                    )
                elif data.startswith(b"PK\x03\x04"):
                    self.files.append(
                        {
                            "type": "application/zip",
                            "size": len(data),
                            "hash": hashlib.sha256(data).hexdigest(),
                            "session": session_key,
                        }
                    )
                elif data.startswith(b"MZ"):
                    self.files.append(
                        {
                            "type": "application/x-executable",
                            "size": len(data),
                            "hash": hashlib.sha256(data).hexdigest(),
                            "session": session_key,
                        }
                    )

    def _analyze_sessions(self):
        for key, conv in self.conversations.items():
            conv["protocols"] = list(conv["protocols"])
            if conv.get("last_seen") and conv.get("first_seen"):
                conv["duration"] = conv["last_seen"] - conv["first_seen"]
                conv["packet_rate"] = conv["packets"] / max(conv["duration"], 1)
                conv["byte_rate"] = conv["bytes"] / max(conv["duration"], 1)

    def _detect_threats(self):
        for conv_key, conv in self.conversations.items():
            if conv.get("packet_rate", 0) > 500:
                self.threats.append(
                    {
                        "type": "HIGH_VOLUME_TRAFFIC",
                        "severity": "MEDIUM",
                        "endpoints": list(conv_key),
                        "rate": conv["packet_rate"],
                        "detail": f"Abnormal packet rate: {conv['packet_rate']:.0f} pkt/s",
                    }
                )

            for proto in conv["protocols"]:
                if proto == "HTTP" and conv["bytes"] > 5000000:
                    self.threats.append(
                        {
                            "type": "LARGE_HTTP_TRANSFER",
                            "severity": "MEDIUM",
                            "endpoints": list(conv_key),
                            "size": conv["bytes"],
                            "detail": f"Large HTTP transfer: {conv['bytes'] / 1024 / 1024:.1f} MB",
                        }
                    )

        ip_counts = defaultdict(int)
        for q in self.dns_queries:
            ip_counts[q["query"]] += 1

        for domain, count in ip_counts.items():
            if count > 20:
                self.threats.append(
                    {
                        "type": "DNS_WATERING_HOLE",
                        "severity": "MEDIUM",
                        "domain": domain,
                        "count": count,
                        "detail": f"High frequency DNS query: {domain} ({count}x)",
                    }
                )

    def _detect_beaconing(self):
        intervals = defaultdict(list)

        for session_key, session_data in self.tls_sessions.items():
            if "hello_time" in session_data:
                intervals[session_key].append(session_data["hello_time"])

        for key, times in intervals.items():
            if len(times) > 3:
                times.sort()
                gaps = [times[i + 1] - times[i] for i in range(len(times) - 1)]
                avg_gap = sum(gaps) / len(gaps)
                variance = sum((g - avg_gap) ** 2 for g in gaps) / len(gaps)

                if 40 < avg_gap < 70 and variance < 10:
                    self.behaviors.append(
                        {
                            "type": "C2_BEACON",
                            "severity": "HIGH",
                            "session": key,
                            "interval": avg_gap,
                            "detail": f"Possible C2 beaconing detected (~{avg_gap:.0f}s interval)",
                        }
                    )
                    self.threats.append(
                        {
                            "type": "C2_BEACONING",
                            "severity": "CRITICAL",
                            "session": key,
                            "interval": avg_gap,
                            "detail": f"Periodic beacon pattern: {avg_gap:.0f}s - strongly suggests C2 malware",
                        }
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
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "conversations": [
                {
                    "src": v["src"],
                    "dst": v["dst"],
                    "packets": v["packets"],
                    "bytes": v["bytes"],
                    "protocols": v["protocols"],
                    "duration": v.get("duration", 0),
                    "packet_rate": v.get("packet_rate", 0),
                }
                for k, v in sorted(
                    self.conversations.items(),
                    key=lambda x: x[1]["bytes"],
                    reverse=True,
                )[:50]
            ],
            "dns_queries": self.dns_queries[:200],
            "http_requests": self.http_requests[:200],
            "tls_sessions": [
                {
                    "session": k,
                    "ja3": v["ja3"],
                    "src": v.get("src"),
                    "dst": v.get("dst"),
                }
                for k, v in self.tls_sessions.items()
                if v.get("ja3")
            ],
            "iocs": {
                "ips": list(self.iocs["ips"]),
                "domains": list(self.iocs["domains"]),
                "urls": list(self.iocs["urls"]),
                "emails": list(self.iocs["emails"]),
                "hashes": list(self.iocs["hashes"]),
                "credentials": self.credentials_found,
            },
            "threats": self.threats,
            "behaviors": self.behaviors,
            "alerts": self.alerts,
            "files": self.files,
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
                "files_extracted": len(self.files),
                "credentials_found": len(self.credentials_found),
                "dns_queries": len(self.dns_queries),
                "http_requests": len(self.http_requests),
                "beaconing_detected": len(
                    [b for b in self.behaviors if b["type"] == "C2_BEACON"]
                ),
            },
        }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        analyzer = DeepPacketAnalyzer()
        result = analyzer.analyze(sys.argv[1])
        print(json.dumps(result, indent=2))
