"""
ThreatForge Packet Analysis Engine - Core Module
Deep packet inspection with AI-powered threat detection
"""

import os
import json
import struct
import hashlib
import zlib
import base64
import re
from datetime import datetime
from collections import defaultdict
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import *
from scapy.layers.tls.all import *
import warnings

warnings.filterwarnings("ignore")

load_contrib("tls")


class PacketAnalysisEngine:
    def __init__(self):
        self.packets = []
        self.sessions = defaultdict(lambda: {"packets": [], "bytes": 0, "flows": set()})
        self.conversations = defaultdict(
            lambda: {
                "packets": 0,
                "bytes": 0,
                "protocols": set(),
                "first_seen": None,
                "last_seen": None,
            }
        )
        self.dns_queries = []
        self.http_requests = []
        self.tls_connections = []
        self.emails = []
        self.urls = []
        self.credentials = []
        self.files = []
        self.iocs = {"ips": set(), "domains": set(), "urls": set(), "hashes": set()}
        self.alerts = []
        self.ja3_signatures = {}
        self.statistics = {
            "total_packets": 0,
            "total_bytes": 0,
            "duration": 0,
            "protocols": defaultdict(int),
            "unique_ips": set(),
            "unique_ports": set(),
        }

    def analyze_pcap(self, pcap_path):
        start_time = time.time()
        try:
            pkts = rdpcap(pcap_path)
            self.statistics["total_packets"] = len(pkts)

            for pkt in pkts:
                self._process_packet(pkt)

            self._analyze_sessions()
            self._detect_threats()
            self._extract_iocs()

            self.statistics["duration"] = time.time() - start_time
            self.statistics["unique_ips"] = len(self.statistics["unique_ips"])
            self.statistics["unique_ports"] = len(self.statistics["unique_ports"])
            self.statistics["protocols"] = dict(self.statistics["protocols"])

            return self._generate_report()
        except Exception as e:
            return {"error": str(e)}

    def analyze_pcap_bytes(self, data):
        start_time = time.time()
        try:
            import tempfile

            with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
                f.write(data)
                temp_path = f.name

            result = self.analyze_pcap(temp_path)
            os.unlink(temp_path)
            return result
        except Exception as e:
            return {"error": str(e)}

    def _process_packet(self, pkt):
        ts = float(pkt.time)

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto

            self.statistics["unique_ips"].add(src_ip)
            self.statistics["unique_ips"].add(dst_ip)
            self.statistics["total_bytes"] += len(pkt)

            self._track_conversation(src_ip, dst_ip, pkt, ts)

            if TCP in pkt:
                self._process_tcp(pkt, src_ip, dst_ip, ts)
            elif UDP in pkt:
                self._process_udp(pkt, src_ip, dst_ip, ts)
            elif ICMP in pkt:
                self._process_icmp(pkt, src_ip, dst_ip, ts)

        self.statistics["total_packets"] += 1

    def _track_conversation(self, src, dst, pkt, ts):
        key = tuple(sorted([src, dst]))
        conv = self.conversations[key]
        conv["packets"] += 1
        conv["bytes"] += len(pkt)
        conv["protocols"].add(self._get_protocol_name(pkt))
        if not conv["first_seen"]:
            conv["first_seen"] = ts
        conv["last_seen"] = ts

    def _get_protocol_name(self, pkt):
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if dport == 80 or sport == 80:
                return "HTTP"
            if dport == 443 or sport == 443:
                return "HTTPS"
            if dport == 22 or sport == 22:
                return "SSH"
            if dport == 21 or sport == 21:
                return "FTP"
            if dport == 25 or sport == 25:
                return "SMTP"
            if dport == 53 or sport == 53:
                return "DNS"
            return f"TCP-{dport}"
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if dport == 53 or sport == 53:
                return "DNS"
            if dport == 67 or dport == 68:
                return "DHCP"
            return f"UDP-{dport}"
        elif ICMP in pkt:
            return "ICMP"
        return "OTHER"

    def _process_tcp(self, pkt, src_ip, dst_ip, ts):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        self.statistics["unique_ports"].add(sport)
        self.statistics["unique_ports"].add(dport)
        self.statistics["protocols"]["TCP"] += 1

        session_key = f"{src_ip}:{sport}-{dst_ip}:{dport}"

        if dport == 80 or sport == 80:
            self._process_http(pkt, session_key, ts)
        elif dport == 443 or sport == 443:
            self._process_tls(pkt, session_key, ts)

        if pkt.haslayer(Raw):
            self._extract_from_payload(pkt[Raw].load, dport, session_key)

    def _process_udp(self, pkt, src_ip, dst_ip, ts):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        self.statistics["unique_ports"].add(sport)
        self.statistics["unique_ports"].add(dport)

        if DNS in pkt:
            self._process_dns(pkt, ts)
        elif dport == 53 or sport == 53:
            self.statistics["protocols"]["DNS"] += 1

    def _process_icmp(self, pkt, src_ip, dst_ip, ts):
        self.statistics["protocols"]["ICMP"] += 1
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code

        if pkt.haslayer(Raw) and len(pkt[Raw].load) > 0:
            payload_size = len(pkt[Raw].load)
            if payload_size > 100:
                self.alerts.append(
                    {
                        "type": "ICMP_TUNNEL_SUSPECTED",
                        "severity": "HIGH",
                        "src": src_ip,
                        "dst": dst_ip,
                        "detail": f"Large ICMP payload: {payload_size} bytes",
                        "timestamp": ts,
                    }
                )

    def _process_dns(self, pkt, ts):
        self.statistics["protocols"]["DNS"] += 1

        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            qtype = pkt[DNSQR].qtype

            self.dns_queries.append(
                {
                    "query": qname,
                    "type": self._dns_type_name(qtype),
                    "timestamp": ts,
                    "src": pkt["IP"].src if IP in pkt else None,
                    "dst": pkt["IP"].dst if IP in pkt else None,
                }
            )
            self.iocs["domains"].add(qname)

        if pkt.haslayer(DNS) and pkt[DNS].ancount > 0:
            for i in range(pkt[DNS].ancount):
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
        }
        return types.get(qtype, f"TYPE{qtype}")

    def _process_http(self, pkt, session_key, ts):
        self.statistics["protocols"]["HTTP"] += 1

        if pkt.haslayer(HTTPRequest):
            try:
                http_layer = pkt[HTTPRequest]
                method = http_layer.Method.decode() if http_layer.Method else "UNKNOWN"
                host = http_layer.Host.decode() if http_layer.Host else ""
                path = http_layer.Path.decode() if http_layer.Path else "/"
                user_agent = (
                    http_layer.User_Agent.decode()
                    if hasattr(http_layer, "User_Agent") and http_layer.User_Agent
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
                        "src": pkt["IP"].src if IP in pkt else None,
                        "timestamp": ts,
                        "session": session_key,
                    }
                )

                self.urls.append({"url": url, "host": host, "ts": ts})
                self.iocs["urls"].add(url)
                self.iocs["domains"].add(host)

                if user_agent:
                    self._check_suspicious_ua(user_agent, pkt["IP"].src, ts)

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
                    self._check_http_payload(pkt[Raw].load, pkt["IP"].src, ts, status)
            except:
                pass

    def _process_tls(self, pkt, session_key, ts):
        self.statistics["protocols"]["HTTPS/TLS"] += 1

        if pkt.haslayer(TLSClientHello):
            try:
                hello = pkt[TLSClientHello]
                ja3 = self._calculate_ja3(hello)

                self.tls_connections.append(
                    {
                        "src": pkt["IP"].src,
                        "dst": pkt["IP"].dst,
                        "ja3": ja3,
                        "timestamp": ts,
                        "session": session_key,
                    }
                )

                self.ja3_signatures[ja3] = {
                    "count": self.ja3_signatures.get(ja3, {}).get("count", 0) + 1,
                    "first_seen": self.ja3_signatures.get(ja3, {}).get(
                        "first_seen", ts
                    ),
                }

            except:
                pass

    def _calculate_ja3(self, hello):
        try:
            version = struct.pack("!H", hello.version)
            cipher_suites = struct.pack("!H", len(hello.ciphers)) + b"".join(
                struct.pack("!H", c) for c in hello.ciphers
            )
            extensions_data = b""
            for ext in hello.ext:
                extensions_data += (
                    struct.pack("!HH", ext.type, len(ext.data)) + ext.data
                )

            ja3_string = (
                version.hex() + cipher_suites.hex() + extensions_data.hex() + "0"
            )
            return hashlib.md5(ja3_string.encode()).hexdigest()
        except:
            return "unknown"

    def _extract_from_payload(self, payload, port, session_key):
        if len(payload) < 4:
            return

        try:
            payload_str = payload.decode("utf-8", errors="ignore")

            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            found_urls = re.findall(url_pattern, payload_str)
            for url in found_urls:
                self.urls.append(
                    {
                        "url": url,
                        "host": url.split("/")[2] if "://" in url else "",
                        "inline": True,
                        "session": session_key,
                    }
                )
                self.iocs["urls"].add(url)

            email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
            found_emails = re.findall(email_pattern, payload_str)
            self.emails.extend(
                [{"email": e, "session": session_key} for e in found_emails]
            )

            cred_patterns = [
                r"(password|passwd|pwd)[\s:=]+[^\s&]{4,50}",
                r"(username|user|login)[\s:=]+[^\s&]{3,50}",
                r"Bearer\s+[a-zA-Z0-9\-_.]+",
                r"Basic\s+[a-zA-Z0-9+/=]+",
                r'api[_-]?key["\s:=]+[a-zA-Z0-9]{16,}',
            ]
            for pattern in cred_patterns:
                found = re.findall(pattern, payload_str, re.IGNORECASE)
                for cred in found:
                    self.credentials.append(
                        {
                            "type": "POTENTIAL_CREDENTIAL",
                            "value": cred[:100],
                            "session": session_key,
                        }
                    )
                    self.alerts.append(
                        {
                            "type": "CREDENTIAL_POTENTIAL",
                            "severity": "CRITICAL",
                            "detail": "Potential credential found in traffic",
                            "session": session_key,
                        }
                    )

            if port in [21, 22, 23, 3389]:
                self._check_telnet_ssh_creds(payload_str, session_key)

        except:
            pass

    def _check_telnet_ssh_creds(self, payload, session):
        patterns = [
            r"login:\s*(\S+)",
            r"username:\s*(\S+)",
            r"password:\s*(\S+)",
            r"user\s+(\S+)\s+pass\s+(\S+)",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            for m in matches:
                self.credentials.append(
                    {
                        "type": "AUTH_CREDENTIAL",
                        "value": str(m)[:100],
                        "session": session,
                    }
                )
                self.alerts.append(
                    {
                        "type": "CLEAR_TEXT_AUTH",
                        "severity": "HIGH",
                        "detail": "Authentication credential captured",
                        "session": session,
                    }
                )

    def _check_http_payload(self, payload, src_ip, ts, status):
        try:
            if b"Content-Disposition:" in payload or b"Content-Type:" in payload:
                content_type = re.search(b"Content-Type:\s*([^\r\n]+)", payload)
                if content_type:
                    ct = content_type.group(1).decode("utf-8", errors="ignore").lower()
                    if any(
                        x in ct
                        for x in [
                            "application/octet",
                            "exe",
                            "zip",
                            "pdf",
                            "doc",
                            "jar",
                        ]
                    ):
                        self.alerts.append(
                            {
                                "type": "FILE_DOWNLOAD",
                                "severity": "MEDIUM",
                                "src": src_ip,
                                "detail": f"File download detected: {ct}",
                                "timestamp": ts,
                            }
                        )
                        self._extract_file_from_http(payload, src_ip)

        except:
            pass

    def _extract_file_from_http(self, payload, src_ip):
        try:
            headers_end = payload.find(b"\r\n\r\n")
            if headers_end == -1:
                headers_end = payload.find(b"\n\n")
            if headers_end != -1:
                file_data = payload[
                    headers_end
                    + (4 if b"\r\n\r\n" in payload[: headers_end + 4] else 2) :
                ]
                if len(file_data) > 100:
                    file_hash = hashlib.sha256(file_data).hexdigest()
                    self.files.append(
                        {
                            "name": f"extracted_file_{file_hash[:8]}",
                            "size": len(file_data),
                            "hash": file_hash,
                            "src": src_ip,
                            "type": "HTTP_PAYLOAD",
                        }
                    )
                    self.iocs["hashes"].add(file_hash)
        except:
            pass

    def _check_suspicious_ua(self, ua, src_ip, ts):
        suspicious_uas = [
            r"curl|wget|python|perl|ruby|java|go\-http",
            r"metasploit|nessus|nmap|nikto|sqlmap|hydra",
            r"powershell|cmd\.exe|bitsadmin",
            r"libwww|perl|fetch|axios|node-fetch",
        ]
        for pattern in suspicious_uas:
            if re.search(pattern, ua, re.IGNORECASE):
                self.alerts.append(
                    {
                        "type": "TOOL_USER_AGENT",
                        "severity": "MEDIUM",
                        "src": src_ip,
                        "detail": f"Suspicious User-Agent: {ua}",
                        "timestamp": ts,
                    }
                )

    def _analyze_sessions(self):
        for key, conv in self.conversations.items():
            conv["protocols"] = list(conv["protocols"])
            if conv["last_seen"] and conv["first_seen"]:
                conv["duration"] = conv["last_seen"] - conv["first_seen"]
                conv["packet_rate"] = conv["packets"] / max(conv["duration"], 1)
                conv["byte_rate"] = conv["bytes"] / max(conv["duration"], 1)

    def _detect_threats(self):
        for key, conv in self.conversations.items():
            if conv["packet_rate"] > 100:
                self.alerts.append(
                    {
                        "type": "HIGH_PACKET_RATE",
                        "severity": "MEDIUM",
                        "detail": f"Abnormal packet rate: {conv['packet_rate']:.2f} pkt/s",
                        "endpoints": list(key),
                    }
                )

            if conv["duration"] > 0:
                interval = conv["duration"] / max(conv["packets"] - 1, 1)
                if 40 < interval < 70:
                    self.alerts.append(
                        {
                            "type": "C2_BEACON_SUSPECTED",
                            "severity": "HIGH",
                            "detail": f"Possible C2 beaconing pattern: ~{interval:.1f}s interval",
                            "endpoints": list(key),
                            "confidence": 0.75,
                        }
                    )
                elif 85 < interval < 115:
                    self.alerts.append(
                        {
                            "type": "C2_BEACON_SUSPECTED",
                            "severity": "HIGH",
                            "detail": f"Possible C2 beaconing pattern: ~{interval:.1f}s interval",
                            "endpoints": list(key),
                            "confidence": 0.85,
                        }
                    )

            for proto in conv["protocols"]:
                if proto == "HTTP" and conv["bytes"] > 1000000:
                    self.alerts.append(
                        {
                            "type": "LARGE_HTTP_TRANSFER",
                            "severity": "MEDIUM",
                            "detail": f"Large HTTP transfer: {conv['bytes'] / 1024 / 1024:.2f} MB",
                            "endpoints": list(key),
                        }
                    )

        for domain in self.iocs["domains"]:
            if self._is_suspicious_domain(domain):
                self.alerts.append(
                    {
                        "type": "SUSPICIOUS_DOMAIN",
                        "severity": "HIGH",
                        "detail": f"Suspicious domain pattern: {domain}",
                    }
                )

    def _is_suspicious_domain(self, domain):
        suspicious_patterns = [
            r"[a-z0-9]{30,}\.",
            r"\d{10,}\.",
            r"[a-z0-9]{2,}\.[a-z0-9]{2,}\.[a-z0-9]{2,}\.[a-z0-9]{2,}",
            r"\.(tk|ml|ga|cf|gq)\/",
            r"bitly|tinyurl|t\.co|goo\.gl",
        ]
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return True
        return False

    def _extract_iocs(self):
        self.iocs = {
            "ips": list(self.iocs["ips"]),
            "domains": list(self.iocs["domains"]),
            "urls": list(self.iocs["urls"]),
            "hashes": list(self.iocs["hashes"]),
            "emails": self.emails,
            "credentials": self.credentials,
        }

    def _generate_report(self):
        return {
            "statistics": self.statistics,
            "conversations": {str(k): v for k, v in self.conversations.items()},
            "dns_queries": self.dns_queries[:200],
            "http_requests": self.http_requests[:200],
            "tls_connections": self.tls_connections[:200],
            "urls": self.urls[:200],
            "emails": self.emails[:50],
            "credentials": self.credentials,
            "files": self.files,
            "ja3_signatures": self.ja3_signatures,
            "iocs": self.iocs,
            "alerts": self.alerts,
            "summary": {
                "total_packets": self.statistics["total_packets"],
                "unique_ips": self.statistics["unique_ips"],
                "unique_ports": self.statistics["unique_ports"],
                "total_dns_queries": len(self.dns_queries),
                "total_http_requests": len(self.http_requests),
                "total_tls_connections": len(self.tls_connections),
                "total_alerts": len(self.alerts),
                "critical_alerts": len(
                    [a for a in self.alerts if a.get("severity") == "CRITICAL"]
                ),
                "high_alerts": len(
                    [a for a in self.alerts if a.get("severity") == "HIGH"]
                ),
                "iocs_count": sum(
                    len(v) if isinstance(v, list) else len(str(v))
                    for v in self.iocs.values()
                ),
            },
        }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        engine = PacketAnalysisEngine()
        result = engine.analyze_pcap(sys.argv[1])
        print(json.dumps(result, indent=2))
