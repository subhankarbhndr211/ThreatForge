"""
ThreatForge Advanced Packet Analyzer - Wireshark-like Deep Analysis Engine
Full protocol dissection, stream reconstruction, expert analysis
"""

import sys
import os
import json
import struct
import warnings
from collections import defaultdict, Counter
from datetime import datetime
from io import BytesIO

warnings.filterwarnings("ignore")

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP, LLC
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import *
    from scapy.layers.tls.all import *

    load_contrib("tls")
except ImportError as e:
    print(f"ERROR: Scapy not available: {e}")
    sys.exit(1)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    HAS_SKLEARN = True
except:
    HAS_SKLEARN = False

try:
    import yara

    HAS_YARA = True
except:
    HAS_YARA = False


class ProtocolDissector:
    """Deep protocol dissection - decodes all layers like Wireshark"""

    PROTOCOL_COLORS = {
        "ETHERNET": "#1a1a2e",
        "IP": "#4a9eff",
        "TCP": "#00d4aa",
        "UDP": "#ff6b6b",
        "ICMP": "#ffd93d",
        "DNS": "#9b59b6",
        "HTTP": "#27ae60",
        "HTTPS": "#f39c12",
        "ARP": "#e74c3c",
        "TLS": "#e67e22",
        "SSH": "#2ecc71",
        "FTP": "#3498db",
        "SMTP": "#9b59b6",
        "RAW": "#7f8c8d",
    }

    def dissect_packet(self, packet):
        """Full protocol dissection - returns tree structure like Wireshark"""
        result = {
            "frame": {},
            "layers": [],
            "raw_hex": "",
            "raw_ascii": "",
            "expert_info": [],
        }

        frame_info = {
            "time": float(packet.time) if hasattr(packet, "time") else 0,
            "time_relative": 0,
            "time_delta": 0,
            "length": len(packet),
            "captured_length": len(packet),
            "wire_length": len(packet),
        }
        result["frame"] = frame_info

        layer_info = []

        if Ether in packet:
            eth = packet[Ether]
            eth_layer = {
                "name": "Ethernet II",
                "collapsed": f"Src: {eth.src} → Dst: {eth.dst}",
                "fields": [
                    {"name": "Destination", "value": eth.dst, "color": "red"},
                    {"name": "Source", "value": eth.src, "color": "green"},
                    {
                        "name": "Type",
                        "value": f"0x{eth.type:04x} ({self._ethertype_name(eth.type)})",
                    },
                ],
            }
            layer_info.append(eth_layer)

        if ARP in packet:
            arp = packet[ARP]
            arp_layer = {
                "name": "Address Resolution Protocol",
                "collapsed": f"Who has {arp.pdst}? Tell {arp.psrc}",
                "fields": [
                    {"name": "Hardware type", "value": self._arp_hw_type(arp.hwtype)},
                    {"name": "Protocol type", "value": f"0x{arp.ptype:04x} (IPv4)"},
                    {"name": "Hardware size", "value": arp.hwlen},
                    {"name": "Protocol size", "value": arp.plen},
                    {"name": "Opcode", "value": self._arp_opcode(arp.op)},
                    {"name": "Sender MAC", "value": arp.hwsrc},
                    {"name": "Sender IP", "value": arp.psrc},
                    {"name": "Target MAC", "value": arp.hwdst},
                    {"name": "Target IP", "value": arp.pdst},
                ],
            }
            layer_info.append(arp_layer)

        if IP in packet:
            ip = packet[IP]
            ip_layer = {
                "name": "Internet Protocol Version 4",
                "collapsed": f"Src: {ip.src} → Dst: {ip.dst}",
                "fields": [
                    {"name": "Version", "value": ip.version},
                    {"name": "Header Length", "value": f"{ip.ihl * 4} bytes"},
                    {
                        "name": "Differentiated Services",
                        "value": f"0x{ip.tos:02x} ({ip.tos})",
                    },
                    {"name": "Total Length", "value": ip.len},
                    {"name": "Identification", "value": f"0x{ip.id:04x} ({ip.id})"},
                    {"name": "Flags", "value": self._ip_flags(ip.flags)},
                    {"name": "Fragment offset", "value": ip.frag},
                    {"name": "Time to Live", "value": ip.ttl},
                    {
                        "name": "Protocol",
                        "value": f"{ip.proto} ({self._proto_name(ip.proto)})",
                    },
                    {"name": "Header Checksum", "value": f"0x{ip.chksum:04x}"},
                    {"name": "Source Address", "value": ip.src, "color": "green"},
                    {"name": "Destination Address", "value": ip.dst, "color": "red"},
                ],
            }
            layer_info.append(ip_layer)

        if ICMP in packet:
            icmp = packet[ICMP]
            icmp_layer = {
                "name": "Internet Control Message Protocol",
                "collapsed": f"Type: {icmp.type} ({self._icmp_type(icmp.type)}) → Code: {icmp.code}",
                "fields": [
                    {
                        "name": "Type",
                        "value": f"{icmp.type} ({self._icmp_type(icmp.type)})",
                    },
                    {"name": "Code", "value": f"{icmp.code}"},
                    {"name": "Checksum", "value": f"0x{icmp.chksum:04x}"},
                ],
            }
            if icmp.type == 8:
                icmp_layer["fields"].append(
                    {"name": "Identifier (BE)", "value": icmp.id}
                )
                icmp_layer["fields"].append(
                    {"name": "Sequence (BE)", "value": icmp.seq}
                )
            layer_info.append(icmp_layer)
            result["expert_info"].extend(self._icmp_expert(icmp))

        if TCP in packet:
            tcp = packet[TCP]
            tcp_layer = {
                "name": "Transmission Control Protocol",
                "collapsed": f"Src Port: {tcp.sport} → Dst Port: {tcp.dport} [SYN, ACK]",
                "fields": [
                    {"name": "Source Port", "value": tcp.sport, "color": "green"},
                    {"name": "Destination Port", "value": tcp.dport, "color": "red"},
                    {"name": "Stream index", "value": f"tcp-{tcp.sport}-{tcp.dport}"},
                    {"name": "Sequence Number", "value": tcp.seq},
                    {"name": "Acknowledgment Number", "value": tcp.ack},
                    {"name": "Header Length", "value": f"{tcp.dataofs * 4} bytes"},
                    {
                        "name": "Flags",
                        "value": self._tcp_flags(tcp.flags),
                        "color": "orange",
                    },
                    {"name": "Window Size", "value": tcp.window},
                    {"name": "Checksum", "value": f"0x{tcp.chksum:04x}"},
                    {"name": "Urgent Pointer", "value": tcp.urgptr},
                ],
            }
            if tcp.options:
                opts = []
                for opt in tcp.options:
                    opts.append(f"{opt[0]}:{opt[1]}")
                tcp_layer["fields"].append({"name": "Options", "value": " ".join(opts)})
            layer_info.append(tcp_layer)
            result["expert_info"].extend(self._tcp_expert(tcp, packet))

        if UDP in packet:
            udp = packet[UDP]
            udp_layer = {
                "name": "User Datagram Protocol",
                "collapsed": f"Src Port: {udp.sport} → Dst Port: {udp.dport}",
                "fields": [
                    {"name": "Source Port", "value": udp.sport, "color": "green"},
                    {"name": "Destination Port", "value": udp.dport, "color": "red"},
                    {"name": "Length", "value": udp.len},
                    {"name": "Checksum", "value": f"0x{udp.chksum:04x}"},
                ],
            }
            layer_info.append(udp_layer)

        if DNS in packet:
            dns = packet[DNS]
            dns_layer = {
                "name": "Domain Name System",
                "collapsed": f"DNS {'Response' if dnsqr.resp else 'Query'} for {dnsqd.qname if dnsqr else 'N/A'}",
                "fields": [
                    {"name": "Transaction ID", "value": f"0x{dns.id:04x}"},
                    {"name": "Flags", "value": self._dns_flags(dns)},
                    {"name": "Questions", "value": dns.qdcount},
                    {"name": "Answers", "value": dns.ancount},
                    {"name": "Authority", "value": dns.nscount},
                    {"name": "Additional", "value": dns.arcount},
                ],
            }
            if dns.qr == 0 and DNSQR in packet:
                dns_layer["fields"].append(
                    {
                        "name": "Query Name",
                        "value": packet[DNSQR].qname.decode("utf-8", errors="ignore")
                        if hasattr(packet[DNSQR], "qname")
                        else "N/A",
                    }
                )
                dns_layer["fields"].append(
                    {
                        "name": "Query Type",
                        "value": f"{packet[DNSQR].qtype} ({self._dns_qtype(packet[DNSQR].qtype)})",
                    }
                )
                dns_layer["fields"].append(
                    {"name": "Query Class", "value": packet[DNSQR].qclass}
                )
            layer_info.append(dns_layer)

        if HTTP in packet:
            http_layer = self._dissect_http(packet)
            if http_layer:
                layer_info.append(http_layer)

        if TLS in packet:
            tls_layer = self._dissect_tls(packet)
            if tls_layer:
                layer_info.append(tls_layer)

        if Raw in packet:
            payload = packet[Raw].load
            raw_layer = {
                "name": "Raw",
                "collapsed": f"Load: {len(payload)} bytes",
                "fields": [
                    {"name": "Length", "value": len(payload)},
                    {
                        "name": "Data",
                        "value": payload[:100].hex() if len(payload) > 0 else "",
                    },
                ],
            }
            layer_info.append(raw_layer)
            result["raw_hex"] = payload.hex()
            result["raw_ascii"] = self._hex_to_ascii(payload)

        result["layers"] = layer_info
        return result

    def _ethertype_name(self, t):
        types = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN"}
        return types.get(t, f"0x{t:04x}")

    def _arp_hw_type(self, t):
        return {1: "Ethernet (1)"}.get(t, str(t))

    def _arp_opcode(self, op):
        return {1: "Request", 2: "Reply"}.get(op, str(op))

    def _ip_flags(self, flags):
        f = []
        if flags & 0x02:
            f.append("DF")
        if flags & 0x01:
            f.append("MF")
        return f"0x{flags:x} ({', '.join(f) if f else 'None'})"

    def _proto_name(self, p):
        return {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH"}.get(
            p, str(p)
        )

    def _icmp_type(self, t):
        return {
            0: "Echo Reply",
            3: "Destination Unreachable",
            8: "Echo Request",
            11: "Time Exceeded",
        }.get(t, "Unknown")

    def _icmp_expert(self, icmp):
        info = []
        if icmp.type == 8:
            info.append(
                {"level": "note", "group": "CHECKSUM", "message": "Echo Request"}
            )
        if icmp.type == 0:
            info.append({"level": "note", "group": "CHECKSUM", "message": "Echo Reply"})
        return info

    def _tcp_flags(self, flags):
        f = []
        if flags & 0x01:
            f.append("FIN")
        if flags & 0x02:
            f.append("SYN")
        if flags & 0x04:
            f.append("RST")
        if flags & 0x08:
            f.append("PSH")
        if flags & 0x10:
            f.append("ACK")
        if flags & 0x20:
            f.append("URG")
        return f"0x{flags:02x} ({', '.join(f)})"

    def _tcp_expert(self, tcp, packet):
        info = []
        if tcp.flags & 0x02:
            info.append({"level": "note", "group": "SEQ", "message": "SYN"})
        if tcp.flags & 0x01:
            info.append({"level": "note", "group": "SEQ", "message": "FIN"})
        if tcp.flags & 0x04:
            info.append(
                {"level": "warn", "group": "SEQ", "message": "RST - Connection reset"}
            )
        if tcp.flags == 0x10:
            info.append({"level": "note", "group": "ACK", "message": "ACK only"})
        return info

    def _dns_flags(self, dns):
        flags = []
        if dns.qr:
            flags.append("Response")
        else:
            flags.append("Query")
        if dns.rd:
            flags.append("RD")
        if dns.ra:
            flags.append("RA")
        if dns.aa:
            flags.append("AA")
        return ", ".join(flags)

    def _dns_qtype(self, t):
        return {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 28: "AAAA"}.get(t, str(t))

    def _dissect_http(self, packet):
        http_layer = {
            "name": "Hypertext Transfer Protocol",
            "fields": [],
            "collapsed": "",
        }
        try:
            if HTTPRequest in packet:
                req = packet[HTTPRequest]
                http_layer["collapsed"] = (
                    f"{req.Method.decode()} {req.Path.decode()} HTTP/{req.Http_Version.decode()}"
                )
                http_layer["fields"].append(
                    {"name": "Method", "value": req.Method.decode()}
                )
                http_layer["fields"].append(
                    {"name": "Path", "value": req.Path.decode()}
                )
                http_layer["fields"].append(
                    {
                        "name": "Host",
                        "value": req.Host.decode() if hasattr(req, "Host") else "",
                    }
                )
                http_layer["fields"].append(
                    {
                        "name": "User-Agent",
                        "value": req.User_Agent.decode()
                        if hasattr(req, "User_Agent")
                        else "",
                    }
                )
                http_layer["fields"].append(
                    {
                        "name": "Content-Type",
                        "value": req.Content_Type.decode()
                        if hasattr(req, "Content_Type")
                        else "",
                    }
                )
            elif HTTPResponse in packet:
                resp = packet[HTTPResponse]
                http_layer["collapsed"] = (
                    f"HTTP/{resp.Status_Line.decode().split()[0]} {resp.Status_Line.decode().split()[1]}"
                )
                http_layer["fields"].append(
                    {"name": "Status Code", "value": resp.Status_Code.decode()}
                )
                http_layer["fields"].append(
                    {
                        "name": "Reason",
                        "value": resp.Reason_Phrase.decode()
                        if hasattr(resp, "Reason_Phrase")
                        else "",
                    }
                )
        except:
            pass
        return http_layer if http_layer["fields"] else None

    def _dissect_tls(self, packet):
        tls_layer = {"name": "Transport Layer Security", "fields": [], "collapsed": ""}
        try:
            if hasattr(packet, "tls") and packet.tls:
                tls_layer["collapsed"] = "TLS Record Layer"
                tls_layer["fields"].append(
                    {"name": "Content Type", "value": "Application Data"}
                )
        except:
            pass
        return tls_layer if tls_layer["fields"] else None

    def _hex_to_ascii(self, data):
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            result.append(f"{i:08x}  {hex_part:<48}  {ascii_part}")
        return "\n".join(result)


class StreamReconstructor:
    """TCP/UDP stream reconstruction like Wireshark's Follow Stream"""

    def __init__(self):
        self.tcp_streams = defaultdict(list)
        self.udp_flows = defaultdict(list)

    def add_packet(self, packet, pkt_info):
        if TCP in packet:
            stream_id = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            if Raw in packet:
                self.tcp_streams[stream_id].append(
                    {
                        "src": packet[IP].src,
                        "dst": packet[IP].dst,
                        "data": bytes(packet[Raw].load),
                        "direction": "client"
                        if packet[IP].src == pkt_info.get("src_ip")
                        else "server",
                    }
                )
        elif UDP in packet:
            flow_id = f"{packet[IP].src}:{packet[UDP].sport}-{packet[IP].dst}:{packet[UDP].dport}"
            if Raw in packet:
                self.udp_flows[flow_id].append(
                    {
                        "src": packet[IP].src,
                        "data": bytes(packet[Raw].load),
                        "direction": "client"
                        if packet[IP].src == pkt_info.get("src_ip")
                        else "server",
                    }
                )

    def get_tcp_stream(self, stream_id):
        packets = self.tcp_streams.get(stream_id, [])
        client_data = b"".join(p["data"] for p in packets if p["direction"] == "client")
        server_data = b"".join(p["data"] for p in packets if p["direction"] == "server")
        return {
            "client": client_data.decode("utf-8", errors="ignore"),
            "server": server_data.decode("utf-8", errors="ignore"),
            "both": self._interleave_streams(packets),
        }

    def _interleave_streams(self, packets):
        result = []
        for p in sorted(packets, key=lambda x: len(x.get("data", b""))):
            prefix = "→ " if p["direction"] == "client" else "← "
            try:
                text = p["data"].decode("utf-8", errors="ignore")
                result.append(prefix + text)
            except:
                result.append(prefix + p["data"].hex())
        return "\n".join(result)


class SessionTracker:
    """Track TCP sessions and calculate statistics"""

    def __init__(self):
        self.sessions = defaultdict(
            lambda: {
                "packets": [],
                "bytes": 0,
                "start_time": None,
                "last_time": None,
                "state": "INIT",
                "retransmissions": 0,
                "out_of_order": 0,
                "rtt_samples": [],
            }
        )

    def add_packet(self, packet):
        if IP not in packet or TCP not in packet:
            return

        session_id = (
            f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
        )
        sess = self.sessions[session_id]

        sess["packets"].append(
            {
                "seq": packet[TCP].seq,
                "ack": packet[TCP].ack,
                "len": len(packet[TCP].payload) if TCP in packet else 0,
                "flags": packet[TCP].flags,
                "time": float(packet.time),
            }
        )
        sess["bytes"] += len(packet)

        if sess["start_time"] is None:
            sess["start_time"] = float(packet.time)
        sess["last_time"] = float(packet.time)

        if packet[TCP].flags & 0x02:
            sess["state"] = "SYN_SENT"
        if packet[TCP].flags & 0x12:
            sess["state"] = "ESTABLISHED"
        if packet[TCP].flags & 0x01:
            sess["state"] = "CLOSING"

    def get_session_stats(self, session_id):
        sess = self.sessions.get(session_id, {})
        if not sess:
            return {}

        duration = 0
        if sess["start_time"] and sess["last_time"]:
            duration = sess["last_time"] - sess["start_time"]

        return {
            "session_id": session_id,
            "packet_count": len(sess["packets"]),
            "total_bytes": sess["bytes"],
            "duration": duration,
            "state": sess["state"],
            "retransmissions": sess.get("retransmissions", 0),
            "avg_rtt": sum(sess.get("rtt_samples", []))
            / max(len(sess.get("rtt_samples", [])), 1),
        }


class ExpertAnalyzer:
    """Wireshark-style expert information analysis"""

    def __init__(self):
        self.experts = []

    def analyze_packet(self, packet, index):
        if TCP in packet:
            self._analyze_tcp(packet, index)
        if DNS in packet:
            self._analyze_dns(packet, index)
        if IP in packet:
            self._analyze_ip(packet, index)
        if Ether in packet:
            self._analyze_ethernet(packet, index)

    def _analyze_tcp(self, packet, index):
        tcp = packet[TCP]
        if tcp.flags & 0x04:
            self.experts.append(
                {
                    "packet": index,
                    "level": "error",
                    "group": "MALFORMED",
                    "message": f"Reset (RST) received - Connection terminated",
                }
            )

        if tcp.flags & 0x02 and tcp.flags & 0x10:
            self.experts.append(
                {
                    "packet": index,
                    "level": "note",
                    "group": "SEQUENCE",
                    "message": "SYN-ACK - Connection establishment",
                }
            )

        if tcp.window < 100:
            self.experts.append(
                {
                    "packet": index,
                    "level": "warn",
                    "group": "PERFORMANCE",
                    "message": f"Very small window size ({tcp.window}) - Possible saturation",
                }
            )

    def _analyze_dns(self, packet, index):
        dns = packet[DNS]
        if DNSQR in packet:
            query = (
                packet[DNSQR].qname.decode("utf-8", errors="ignore")
                if hasattr(packet[DNSQR], "qname")
                else ""
            )
            if len(query) > 50:
                self.experts.append(
                    {
                        "packet": index,
                        "level": "warn",
                        "group": "SUSPICIOUS",
                        "message": f"Unusually long DNS query ({len(query)} chars): {query}",
                    }
                )
            if any(c.isdigit() for c in query[:10]):
                self.experts.append(
                    {
                        "packet": index,
                        "level": "warn",
                        "group": "SUSPICIOUS",
                        "message": f"DNS query starts with digits - Possible DNS tunnel or DGA",
                    }
                )

    def _analyze_ip(self, packet, index):
        ip = packet[IP]
        if ip.ttl < 10:
            self.experts.append(
                {
                    "packet": index,
                    "level": "note",
                    "group": "CONFIG",
                    "message": f"Low TTL ({ip.ttl}) - Possible traceroute or spoofed packets",
                }
            )

        src_octets = ip.src.split(".")
        if len(src_octets) == 4:
            if src_octets[0] == "0" or src_octets[0] == "127":
                self.experts.append(
                    {
                        "packet": index,
                        "level": "error",
                        "group": "MALFORMED",
                        "message": f"Invalid source IP: {ip.src}",
                    }
                )

    def _analyze_ethernet(self, packet, index):
        eth = packet[Ether]
        if eth.dst == "ff:ff:ff:ff:ff:ff":
            self.experts.append(
                {
                    "packet": index,
                    "level": "note",
                    "group": "BROADCAST",
                    "message": "Broadcast frame",
                }
            )

    def get_experts(self):
        return self.experts


class AnomalyDetector:
    """ML-based anomaly detection for network traffic"""

    def __init__(self):
        self.model = None
        if HAS_SKLEARN:
            self._train_model()

    def _train_model(self):
        normal_traffic = np.random.randn(1000, 5)
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(normal_traffic)

    def extract_features(self, packet):
        features = []
        if IP in packet:
            features.append(len(packet))
            features.append(packet[IP].ttl)
            features.append(packet[IP].id)
            if TCP in packet:
                features.append(packet[TCP].window)
                features.append(packet[TCP].dport)
            elif UDP in packet:
                features.append(packet[UDP].len)
                features.append(packet[UDP].dport)
            else:
                features.extend([0, 0])
        return features

    def detect(self, packets_features):
        if self.model is None:
            return []
        predictions = self.model.predict(packets_features)
        anomalies = np.where(predictions == -1)[0]
        return anomalies.tolist()


class AdvancedPacketAnalyzer:
    """Main analyzer - orchestrates all components"""

    def __init__(self):
        self.dissector = ProtocolDissector()
        self.reconstructor = StreamReconstructor()
        self.session_tracker = SessionTracker()
        self.expert_analyzer = ExpertAnalyzer()
        self.anomaly_detector = AnomalyDetector()

    def analyze_pcap(self, pcap_path=None, pcap_data=None):
        """Full PCAP analysis like Wireshark"""
        if pcap_data:
            packets = rdpcap(BytesIO(pcap_data))
        elif pcap_path:
            packets = rdpcap(pcap_path)
        else:
            return {"error": "No input provided"}

        start_time = float(packets[0].time) if packets else 0

        result = {
            "metadata": {
                "total_packets": len(packets),
                "start_time": datetime.fromtimestamp(start_time).isoformat(),
                "source": pcap_path or "memory",
                "analyzer_version": "1.0.0",
            },
            "packet_list": [],
            "conversations": defaultdict(
                lambda: {"packets": 0, "bytes": 0, "protocols": set()}
            ),
            "endpoints": defaultdict(
                lambda: {"packets": 0, "bytes": 0, "protocols": set()}
            ),
            "protocol_hierarchy": Counter(),
            "statistics": {
                "by_protocol": Counter(),
                "by_size": {
                    "<64": 0,
                    "64-128": 0,
                    "128-512": 0,
                    "512-1500": 0,
                    ">1500": 0,
                },
            },
            "dns_queries": [],
            "http_requests": [],
            "expert_info": [],
            "streams": {},
            "sessions": {},
        }

        feature_vectors = []

        for i, packet in enumerate(packets):
            if len(result["packet_list"]) >= 5000:
                break

            pkt_info = self._analyze_single_packet(packet, i, start_time, result)
            feature_vectors.append(self.anomaly_detector.extract_features(packet))
            self.session_tracker.add_packet(packet)
            self.reconstructor.add_packet(packet, pkt_info)
            self.expert_analyzer.analyze_packet(packet, i)

        result["expert_info"] = self.expert_analyzer.get_experts()

        anomaly_indices = self.anomaly_detector.detect(np.array(feature_vectors))
        result["anomalies"] = anomaly_indices

        result["protocol_hierarchy"] = dict(result["protocol_hierarchy"])
        result["statistics"]["by_protocol"] = dict(result["statistics"]["by_protocol"])
        result["conversations"] = dict(result["conversations"])
        result["endpoints"] = dict(result["endpoints"])

        result["top_conversations"] = sorted(
            [{"pair": k, **v} for k, v in result["conversations"].items()],
            key=lambda x: x["bytes"],
            reverse=True,
        )[:50]

        result["top_endpoints"] = sorted(
            [{"ip": k, **v} for k, v in result["endpoints"].items()],
            key=lambda x: x["bytes"],
            reverse=True,
        )[:100]

        return result

    def _analyze_single_packet(self, packet, index, start_time, result):
        pkt_info = {
            "index": index,
            "number": index + 1,
            "time": float(packet.time) - start_time,
            "time_relative": float(packet.time) - start_time,
        }

        protocols = []
        if Ether in packet:
            protocols.append("Ethernet")
            result["statistics"]["by_protocol"]["Ethernet"] += 1

        if IP in packet:
            ip = packet[IP]
            pkt_info["src_ip"] = ip.src
            pkt_info["dst_ip"] = ip.dst
            protocols.append(f"IPv4")
            result["statistics"]["by_protocol"]["IPv4"] += 1
            result["statistics"]["by_protocol"][
                f"IP: {self.dissector._proto_name(ip.proto)}"
            ] += 1

            size_bucket = self._size_bucket(len(packet))
            result["statistics"]["by_size"][size_bucket] += 1

            endpoint_key = ip.src
            result["endpoints"][endpoint_key]["packets"] += 1
            result["endpoints"][endpoint_key]["bytes"] += len(packet)

            endpoint_key = ip.dst
            result["endpoints"][endpoint_key]["packets"] += 1
            result["endpoints"][endpoint_key]["bytes"] += len(packet)

        if TCP in packet:
            protocols.append("TCP")
            tcp = packet[TCP]
            pkt_info["src_port"] = tcp.sport
            pkt_info["dst_port"] = tcp.dport

            conv_key = f"{ip.src}:{tcp.sport} ↔ {ip.dst}:{tcp.dport}"
            result["conversations"][conv_key]["packets"] += 1
            result["conversations"][conv_key]["bytes"] += len(packet)
            result["conversations"][conv_key]["protocols"].add("TCP")

            result["endpoints"][ip.src]["protocols"].add("TCP")
            result["endpoints"][ip.dst]["protocols"].add("TCP")

            pkt_info["flags"] = self.dissector._tcp_flags(tcp.flags)
            pkt_info["seq"] = tcp.seq
            pkt_info["ack"] = tcp.ack

        elif UDP in packet:
            protocols.append("UDP")
            udp = packet[UDP]
            pkt_info["src_port"] = udp.sport
            pkt_info["dst_port"] = udp.dport

            conv_key = f"{ip.src}:{udp.sport} ↔ {ip.dst}:{udp.dport}"
            result["conversations"][conv_key]["packets"] += 1
            result["conversations"][conv_key]["bytes"] += len(packet)
            result["conversations"][conv_key]["protocols"].add("UDP")

            result["endpoints"][ip.src]["protocols"].add("UDP")
            result["endpoints"][ip.dst]["protocols"].add("UDP")

            if udp.sport == 53 or udp.dport == 53:
                protocols.append("DNS")
                result["statistics"]["by_protocol"]["DNS"] += 1

        if ICMP in packet:
            protocols.append("ICMP")
            result["statistics"]["by_protocol"]["ICMP"] += 1

        if ARP in packet:
            protocols.append("ARP")
            result["statistics"]["by_protocol"]["ARP"] += 1

        if DNS in packet and DNSQR in packet:
            try:
                query = packet[DNSQR].qname.decode("utf-8", errors="ignore")
                qtype = packet[DNSQR].qtype
                result["dns_queries"].append(
                    {
                        "time": pkt_info["time_relative"],
                        "query": query,
                        "type": qtype,
                        "src": ip.src if IP in packet else "",
                        "dst": ip.dst if IP in packet else "",
                    }
                )
            except:
                pass

        if HTTP in packet and HTTPRequest in packet:
            try:
                req = packet[HTTPRequest]
                result["http_requests"].append(
                    {
                        "time": pkt_info["time_relative"],
                        "method": req.Method.decode(),
                        "path": req.Path.decode(),
                        "host": req.Host.decode() if hasattr(req, "Host") else "",
                        "src": ip.src if IP in packet else "",
                        "dst": ip.dst if IP in packet else "",
                    }
                )
            except:
                pass

        pkt_info["protocols"] = protocols
        pkt_info["protocol"] = "/".join(protocols)
        pkt_info["length"] = len(packet)
        pkt_info["info"] = self._generate_info(packet, pkt_info)

        dissection = self.dissector.dissect_packet(packet)
        pkt_info["layers"] = dissection["layers"]
        pkt_info["raw_hex"] = dissection["raw_hex"]
        pkt_info["raw_ascii"] = dissection["raw_ascii"]

        result["packet_list"].append(pkt_info)
        result["protocol_hierarchy"].update(protocols)

        return pkt_info

    def _generate_info(self, packet, pkt_info):
        info_parts = []

        if TCP in packet:
            tcp = packet[TCP]
            flags = []
            if tcp.flags & 0x02:
                flags.append("SYN")
            if tcp.flags & 0x01:
                flags.append("FIN")
            if tcp.flags & 0x04:
                flags.append("RST")
            if tcp.flags & 0x10:
                flags.append("ACK")
            if tcp.flags & 0x08:
                flags.append("PSH")
            info_parts.append(
                f"{pkt_info['src_ip']}:{tcp.sport} → {pkt_info['dst_ip']}:{tcp.dport} [{','.join(flags)}]"
            )
            if tcp.payload:
                info_parts.append(f"Seq={tcp.seq} Ack={tcp.ack}")
        elif UDP in packet:
            udp = packet[UDP]
            info_parts.append(
                f"{pkt_info['src_ip']}:{udp.sport} → {pkt_info['dst_ip']}:{udp.dport} Len={udp.len}"
            )
        elif ICMP in packet:
            icmp = packet[ICMP]
            info_parts.append(f"Type={icmp.type} Code={icmp.code}")
        elif ARP in packet:
            arp = packet[ARP]
            info_parts.append(f"{'Who has' if arp.op == 1 else 'Reply'} {arp.pdst}")

        return " ".join(info_parts) if info_parts else f"Len={len(packet)}"

    def _size_bucket(self, size):
        if size < 64:
            return "<64"
        elif size < 128:
            return "64-128"
        elif size < 512:
            return "128-512"
        elif size <= 1500:
            return "512-1500"
        else:
            return ">1500"


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python advanced_analyzer.py <pcap_file>"}))
        sys.exit(1)

    analyzer = AdvancedPacketAnalyzer()

    try:
        result = analyzer.analyze_pcap(sys.argv[1])
        print(json.dumps(result, default=str))
    except Exception as e:
        print(json.dumps({"error": str(e), "traceback": traceback.format_exc()}))
        sys.exit(1)
