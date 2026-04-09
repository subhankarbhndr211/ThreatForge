"""
ThreatForge Ultra Live Monitor v2.0
====================================
Real-time packet capture with Ultra engine threat streaming.

Emits newline-delimited JSON snapshots to stdout every second.
Each snapshot is consumed by the Node.js live capture bridge.

New in v2:
  - Integrates UltraPacketAnalyzer sub-engines per packet
  - Streams THREAT events immediately (not just stats)
  - JA3 fingerprinting on live TLS hellos
  - DNS DGA / tunnel detection in real-time
  - Port scan detection with sliding window
  - Beaconing detection on accumulated timestamps
  - OS fingerprint on first SYN from each IP
  - All events tagged with MITRE ATT&CK IDs
"""

import json
import time
import sys
import os
import threading
import math
import hashlib
import re
from collections import defaultdict, Counter
from datetime import datetime

# ── scapy ────────────────────────────────────────────────────────────────────
try:
    from scapy.all import AsyncSniffer, get_if_list, get_if_addr
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP
    from scapy.layers.dns import DNS, DNSQR
    import warnings
    warnings.filterwarnings("ignore")
    try:
        from scapy.layers.http import HTTPRequest
        from scapy.layers.tls.all import TLSClientHello, TLSServerHello
        from scapy.contrib.tls import *
    except Exception:
        pass
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── pull ultra engine sub-modules if available ────────────────────────────────
try:
    sys.path.insert(0, os.path.dirname(__file__))
    from ultra_analyzer import (
        EntropyEngine, BeaconDetector, UltraDNSAnalyzer,
        TLSFingerprinter, PassiveOSFingerprinter, UltraPortScanDetector,
        ProtocolAbuseDetector, map_mitre
    )
    ULTRA_OK = True
except ImportError:
    ULTRA_OK = False


# ══════════════════════════════════════════════════════════════════════════════
# ULTRA LIVE MONITOR
# ══════════════════════════════════════════════════════════════════════════════

class UltraLiveMonitor:
    def __init__(self, interface=None, bpf_filter=None):
        self.interface   = interface
        self.bpf_filter  = bpf_filter
        self.running     = False
        self.sniffer     = None
        self.start_time  = None
        self._lock       = threading.Lock()

        # ── stats ──────────────────────────────────────────────────────────
        self.stats = {
            "total_packets": 0,
            "total_bytes":   0,
            "protocols":     defaultdict(int),
            "unique_ips":    set(),
            "unique_ports":  set(),
        }

        # ── queues ─────────────────────────────────────────────────────────
        self.threats:   list = []   # emitted immediately on detect
        self.dns_log:   list = []
        self.http_log:  list = []
        self.tls_log:   list = []
        self.os_fps:    dict = {}   # ip → fingerprint
        self.alerts:    list = []   # last 100

        # ── sub-engines ────────────────────────────────────────────────────
        if ULTRA_OK:
            self.entropy_eng    = EntropyEngine()
            self.dns_analyzer   = UltraDNSAnalyzer()
            self.tls_fp         = TLSFingerprinter()
            self.os_fp          = PassiveOSFingerprinter()
            self.scan_detector  = UltraPortScanDetector(threshold=10, time_window=30.0)
            self.proto_abuse    = ProtocolAbuseDetector()
        else:
            self.entropy_eng    = None
            self.dns_analyzer   = None
            self.tls_fp         = None
            self.os_fp          = None
            self.scan_detector  = None
            self.proto_abuse    = None

        # ── beaconing: per-IP timestamps ───────────────────────────────────
        self._ip_timestamps:  dict = defaultdict(list)  # dst_ip → [ts,…]
        self._beacon_checked: set  = set()

        # ── C2 port list ───────────────────────────────────────────────────
        self.C2_PORTS = {4444,4445,5555,6666,6667,1337,31337,8888,9999,
                         1234,3333,2222,7777,8080,8443}

    # ── PACKET HANDLER ───────────────────────────────────────────────────────

    def _handle(self, pkt):
        if not self.running:
            return
        ts = float(pkt.time)

        with self._lock:
            self.stats["total_packets"] += 1
            self.stats["total_bytes"]   += len(pkt)

        if ARP in pkt:
            self._handle_arp(pkt, ts)
            return

        if IP not in pkt:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst

        with self._lock:
            self.stats["unique_ips"].add(src)
            self.stats["unique_ips"].add(dst)

        # OS fingerprint on first SYN
        if ULTRA_OK and self.os_fp and TCP in pkt:
            if (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10):
                if src not in self.os_fps:
                    fp = self.os_fp.fingerprint(pkt)
                    if fp:
                        self.os_fps[src] = fp

        if TCP in pkt:
            self._handle_tcp(pkt, src, dst, ts)
        elif UDP in pkt:
            self._handle_udp(pkt, src, dst, ts)
        elif ICMP in pkt:
            self._handle_icmp(pkt, src, dst, ts)

    def _handle_arp(self, pkt, ts):
        with self._lock:
            self.stats["protocols"]["ARP"] += 1
        if ULTRA_OK and self.proto_abuse and ARP in pkt and pkt[ARP].op == 2:
            src_ip  = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            if not hasattr(self, '_arp_cache'):
                self._arp_cache = {}
            prev = self._arp_cache.get(src_ip)
            if prev and prev != src_mac:
                self._emit_threat("ARP_SPOOFING", "CRITICAL", src_ip, None,
                    f"ARP cache poisoning: {src_ip} MAC changed {prev}→{src_mac}",
                    ["T1557.002"])
            self._arp_cache[src_ip] = src_mac

    def _handle_tcp(self, pkt, src, dst, ts):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        with self._lock:
            self.stats["protocols"]["TCP"] += 1
            self.stats["unique_ports"].add(sport)
            self.stats["unique_ports"].add(dport)

        # Port scan detection
        if ULTRA_OK and self.scan_detector:
            self.scan_detector.add_packet(pkt, ts)

        # C2 port
        if dport in self.C2_PORTS:
            self._emit_threat("C2_PORT", "CRITICAL", src, dst,
                f"Connection to known C2 port {dport}",
                ["T1071", "T1571"], confidence=0.85)

        # Beaconing accumulation
        self._ip_timestamps[dst].append(ts)
        if len(self._ip_timestamps[dst]) >= 8 and dst not in self._beacon_checked:
            if ULTRA_OK:
                result = BeaconDetector.analyze(self._ip_timestamps[dst])
                if result.get("beaconing"):
                    self._beacon_checked.add(dst)
                    self._emit_threat("C2_BEACONING", "CRITICAL", src, dst,
                        f"Beacon detected: interval={result['mean_interval_s']}s "
                        f"CV={result['cv']:.3f} type={result.get('beacon_type','?')}",
                        ["T1071", "T1571"],
                        evidence=result, confidence=result.get("confidence", 0.7))

        # TLS/JA3
        try:
            if TLSClientHello and pkt.haslayer(TLSClientHello) and ULTRA_OK and self.tls_fp:
                hello = pkt[TLSClientHello]
                ja3   = self.tls_fp.ja3(hello)
                if ja3:
                    bad = self.tls_fp.check_ja3(ja3)
                    entry = {"src": src, "dst": dst, "ja3": ja3, "ts": ts,
                             "known_tool": bad}
                    with self._lock:
                        self.tls_log.append(entry)
                        self.stats["protocols"]["TLS"] += 1
                    if bad:
                        self._emit_threat("MALICIOUS_JA3", "CRITICAL", src, dst,
                            f"Malicious TLS fingerprint: {ja3} ({bad})",
                            ["T1573", "T1573.001"],
                            evidence={"ja3": ja3, "tool": bad}, confidence=0.95)
        except Exception:
            pass

        # HTTP
        try:
            if HTTPRequest and pkt.haslayer(HTTPRequest) and ULTRA_OK and self.proto_abuse:
                req = pkt[HTTPRequest]
                method = req.Method.decode()  if req.Method  else "GET"
                host   = req.Host.decode()    if req.Host    else ""
                path   = req.Path.decode()    if req.Path    else "/"
                ua     = req.User_Agent.decode() if (hasattr(req,"User_Agent") and req.User_Agent) else None
                entry  = {"method": method, "host": host, "path": path, "src": src, "ts": ts}
                with self._lock:
                    self.http_log.append(entry)
                    self.stats["protocols"]["HTTP"] += 1
                for evt in self.proto_abuse.check_http(method, ua, path, src, ts):
                    self._emit_threat(evt.type, evt.severity, src, dst,
                        evt.detail, [m["id"] if isinstance(m,dict) else m
                                     for m in (evt.mitre or [])],
                        confidence=evt.confidence)
        except Exception:
            pass

        # Payload entropy + YARA
        if pkt.haslayer('Raw') and ULTRA_OK and self.entropy_eng:
            try:
                data = bytes(pkt['Raw'].load)
                if len(data) > 64:
                    ent = self.entropy_eng.classify(data)
                    if ent["entropy"] > 7.5:
                        self._maybe_add_alert("HIGH_ENTROPY", "MEDIUM",
                            f"Encrypted/obfuscated payload: {ent['entropy']:.2f} entropy "
                            f"({ent['classification']})", src, dst)
            except Exception:
                pass

    def _handle_udp(self, pkt, src, dst, ts):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        with self._lock:
            self.stats["unique_ports"].add(sport)
            self.stats["unique_ports"].add(dport)

        if DNS in pkt:
            self._handle_dns(pkt, src, dst, ts)
        elif dport in (67, 68):
            with self._lock: self.stats["protocols"]["DHCP"] += 1
        elif dport == 123:
            with self._lock: self.stats["protocols"]["NTP"] += 1
        else:
            with self._lock: self.stats["protocols"]["UDP"] += 1

        # LLMNR / NBNS
        if ULTRA_OK and self.proto_abuse:
            evts = self.proto_abuse.check_llmnr(pkt, src)
            for e in evts:
                self._emit_threat(e.type, e.severity, src, dst, e.detail,
                    [m["id"] if isinstance(m,dict) else m for m in (e.mitre or [])])

    def _handle_dns(self, pkt, src, dst, ts):
        with self._lock: self.stats["protocols"]["DNS"] += 1

        if not (ULTRA_OK and self.dns_analyzer):
            return

        self.dns_analyzer.add_query(pkt, src, dst, ts)

        # Check last query for immediate threats
        if self.dns_analyzer.queries:
            q = self.dns_analyzer.queries[-1]
            if q.get("dga_suspect"):
                self._emit_threat("DNS_DGA", "HIGH", src, dst,
                    f"DGA domain: {q['query']} (entropy={q['label_entropy']})",
                    ["T1568", "T1568.002"])

            if q.get("suspicious_tld"):
                self._maybe_add_alert("SUSPICIOUS_DOMAIN", "MEDIUM",
                    f"Suspicious TLD: {q['query']}", src, dst)

        # Check for tunneling every 20 queries
        if len(self.dns_analyzer.queries) % 20 == 0:
            tunnels = self.dns_analyzer.detect_tunneling()
            for t in tunnels[-3:]:
                self._emit_threat("DNS_TUNNELING", "HIGH", src, dst,
                    f"DNS tunnel: {t['domain']} — {'; '.join(t['reasons'])}",
                    ["T1048", "T1071.004"])

        with self._lock:
            self.dns_log.append({
                "query": self.dns_analyzer.queries[-1].get("query", ""),
                "type": self.dns_analyzer.queries[-1].get("type", "A"),
                "src": src, "ts": ts
            })

    def _handle_icmp(self, pkt, src, dst, ts):
        with self._lock: self.stats["protocols"]["ICMP"] += 1

        if ULTRA_OK and self.proto_abuse:
            evts = self.proto_abuse.check_icmp(pkt, src, dst)
            for e in evts:
                self._emit_threat(e.type, e.severity, src, dst, e.detail,
                    [m["id"] if isinstance(m,dict) else m for m in (e.mitre or [])],
                    confidence=e.confidence)

    # ── THREAT EMITTER ────────────────────────────────────────────────────────

    def _emit_threat(self, threat_type, severity, src, dst, detail,
                     mitre=None, evidence=None, confidence=1.0):
        event = {
            "type":       threat_type,
            "severity":   severity,
            "src":        src,
            "dst":        dst,
            "detail":     detail,
            "mitre":      mitre or [],
            "confidence": round(confidence, 3),
            "timestamp":  datetime.utcnow().isoformat(),
        }
        if evidence:
            event["evidence"] = evidence
        with self._lock:
            self.threats.append(event)
            self.alerts.append(event)
            if len(self.alerts) > 200:
                self.alerts = self.alerts[-200:]

    def _maybe_add_alert(self, alert_type, severity, detail, src, dst):
        """Add to alerts list but don't push as threat event (lower confidence)"""
        entry = {
            "type":    alert_type,
            "severity": severity,
            "detail":  detail,
            "src":     src,
            "dst":     dst,
            "ts":      datetime.utcnow().isoformat(),
        }
        with self._lock:
            self.alerts.append(entry)
            if len(self.alerts) > 200:
                self.alerts = self.alerts[-200:]

    # ── SNAPSHOT BUILDER ─────────────────────────────────────────────────────

    def _snapshot(self):
        duration = time.time() - self.start_time if self.start_time else 0
        with self._lock:
            # Flush new threats since last snapshot
            new_threats = list(self.threats)
            self.threats.clear()

            snap = {
                "event":        "snapshot",
                "ts":           datetime.utcnow().isoformat(),
                "running":      self.running,
                "duration_s":   round(duration, 1),
                "stats": {
                    "total_packets": self.stats["total_packets"],
                    "total_bytes":   self.stats["total_bytes"],
                    "packet_rate":   round(self.stats["total_packets"] / max(duration, 1), 1),
                    "byte_rate":     round(self.stats["total_bytes"] / max(duration, 1), 1),
                    "unique_ips":    len(self.stats["unique_ips"]),
                    "unique_ports":  len(self.stats["unique_ports"]),
                    "protocols":     dict(self.stats["protocols"]),
                },
                "new_threats":  new_threats,
                "alerts":       list(self.alerts[-20:]),
                "dns_recent":   list(self.dns_log[-10:]),
                "http_recent":  list(self.http_log[-10:]),
                "tls_recent":   list(self.tls_log[-10:]),
                "os_fingerprints": dict(self.os_fps),
                "ultra_engine": ULTRA_OK,
            }

            # Port scan results (checked every snapshot)
            if ULTRA_OK and self.scan_detector:
                scans = self.scan_detector.get_scan_events()
                for s in scans:
                    snap["new_threats"].append({
                        "type":      s.get("scan_type", "PORT_SCAN"),
                        "severity":  s.get("severity", "HIGH"),
                        "src":       s.get("src"),
                        "detail":    f"{s.get('scan_type')} — {s.get('ports_targeted', s.get('unique_sources','?'))} targets",
                        "mitre":     ["T1046"],
                        "confidence": 0.9,
                        "timestamp": datetime.utcnow().isoformat(),
                    })

        return snap

    # ── START / STOP ──────────────────────────────────────────────────────────

    def start(self):
        if not SCAPY_OK:
            print(json.dumps({"error": "scapy not installed"}), flush=True)
            return

        self.running    = True
        self.start_time = time.time()

        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter or None,
            prn=self._handle,
            store=False,
        )
        self.sniffer.start()

        try:
            while self.running:
                time.sleep(1)
                snap = self._snapshot()
                print(json.dumps(snap, default=str), flush=True)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        # Final snapshot
        snap = self._snapshot()
        snap["event"] = "final"
        print(json.dumps(snap, default=str), flush=True)


# ══════════════════════════════════════════════════════════════════════════════
# LIST INTERFACES
# ══════════════════════════════════════════════════════════════════════════════

def list_interfaces():
    if not SCAPY_OK:
        return [{"name": "error", "ip": "scapy not installed"}]
    try:
        result = []
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                result.append({"name": iface, "ip": ip or "0.0.0.0"})
            except Exception:
                result.append({"name": iface, "ip": "0.0.0.0"})
        return result
    except Exception as e:
        return [{"name": "default", "ip": str(e)}]


# ══════════════════════════════════════════════════════════════════════════════
# LEGACY COMPAT: LivePacketMonitor class (used by old Node bridge)
# ══════════════════════════════════════════════════════════════════════════════

class LivePacketMonitor(UltraLiveMonitor):
    """Drop-in replacement for the old LivePacketMonitor — backed by UltraLiveMonitor."""

    def __init__(self, interface=None, bpf_filter=None, max_packets=10000):
        super().__init__(interface=interface, bpf_filter=bpf_filter)
        self.max_packets = max_packets
        self.packet_count = 0
        self.callback = None

    def set_callback(self, callback):
        self.callback = callback

    def get_snapshot(self):
        return self._snapshot()

    def get_final_stats(self):
        return self._snapshot()


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ThreatForge Ultra Live Monitor v2")
    parser.add_argument("--interfaces", action="store_true", help="List interfaces")
    parser.add_argument("--monitor",    metavar="IFACE",    help="Interface to capture on")
    parser.add_argument("--bpf",        default="",         help="BPF filter")
    args = parser.parse_args()

    if args.interfaces:
        for iface in list_interfaces():
            print(f"{iface['name']}: {iface['ip']}")
        sys.exit(0)

    iface = args.monitor or None
    bpf   = args.bpf or None

    monitor = UltraLiveMonitor(interface=iface, bpf_filter=bpf)
    monitor.start()
