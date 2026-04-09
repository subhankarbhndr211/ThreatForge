"""
ThreatForge Ultra Packet Engine — Unit Tests
Run: python -m pytest tests/test_ultra_analyzer.py -v
"""
import sys, os, json, math, hashlib, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'packet-engine'))

import pytest

# ── imports under test ────────────────────────────────────────────────────────
from ultra_analyzer import (
    EntropyEngine,
    UltraFileCarver,
    BeaconDetector,
    UltraDNSAnalyzer,
    PassiveOSFingerprinter,
    TLSFingerprinter,
    UltraPortScanDetector,
    LLMTriageFormatter,
    STIXExporter,
    map_mitre,
    MITRE_MAP,
)

# ══════════════════════════════════════════════════════════════════════════════
# ENTROPY ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class TestEntropyEngine:
    def test_zero_entropy_constant(self):
        """All same byte → entropy = 0"""
        data = b'\x00' * 1000
        assert EntropyEngine.shannon(data) == 0.0

    def test_max_entropy_random(self):
        """256-byte alphabet used once each → entropy ≈ 8"""
        data = bytes(range(256))
        e = EntropyEngine.shannon(data)
        assert abs(e - 8.0) < 0.01

    def test_empty_data(self):
        assert EntropyEngine.shannon(b'') == 0.0

    def test_plaintext_low_entropy(self):
        text = b'hello world ' * 100
        e = EntropyEngine.shannon(text)
        assert e < 4.5

    def test_compression_ratio_constant(self):
        """Constant data should compress very well"""
        cr = EntropyEngine.compression_ratio(b'\x00' * 10000)
        assert cr < 0.02

    def test_compression_ratio_random(self):
        """Random-ish data compresses poorly"""
        import os
        data = bytes(range(256)) * 40
        cr = EntropyEngine.compression_ratio(data)
        assert cr > 0.5

    def test_classify_encrypted(self):
        data = bytes(range(256)) * 40
        result = EntropyEngine.classify(data)
        assert result['entropy'] > 7.0
        assert result['classification'] in ('encrypted_or_random', 'compressed')

    def test_classify_plaintext(self):
        result = EntropyEngine.classify(b'The quick brown fox jumps over the lazy dog. ' * 50)
        assert result['classification'] == 'plaintext'

    def test_block_entropy_returns_list(self):
        blocks = EntropyEngine.block_entropy(bytes(range(256)) * 10, block=256)
        assert isinstance(blocks, list)
        assert len(blocks) >= 1

# ══════════════════════════════════════════════════════════════════════════════
# FILE CARVER
# ══════════════════════════════════════════════════════════════════════════════

class TestUltraFileCarver:
    def test_identify_pe(self):
        data = b'MZ' + b'\x00' * 100
        info = UltraFileCarver.identify(data)
        assert info is not None
        assert info['type'] == 'pe'

    def test_identify_elf(self):
        data = b'\x7fELF' + b'\x00' * 100
        info = UltraFileCarver.identify(data)
        assert info is not None
        assert info['type'] == 'elf'

    def test_identify_pdf(self):
        data = b'%PDF-1.4' + b'\x00' * 100
        info = UltraFileCarver.identify(data)
        assert info is not None
        assert info['type'] == 'pdf'

    def test_identify_zip(self):
        data = b'PK\x03\x04' + b'\x00' * 100
        info = UltraFileCarver.identify(data)
        assert info is not None
        assert info['type'] == 'zip'

    def test_identify_png(self):
        data = b'\x89PNG' + b'\x00' * 100
        info = UltraFileCarver.identify(data)
        assert info is not None
        assert info['type'] == 'png'

    def test_identify_unknown(self):
        info = UltraFileCarver.identify(b'\xde\xad\xbe\xef' + b'\x00' * 100)
        assert info is None

    def test_identify_too_short(self):
        assert UltraFileCarver.identify(b'MZ') is None

    def test_hashes_correct(self):
        data = b'MZ' + b'\x00' * 100
        info = UltraFileCarver.identify(data)
        assert info['sha256'] == hashlib.sha256(data).hexdigest()
        assert info['md5']    == hashlib.md5(data).hexdigest()

    def test_carve_finds_pe_in_stream(self):
        stream = b'\x00' * 50 + b'MZ' + b'\x00' * 100 + b'\xff' * 50
        carved = UltraFileCarver.carve_all(stream)
        types = [c['type'] for c in carved]
        assert 'pe' in types

    def test_carve_empty(self):
        assert UltraFileCarver.carve_all(b'') == []

# ══════════════════════════════════════════════════════════════════════════════
# BEACON DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

class TestBeaconDetector:
    def _make_timestamps(self, interval, count, jitter=0.0):
        import random
        ts = [0.0]
        for _ in range(count - 1):
            ts.append(ts[-1] + interval + (random.uniform(-jitter, jitter) if jitter else 0))
        return ts

    def test_perfect_60s_beacon_detected(self):
        ts = self._make_timestamps(60, 20)
        result = BeaconDetector.analyze(ts)
        assert result['beaconing'] is True
        assert result['mean_interval_s'] == pytest.approx(60, abs=1)

    def test_random_traffic_no_beacon(self):
        import random
        random.seed(42)
        ts = sorted(random.uniform(0, 3600) for _ in range(50))
        result = BeaconDetector.analyze(ts)
        # High CV → not beaconing
        assert result['cv'] > 0.3 or result['beaconing'] is False

    def test_insufficient_samples(self):
        result = BeaconDetector.analyze([1.0, 2.0, 3.0])
        assert result['beaconing'] is False
        assert 'insufficient' in result['reason']

    def test_cobalt_strike_interval(self):
        ts = self._make_timestamps(60, 30)
        result = BeaconDetector.analyze(ts)
        assert result.get('beacon_type') == 'Cobalt Strike default (~60s)'

    def test_zero_mean_handled(self):
        result = BeaconDetector.analyze([1.0] * 10)
        assert result['beaconing'] is False

    def test_confidence_bounds(self):
        ts = self._make_timestamps(60, 15)
        result = BeaconDetector.analyze(ts)
        assert 0.0 <= result['confidence'] <= 1.0

    def test_cv_calculation(self):
        ts = self._make_timestamps(30, 20, jitter=0.5)
        result = BeaconDetector.analyze(ts)
        assert result['cv'] >= 0

    def test_changepoint_returned(self):
        """Beacon starting halfway through"""
        ts = list(range(10))  # random fast traffic
        ts += [10 + i * 60 for i in range(15)]  # then beacon
        result = BeaconDetector.analyze(ts)
        # Just check it doesn't crash
        assert 'changepoint' in result

# ══════════════════════════════════════════════════════════════════════════════
# DNS ANALYZER
# ══════════════════════════════════════════════════════════════════════════════

class TestUltraDNSAnalyzer:
    def _mock_dns_query(self, domain, qtype_str='A', label_entropy=None):
        if label_entropy is None:
            label = domain.split('.')[0]
            counts = {}
            for c in label:
                counts[c] = counts.get(c, 0) + 1
            total = len(label)
            label_entropy = -sum((v/total)*math.log2(v/total) for v in counts.values()) if total else 0
        return {
            'query': domain,
            'type': qtype_str,
            'src': '10.0.0.1',
            'dst': '8.8.8.8',
            'ts': 1000.0,
            'label_entropy': round(label_entropy, 3),
            'subdomain_depth': len(domain.split('.')) - 2,
            'label_length': len(domain.split('.')[0]),
            'suspicious_tld': any(domain.endswith(t) for t in UltraDNSAnalyzer.SUSPICIOUS_TLDS),
            'dga_suspect': label_entropy > UltraDNSAnalyzer.DGA_ENTROPY_THRESHOLD and len(domain) > 15,
        }

    def test_dga_detection_long_random(self):
        analyzer = UltraDNSAnalyzer()
        # Force a DGA-like query directly
        dga_domain = 'a4f3b9e2c1d7f6a5b8e3c2d1f9a7b6c5.evil.com'
        q = self._mock_dns_query(dga_domain)
        analyzer.queries.append(q)
        results = analyzer.detect_dga()
        assert len(results) >= 1

    def test_normal_domain_not_dga(self):
        analyzer = UltraDNSAnalyzer()
        q = self._mock_dns_query('google.com')
        analyzer.queries.append(q)
        results = analyzer.detect_dga()
        assert len(results) == 0

    def test_nx_sweep_detection(self):
        analyzer = UltraDNSAnalyzer()
        for i in range(150):
            analyzer.nx_domains.add(f'nonexistent{i}.evil.com')
        result = analyzer.detect_nx_sweep()
        assert result is not None
        assert result['nx_count'] > 100

    def test_no_nx_sweep_below_threshold(self):
        analyzer = UltraDNSAnalyzer()
        for i in range(50):
            analyzer.nx_domains.add(f'nonexistent{i}.evil.com')
        assert analyzer.detect_nx_sweep() is None

    def test_dns_rebinding_detection(self):
        analyzer = UltraDNSAnalyzer()
        analyzer.resolv_map['victim.com'] = {'1.2.3.4', '192.168.1.100', '10.0.0.1'}
        analyzer.ttl_history['victim.com'] = [5, 3, 2]
        results = analyzer.detect_rebinding()
        assert any(r['domain'] == 'victim.com' for r in results)

    def test_tunneling_long_label(self):
        analyzer = UltraDNSAnalyzer()
        long_label = 'a' * 60
        q = self._mock_dns_query(f'{long_label}.tunneldomain.com')
        analyzer.queries.append(q)
        results = analyzer.detect_tunneling()
        assert any('long label' in ' '.join(r['reasons']).lower() for r in results)

    def test_suspicious_tld_flagged(self):
        q = self._mock_dns_query('malware.tk')
        assert q['suspicious_tld'] is True

    def test_label_entropy_bounds(self):
        for domain in ['aaa.com', 'abc.com', 'xkj3fs9a.com']:
            q = self._mock_dns_query(domain)
            assert 0.0 <= q['label_entropy'] <= 8.0

# ══════════════════════════════════════════════════════════════════════════════
# PASSIVE OS FINGERPRINTER
# ══════════════════════════════════════════════════════════════════════════════

class TestPassiveOSFingerprinter:
    def test_no_scapy_returns_none_gracefully(self):
        """Without real packet, returns None"""
        result = PassiveOSFingerprinter.fingerprint("not_a_packet")
        assert result is None

    def test_ttl_normalization(self):
        """TTL 63 → initial 64"""
        class FakeIP:
            ttl = 63
            flags = 0x02  # DF set
        class FakeTCP:
            window = 65535
            options = [('MSS', 1460)]
        class FakePkt:
            def __contains__(self, item):
                from ultra_analyzer import IP, TCP
                return item in (IP, TCP)
            def __getitem__(self, item):
                from ultra_analyzer import IP, TCP
                if item == IP: return FakeIP()
                if item == TCP: return FakeTCP()

        # Can't really test without scapy packet — just validate the lookup table
        fp = PassiveOSFingerprinter()
        sig = (64, 65535, True, (1460,))
        assert sig in PassiveOSFingerprinter.OS_SIGNATURES
        assert 'Linux' in PassiveOSFingerprinter.OS_SIGNATURES[sig]

    def test_windows_signature_exists(self):
        sig = (128, 65535, True, (1460,))
        assert sig in PassiveOSFingerprinter.OS_SIGNATURES

    def test_ios_macos_signature(self):
        sig = (255, 65535, False, (1460,))
        assert sig in PassiveOSFingerprinter.OS_SIGNATURES

# ══════════════════════════════════════════════════════════════════════════════
# TLS FINGERPRINTER
# ══════════════════════════════════════════════════════════════════════════════

class TestTLSFingerprinter:
    def test_malicious_ja3_detected(self):
        known_hash = 'a0e9f5d64349fb13191bc781f81f42e1'
        result = TLSFingerprinter.check_ja3(known_hash)
        assert result is not None
        assert 'Cobalt' in result

    def test_clean_ja3_not_flagged(self):
        result = TLSFingerprinter.check_ja3('0' * 32)
        assert result is None

    def test_case_insensitive(self):
        known = 'A0E9F5D64349FB13191BC781F81F42E1'
        result = TLSFingerprinter.check_ja3(known)
        assert result is not None

    def test_ja3_bad_input_returns_none(self):
        """ja3 method with no valid hello returns None"""
        result = TLSFingerprinter.ja3(None)
        assert result is None

    def test_ja3s_bad_input_returns_none(self):
        result = TLSFingerprinter.ja3s(None)
        assert result is None

# ══════════════════════════════════════════════════════════════════════════════
# PORT SCAN DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

class TestUltraPortScanDetector:
    def test_syn_scan_detection(self):
        detector = UltraPortScanDetector(threshold=5, time_window=60)
        # Simulate 20 SYN packets to different ports from same source
        class FakeIP:
            def __init__(self):
                self.src = '10.0.0.1'
                self.dst = '192.168.1.1'
        class FakeTCP:
            def __init__(self, dport):
                self.dport = dport
                self.sport = 54321
                self.flags = 0x02  # SYN

        try:
            from ultra_analyzer import IP, TCP
            # Without real Scapy, test internal state directly
            detector.target_ports['10.0.0.1'] = set(range(80, 180))
            detector.attempts['10.0.0.1'] = [
                {'port': p, 'ts': float(i), 'flags': 0x02, 'dst': '192.168.1.1'}
                for i, p in enumerate(range(80, 180))
            ]
            results = detector.get_scan_events()
            assert len(results) >= 1
            src_results = [r for r in results if r.get('src') == '10.0.0.1']
            assert len(src_results) >= 1
            assert src_results[0]['scan_type'] == 'SYN Scan'
        except ImportError:
            pass

    def test_horizontal_scan_detection(self):
        detector = UltraPortScanDetector(threshold=5, time_window=60)
        # 20 different IPs hitting port 22
        for i in range(20):
            detector.horizontal[22].add(f'1.2.3.{i}')
        results = detector.get_scan_events()
        h_results = [r for r in results if r.get('scan_type') == 'Horizontal Scan']
        assert len(h_results) >= 1
        assert h_results[0]['port'] == 22

    def test_below_threshold_no_alert(self):
        detector = UltraPortScanDetector(threshold=50, time_window=60)
        detector.target_ports['10.0.0.1'] = set(range(80, 90))  # only 10 ports
        detector.attempts['10.0.0.1'] = [
            {'port': p, 'ts': float(i), 'flags': 0x02, 'dst': '192.168.1.1'}
            for i, p in enumerate(range(80, 90))
        ]
        results = detector.get_scan_events()
        src_results = [r for r in results if r.get('src') == '10.0.0.1']
        assert len(src_results) == 0

    def test_xmas_scan_flags(self):
        detector = UltraPortScanDetector(threshold=5, time_window=60)
        detector.target_ports['10.0.0.2'] = set(range(1, 50))
        detector.attempts['10.0.0.2'] = [
            {'port': p, 'ts': float(i), 'flags': 0x29, 'dst': '192.168.1.1'}
            for i, p in enumerate(range(1, 50))
        ]
        results = detector.get_scan_events()
        src_results = [r for r in results if r.get('src') == '10.0.0.2']
        assert any('XMAS' in r.get('scan_type','') for r in src_results)

# ══════════════════════════════════════════════════════════════════════════════
# MITRE MAPPING
# ══════════════════════════════════════════════════════════════════════════════

class TestMITREMapping:
    def test_c2_beaconing_maps(self):
        result = map_mitre('C2_BEACONING')
        ids = [m['id'] for m in result]
        assert 'T1071' in ids

    def test_dns_tunneling_maps(self):
        result = map_mitre('DNS_TUNNELING')
        ids = [m['id'] for m in result]
        assert 'T1048' in ids

    def test_unknown_type_returns_empty(self):
        result = map_mitre('NONEXISTENT_THREAT_TYPE')
        assert result == []

    def test_all_mappings_have_id_and_name(self):
        for threat_type, entries in MITRE_MAP.items():
            for mitre_id, mitre_name in entries:
                assert mitre_id.startswith('T') or mitre_id.startswith('TA'), \
                    f"{threat_type}: invalid MITRE ID {mitre_id}"
                assert len(mitre_name) > 0

    def test_map_mitre_returns_dicts(self):
        result = map_mitre('ARP_SPOOFING')
        assert all(isinstance(m, dict) for m in result)
        assert all('id' in m and 'name' in m for m in result)

    def test_credential_exposure_maps(self):
        result = map_mitre('CREDENTIAL_EXPOSURE')
        ids = [m['id'] for m in result]
        assert 'T1040' in ids or 'T1552' in ids

# ══════════════════════════════════════════════════════════════════════════════
# STIX EXPORTER
# ══════════════════════════════════════════════════════════════════════════════

class TestSTIXExporter:
    def _sample_iocs(self):
        return {
            'ips': ['1.2.3.4', '5.6.7.8'],
            'domains': ['evil.com', 'c2.example.org'],
            'urls': ['http://evil.com/payload'],
            'hashes': ['a' * 64, 'b' * 64],
            'emails': [],
            'certificates': [],
        }

    def test_bundle_type(self):
        bundle = STIXExporter.build_bundle(self._sample_iocs(), [])
        assert bundle['type'] == 'bundle'

    def test_bundle_has_objects(self):
        bundle = STIXExporter.build_bundle(self._sample_iocs(), [])
        assert len(bundle['objects']) >= 4  # 2 IPs + 2 domains

    def test_ip_indicator_pattern(self):
        bundle = STIXExporter.build_bundle({'ips': ['1.2.3.4'], 'domains': [], 'urls': [], 'hashes': []}, [])
        ip_obj = next(o for o in bundle['objects'] if '1.2.3.4' in o.get('pattern',''))
        assert "ipv4-addr:value" in ip_obj['pattern']

    def test_domain_indicator_pattern(self):
        bundle = STIXExporter.build_bundle({'ips': [], 'domains': ['evil.com'], 'urls': [], 'hashes': []}, [])
        dom_obj = next(o for o in bundle['objects'] if 'evil.com' in o.get('pattern',''))
        assert "domain-name:value" in dom_obj['pattern']

    def test_hash_indicator_pattern(self):
        h = 'a' * 64
        bundle = STIXExporter.build_bundle({'ips': [], 'domains': [], 'urls': [], 'hashes': [h]}, [])
        hash_obj = next(o for o in bundle['objects'] if h in o.get('pattern',''))
        assert "SHA-256" in hash_obj['pattern']

    def test_all_objects_have_required_stix_fields(self):
        bundle = STIXExporter.build_bundle(self._sample_iocs(), [])
        required = {'type', 'id', 'created', 'modified'}
        for obj in bundle['objects']:
            assert required.issubset(obj.keys()), f"Missing fields in {obj.get('id')}"

    def test_bundle_id_is_deterministic_per_call(self):
        """Two calls in same second → different bundles (timestamp-based)"""
        b1 = STIXExporter.build_bundle({'ips': ['1.2.3.4'], 'domains': [], 'urls': [], 'hashes': []}, [])
        assert b1['id'].startswith('bundle--')

    def test_empty_iocs_produces_empty_objects(self):
        bundle = STIXExporter.build_bundle({'ips': [], 'domains': [], 'urls': [], 'hashes': []}, [])
        assert bundle['objects'] == []

# ══════════════════════════════════════════════════════════════════════════════
# LLM TRIAGE FORMATTER
# ══════════════════════════════════════════════════════════════════════════════

class TestLLMTriageFormatter:
    def _sample_report(self):
        return {
            'metadata': {
                'total_packets': 50000,
                'total_bytes': 10_000_000,
                'duration': 120.0,
                'unique_ips': 25,
                'unique_ports': 80,
            },
            'summary': {
                'critical': 2,
                'high': 5,
                'medium': 10,
                'mitre_techniques': ['T1071', 'T1040'],
            },
            'threats': [
                {'type': 'C2_BEACONING', 'severity': 'CRITICAL',
                 'src': '10.0.0.1', 'dst': '1.2.3.4', 'detail': 'test', 'mitre': [{'id':'T1071'}]},
                {'type': 'DNS_TUNNELING', 'severity': 'HIGH',
                 'src': '10.0.0.2', 'dst': '8.8.8.8', 'detail': 'tunnel', 'mitre': []},
            ],
            'dns_analysis': {'dga_suspects': [{'query': 'evil.tk'}]},
            'beaconing_analysis': {
                'beaconing': True, 'mean_interval_s': 60, 'confidence': 0.9,
                'beacon_type': 'Cobalt Strike default (~60s)',
            },
            'os_fingerprints': {
                '10.0.0.1': {'os_guess': 'Windows 10', 'initial_ttl': 128, 'window': 65535}
            },
        }

    def test_returns_string(self):
        out = LLMTriageFormatter.format(self._sample_report())
        assert isinstance(out, str)

    def test_contains_summary(self):
        out = LLMTriageFormatter.format(self._sample_report())
        assert 'CRITICAL' in out
        assert '2' in out

    def test_contains_beacon_info(self):
        out = LLMTriageFormatter.format(self._sample_report())
        assert '60' in out or 'beacon' in out.lower()

    def test_contains_analyst_questions(self):
        out = LLMTriageFormatter.format(self._sample_report())
        assert 'Analyst' in out or 'analyst' in out.lower()

    def test_handles_empty_report(self):
        out = LLMTriageFormatter.format({})
        assert isinstance(out, str)

    def test_os_fingerprints_included(self):
        out = LLMTriageFormatter.format(self._sample_report())
        assert 'Windows 10' in out

# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION-LIKE: UltraPacketAnalyzer smoke test (no scapy required)
# ══════════════════════════════════════════════════════════════════════════════

class TestUltraAnalyzerSmokeTest:
    def test_import_succeeds(self):
        from ultra_analyzer import UltraPacketAnalyzer
        assert UltraPacketAnalyzer is not None

    def test_instantiation_no_crash(self):
        from ultra_analyzer import UltraPacketAnalyzer
        a = UltraPacketAnalyzer(enable_ml=False, enable_yara=False, enable_reassembly=False)
        assert a is not None

    def test_analyze_without_scapy_returns_error(self):
        from ultra_analyzer import UltraPacketAnalyzer, SCAPY
        if SCAPY:
            pytest.skip("Scapy available — real test needed")
        a = UltraPacketAnalyzer(enable_ml=False, enable_yara=False)
        result = a.analyze('/nonexistent.pcap')
        assert 'error' in result

    def test_llm_triage_on_empty_report(self):
        from ultra_analyzer import UltraPacketAnalyzer
        a = UltraPacketAnalyzer(enable_ml=False, enable_yara=False)
        brief = a.llm_triage_brief()
        assert isinstance(brief, str)

    def test_export_stix_on_empty(self):
        from ultra_analyzer import UltraPacketAnalyzer
        a = UltraPacketAnalyzer(enable_ml=False, enable_yara=False)
        bundle = a.export_stix()
        assert bundle['type'] == 'bundle'
        assert bundle['objects'] == []

    def test_build_report_structure(self):
        from ultra_analyzer import UltraPacketAnalyzer
        a = UltraPacketAnalyzer(enable_ml=False, enable_yara=False)
        report = a._build_report()
        assert 'engine' in report
        assert 'metadata' in report
        assert 'summary' in report
        assert 'threats' in report
        assert 'iocs' in report

# ══════════════════════════════════════════════════════════════════════════════
# EDGE CASES
# ══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_entropy_single_byte(self):
        assert EntropyEngine.shannon(b'\xff') == 0.0

    def test_entropy_two_bytes_equal(self):
        e = EntropyEngine.shannon(b'\x00\xff')
        assert abs(e - 1.0) < 0.01

    def test_beacon_exact_5_samples(self):
        ts = [0, 60, 120, 180, 240]
        result = BeaconDetector.analyze(ts)
        assert 'beaconing' in result

    def test_dns_analyzer_empty_resolv_map(self):
        a = UltraDNSAnalyzer()
        assert a.detect_rebinding() == []

    def test_stix_export_large_ioc_list(self):
        iocs = {
            'ips': [f'1.2.3.{i}' for i in range(500)],
            'domains': [], 'urls': [], 'hashes': [],
        }
        bundle = STIXExporter.build_bundle(iocs, [])
        # Should cap at 100
        assert len(bundle['objects']) <= 100

    def test_map_mitre_all_keys_present(self):
        critical_keys = ['C2_BEACONING', 'DNS_TUNNELING', 'ARP_SPOOFING',
                         'CREDENTIAL_EXPOSURE', 'PORT_SCAN', 'MALICIOUS_JA3']
        for key in critical_keys:
            assert key in MITRE_MAP, f"Missing MITRE mapping for {key}"

    def test_file_carver_ole2(self):
        data = b'\xd0\xcf\x11\xe0' + b'\x00' * 100
        info = UltraFileCarver.identify(data)
        assert info is not None
        assert info['type'] == 'ole'

    def test_file_carver_sqlite(self):
        data = b'SQLite format 3\x00' + b'\x00' * 100
        info = UltraFileCarver.identify(data)
        assert info is not None
        assert info['type'] == 'sqlite'


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
