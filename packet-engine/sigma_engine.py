"""
ThreatForge Sigma-Like Rule Engine for Network Traffic
Converts Sigma rules to network traffic detection
"""

import json
import re
import math
from datetime import datetime, timedelta
from collections import defaultdict


class SigmaRule:
    def __init__(self, rule_data):
        self.id = rule_data.get("id", "unknown")
        self.name = rule_data.get("name", "Unnamed Rule")
        self.description = rule_data.get("description", "")
        self.author = rule_data.get("author", "")
        self.date = rule_data.get("date", "")
        self.level = rule_data.get("level", "medium")
        self.tags = rule_data.get("tags", [])
        self.logsource = rule_data.get("logsource", {})
        self.detection = rule_data.get("detection", {})
        self.condition = rule_data.get("condition", "all of them")
        self.mitre = rule_data.get("mitre", [])

    def matches(self, event):
        """Check if event matches this rule"""
        selections = self._evaluate_selections(event)
        return self._evaluate_condition(selections)

    def _evaluate_selections(self, event):
        """Evaluate all detection selections"""
        results = {}
        detection = self.detection

        if "selection" in detection:
            results["selection"] = self._match_selection(detection["selection"], event)
        if "filter" in detection:
            results["filter"] = self._match_selection(detection["filter"], event)
        if "keywords" in detection:
            results["keywords"] = self._match_keywords(detection["keywords"], event)

        return results

    def _match_selection(self, selection, event):
        """Match a selection against an event"""
        for key, value in selection.items():
            if key not in event:
                return False
            if isinstance(value, list):
                if event[key] not in value:
                    return False
            elif isinstance(value, str):
                if value.startswith("|"):
                    if not self._match_regex(value[1:], str(event[key])):
                        return False
                elif value.startswith("*"):
                    if value.endswith("*"):
                        if not str(event[key]).startswith(value[:-1]):
                            return False
                    elif not value in str(event[key]):
                        return False
                else:
                    if str(event[key]) != value:
                        return False
        return True

    def _match_keywords(self, keywords, event):
        """Match keywords in event values"""
        event_str = json.dumps(event).lower()
        for keyword in keywords:
            if keyword.lower() not in event_str:
                return False
        return True

    def _match_regex(self, pattern, value):
        """Match regex pattern"""
        try:
            return bool(re.search(pattern, value, re.IGNORECASE))
        except:
            return False

    def _evaluate_condition(self, selections):
        """Evaluate the condition expression"""
        condition = self.condition.lower()

        if "all of them" in condition:
            return all(selections.values()) if selections else False
        if "any of them" in condition:
            return any(selections.values()) if selections else False
        if "1 of them" in condition:
            return sum(1 for v in selections.values() if v) >= 1
        if "not filter" in condition and "selection" in selections:
            return selections["selection"] and not selections.get("filter", False)

        return False


class NetworkSigmaEngine:
    def __init__(self):
        self.rules = {}
        self.matches = []
        self.stats = defaultdict(int)

    def load_rules(self, rules_data):
        """Load rules from data"""
        for rule_data in rules_data:
            rule = SigmaRule(rule_data)
            self.rules[rule.id] = rule

    def add_rule(self, rule_data):
        """Add a single rule"""
        rule = SigmaRule(rule_data)
        self.rules[rule.id] = rule

    def detect(self, events):
        """Run detection on events"""
        results = []
        for event in events:
            for rule_id, rule in self.rules.items():
                try:
                    if rule.matches(event):
                        results.append(
                            {
                                "rule_id": rule_id,
                                "rule_name": rule.name,
                                "level": rule.level,
                                "event": event,
                                "mitre": rule.mitre,
                                "timestamp": datetime.now().isoformat(),
                            }
                        )
                        self.matches.append(rule_id)
                        self.stats[rule_id] += 1
                except Exception as e:
                    pass
        return results

    def detect_realtime(self, event):
        """Real-time detection on single event"""
        matched_rules = []
        for rule_id, rule in self.rules.items():
            try:
                if rule.matches(event):
                    matched_rules.append(
                        {
                            "rule_id": rule_id,
                            "rule_name": rule.name,
                            "level": rule.level,
                            "mitre": rule.mitre,
                        }
                    )
                    self.matches.append(rule_id)
                    self.stats[rule_id] += 1
            except:
                pass
        return matched_rules

    def get_stats(self):
        """Get detection statistics"""
        return {
            "total_rules": len(self.rules),
            "total_matches": len(self.matches),
            "rules_by_level": {
                "critical": len(
                    [r for r in self.rules.values() if r.level == "critical"]
                ),
                "high": len([r for r in self.rules.values() if r.level == "high"]),
                "medium": len([r for r in self.rules.values() if r.level == "medium"]),
                "low": len([r for r in self.rules.values() if r.level == "low"]),
            },
            "top_rules": sorted(self.stats.items(), key=lambda x: x[1], reverse=True)[
                :10
            ],
        }

    def clear_stats(self):
        """Clear statistics"""
        self.matches = []
        self.stats = defaultdict(int)


BUILTIN_NETWORK_RULES = [
    {
        "id": "network_c2_beaconing",
        "name": "C2 Beaconing Detection",
        "description": "Detects periodic beaconing patterns characteristic of C2 malware",
        "level": "high",
        "tags": ["attack.persistence", "attack.command_and_control"],
        "detection": {"selection": {"type": "dns_query", "interval_range": "45-65"}},
        "condition": "selection",
        "mitre": ["T1071", "T1071.001"],
    },
    {
        "id": "network_dns_tunneling",
        "name": "DNS Tunneling Detection",
        "description": "Detects potential DNS tunneling by high query volume or long subdomains",
        "level": "high",
        "tags": ["attack.exfiltration", "attack.command_and_control"],
        "detection": {
            "selection": {"type": "dns", "high_entropy": True},
            "keywords": ["txt", "base64", "encoded", "tunnel"],
        },
        "condition": "selection or keywords",
        "mitre": ["T1048", "T1071"],
    },
    {
        "id": "network_portscan",
        "name": "Port Scan Detection",
        "description": "Detects port scanning activity",
        "level": "medium",
        "tags": ["attack.discovery"],
        "detection": {"selection": {"type": "tcp", "flags": "S", "unique_ports": 15}},
        "condition": "selection",
        "mitre": ["T1046"],
    },
    {
        "id": "network_bruteforce_ssh",
        "name": "SSH Brute Force",
        "description": "Detects SSH brute force attempts",
        "level": "high",
        "tags": ["attack.credential_access", "attack.brute_force"],
        "detection": {"selection": {"type": "auth", "service": "ssh", "failed": True}},
        "condition": "selection",
        "mitre": ["T1110", "T1110.001"],
    },
    {
        "id": "network_data_exfiltration",
        "name": "Large Data Transfer",
        "description": "Detects large outbound data transfers",
        "level": "medium",
        "tags": ["attack.exfiltration"],
        "detection": {
            "selection": {"type": "flow", "direction": "outbound", "bytes": 104857600}
        },
        "condition": "selection",
        "mitre": ["T1041"],
    },
    {
        "id": "network_malicious_ja3",
        "name": "Malicious TLS Fingerprint",
        "description": "Detects known malicious TLS fingerprints",
        "level": "critical",
        "tags": ["attack.command_and_control"],
        "detection": {"selection": {"type": "tls", "ja3_known_malicious": True}},
        "condition": "selection",
        "mitre": ["T1071", "T1573"],
    },
    {
        "id": "network_icmp_tunnel",
        "name": "ICMP Tunnel Detection",
        "description": "Detects ICMP tunnels with large payloads",
        "level": "high",
        "tags": ["attack.command_and_control", "attack.exfiltration"],
        "detection": {"selection": {"type": "icmp", "payload_size": 100}},
        "condition": "selection",
        "mitre": ["T1095"],
    },
    {
        "id": "network_suspicious_dns",
        "name": "Suspicious DNS Query",
        "description": "Detects suspicious domain patterns",
        "level": "medium",
        "tags": ["attack.command_and_control"],
        "detection": {"keywords": ["c2", "malware", "phishing", "suspicious"]},
        "condition": "keywords",
        "mitre": ["T1071"],
    },
    {
        "id": "network_reverse_shell",
        "name": "Potential Reverse Shell",
        "description": "Detects potential reverse shell patterns",
        "level": "critical",
        "tags": ["attack.execution", "attack.command_and_control"],
        "detection": {
            "keywords": ["/bin/sh -i", "/bin/bash -i", "cmd.exe /c", "powershell -enc"]
        },
        "condition": "keywords",
        "mitre": ["T1059", "T1059.001"],
    },
    {
        "id": "network_anomalous_traffic",
        "name": "Anomalous Traffic Pattern",
        "description": "Detects anomalous traffic patterns using ML",
        "level": "medium",
        "tags": ["attack.initial_access"],
        "detection": {"selection": {"type": "flow", "ml_anomaly": True}},
        "condition": "selection",
        "mitre": ["T1070"],
    },
]


def create_network_sigma_engine():
    """Create engine with built-in network rules"""
    engine = NetworkSigmaEngine()
    engine.load_rules(BUILTIN_NETWORK_RULES)
    return engine


if __name__ == "__main__":
    engine = create_network_sigma_engine()
    print(f"Loaded {len(engine.rules)} network detection rules")
    print(json.dumps(engine.get_stats(), indent=2))
