from __future__ import annotations

import copy
from typing import Any, Dict, List

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.evaluators import NocEvaluator, SocEvaluator
from azazel_edge.explanations import DecisionExplainer
from azazel_edge.policy import load_soc_policy


class DemoScenarioPack:
    def scenarios(self) -> Dict[str, Dict[str, Any]]:
        return {
            'soc_redirect_demo': {
                'description': 'High-confidence SOC path leading to redirect-capable decision.',
                'demo': {
                    'title': 'High-confidence SOC path',
                    'summary': 'Cross-source SOC evidence promotes bounded control and a clear explanation trail.',
                    'attack_label': 'DNS C2 Beacon',
                    'default_hold_sec': 8,
                    'talk_track': 'Suricata and flow evidence raise a high-confidence SOC signal, so the deterministic demo path shows why the arbiter selects reversible control.',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'SOC SIGNAL: CRITICAL',
                            'detail': 'The Suricata alert and failed TLS flow align on the same source / destination pair.',
                        },
                        'second_pass': {
                            'headline': 'CORRELATION SUPPORT ACTIVE',
                            'detail': 'Cross-source evidence keeps the case on the SOC path before the arbiter selects control.',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: THROTTLE',
                            'detail': 'The suspicious flow moves into reversible bounded control instead of immediate isolation.',
                        },
                    },
                    'proofs': {
                        'detection': {
                            'status': 'active',
                            'headline': 'SURICATA ALERT ACTIVE',
                            'detail': 'The core trigger comes from Suricata and is reinforced by aligned flow evidence.',
                            'evidence': 'sid=210001 | flow anomaly support',
                        },
                        'control': {
                            'status': 'active',
                            'headline': 'REVERSIBLE CONTROL READY',
                            'detail': 'The arbiter keeps the response bounded and auditable.',
                            'evidence': 'action=throttle | mode=route_preference',
                        },
                        'explanation': {
                            'status': 'active',
                            'headline': 'EXPLANATION PAYLOAD READY',
                            'detail': 'The operator wording and next checks are available for replay surfaces.',
                            'evidence': 'decision explanation emitted for demo overlay',
                        },
                    },
                },
                'events': [
                    {'event_id': 'soc-1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.5->192.168.40.10:443/TCP', 'severity': 88, 'confidence': 0.92, 'attrs': {'sid': 210001, 'attack_type': 'DNS C2 Beacon', 'category': 'Potentially Bad Traffic', 'target_port': 443, 'risk_score': 88, 'confidence_raw': 92, 'src_ip': '10.0.0.5', 'dst_ip': '192.168.40.10'}},
                    {'event_id': 'flow-1', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.5->192.168.40.10:443/TCP', 'severity': 45, 'confidence': 0.70, 'attrs': {'src_ip': '10.0.0.5', 'dst_ip': '192.168.40.10', 'dst_port': 443, 'flow_state': 'failed', 'app_proto': 'tls'}},
                    {'event_id': 'probe-1', 'source': 'noc_probe', 'kind': 'icmp_probe', 'subject': '192.168.40.1', 'severity': 0, 'confidence': 0.95, 'attrs': {'reachable': True}},
                ],
            },
            'noc_degraded_demo': {
                'description': 'NOC degradation path with poor path health and degraded device state.',
                'demo': {
                    'title': 'NOC degradation path',
                    'summary': 'Path and device health degrade without a dominant SOC threat signal.',
                    'attack_label': 'Path / Service Degradation',
                    'default_hold_sec': 8,
                    'talk_track': 'This scenario keeps the focus on NOC evidence, showing that Azazel-Edge can separate service-health degradation from a primary attack response.',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'NOC HEALTH: CRITICAL',
                            'detail': 'ICMP reachability, interface state, and system telemetry all degrade at once.',
                        },
                        'second_pass': {
                            'headline': 'SOC THREAT SIGNAL: LOW',
                            'detail': 'There is no comparable SOC signal, so the arbiter avoids stronger traffic control.',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: NOTIFY',
                            'detail': 'The operator is prompted to investigate the path and device state before escalation.',
                        },
                    },
                    'proofs': {
                        'availability': {
                            'status': 'critical',
                            'headline': 'PATH HEALTH DEGRADED',
                            'detail': 'Reachability and interface evidence point to an uplink or path problem.',
                            'evidence': 'icmp unreachable | iface eth1 down',
                        },
                        'device': {
                            'status': 'critical',
                            'headline': 'DEVICE HEALTH DEGRADED',
                            'detail': 'Local resource pressure reinforces the NOC case.',
                            'evidence': 'cpu=95% | mem=88% | temp=84C',
                        },
                        'policy': {
                            'status': 'notify',
                            'headline': 'HUMAN LOOP ACTIVE',
                            'detail': 'The chosen action is operator notification instead of automatic containment.',
                            'evidence': 'action=notify | mode=human_loop',
                        },
                    },
                },
                'events': [
                    {'event_id': 'icmp-1', 'source': 'noc_probe', 'kind': 'icmp_probe', 'subject': '192.168.40.1', 'severity': 80, 'confidence': 0.95, 'attrs': {'reachable': False}},
                    {'event_id': 'iface-1', 'source': 'noc_probe', 'kind': 'iface_stats', 'subject': 'eth1', 'severity': 70, 'confidence': 0.95, 'attrs': {'interface': 'eth1', 'operstate': 'down', 'carrier': 0}},
                    {'event_id': 'sys-1', 'source': 'noc_probe', 'kind': 'cpu_mem_temp', 'subject': 'azazel-edge', 'severity': 70, 'confidence': 0.95, 'attrs': {'cpu_percent': 95, 'memory': {'percent': 88}, 'temperature_c': 84}},
                ],
            },
            'mixed_correlation_demo': {
                'description': 'Cross-source pair that demonstrates correlation, Sigma/YARA assist, and explanation payloads.',
                'demo': {
                    'title': 'Correlation with Sigma and YARA support',
                    'summary': 'Cross-source evidence is reinforced by Sigma and YARA helper hits before bounded control is chosen.',
                    'attack_label': 'SSH Brute Force',
                    'default_hold_sec': 10,
                    'talk_track': 'This replay shows the deterministic first pass, helper detections, and the final reversible-control decision in one compact sequence.',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'SSH SIGNAL: CRITICAL',
                            'detail': 'The Suricata alert, flow summary, and syslog line line up on the same SSH service.',
                        },
                        'second_pass': {
                            'headline': 'SIGMA / YARA SUPPORT',
                            'detail': 'Helper rules strengthen confidence before the arbiter finalizes bounded control.',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: THROTTLE',
                            'detail': 'The suspicious flow moves into reversible control while preserving the main path.',
                        },
                    },
                    'proofs': {
                        'sigma': {
                            'status': 'active',
                            'headline': 'SIGMA SUPPORT ACTIVE',
                            'detail': 'The SSH brute-force helper rule hits the Suricata evidence.',
                            'evidence': 'sigma.ssh.bruteforce',
                        },
                        'yara': {
                            'status': 'active',
                            'headline': 'YARA SUPPORT ACTIVE',
                            'detail': 'The sample reference aligns with the helper YARA rule.',
                            'evidence': 'yara.loader.alpha',
                        },
                        'policy': {
                            'status': 'active',
                            'headline': 'BOUNDED CONTROL SELECTED',
                            'detail': 'The chosen action remains reversible and audited.',
                            'evidence': 'action=throttle | effect=traffic_shaping',
                        },
                    },
                },
                'events': [
                    {'event_id': 'soc-2', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.5->192.168.40.10:22/TCP', 'severity': 82, 'confidence': 0.88, 'attrs': {'sid': 210020, 'attack_type': 'SSH Brute Force', 'category': 'Attempted Administrator Privilege Gain', 'target_port': 22, 'risk_score': 82, 'confidence_raw': 88, 'src_ip': '10.0.0.5', 'dst_ip': '192.168.40.10', 'sample_name': 'loader_beacon_alpha'}, 'evidence_refs': ['sample:loader_beacon_alpha']},
                    {'event_id': 'flow-2', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.5->192.168.40.10:22/TCP', 'severity': 45, 'confidence': 0.70, 'attrs': {'src_ip': '10.0.0.5', 'dst_ip': '192.168.40.10', 'dst_port': 22, 'flow_state': 'failed', 'app_proto': 'ssh'}},
                    {'event_id': 'syslog-2', 'source': 'syslog_min', 'kind': 'syslog_line', 'subject': '10.0.0.5->192.168.40.10:22/TCP', 'severity': 60, 'confidence': 0.75, 'attrs': {'message': 'failed ssh auth burst', 'host': 'edge', 'tag': 'sshd'}},
                ],
            },
            'disaster_phishing_demo': {
                'description': 'Disaster shelter phishing attack with fake government domain indicators.',
                'demo': {
                    'title': 'Disaster phishing triage',
                    'summary': 'A fake relief/government portal pattern is detected and routed to bounded SOC response.',
                    'attack_label': 'Disaster Phishing',
                    'default_hold_sec': 8,
                    'talk_track': 'The replay highlights social-engineering signals and keeps action bounded for operator review.',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'SOC SIGNAL: SOCIAL ENGINEERING',
                            'detail': 'Suricata phishing indicators and DNS anomaly support align on the same source.',
                        },
                        'second_pass': {
                            'headline': 'ATT&CK SUPPORT: T1566',
                            'detail': 'Mapping and category support reinforce phishing triage confidence.',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: REDIRECT OR NOTIFY',
                            'detail': 'The deterministic path keeps response reversible and operator-auditable.',
                        },
                    },
                },
                'events': [
                    {'event_id': 'soc-p1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.23->192.168.40.12:80/TCP', 'severity': 82, 'confidence': 0.88, 'attrs': {'sid': 9901201, 'attack_type': 'phishing/social-engineering', 'category': 'social-engineering', 'target_port': 80, 'risk_score': 82, 'confidence_raw': 88, 'src_ip': '10.0.0.23', 'dst_ip': '192.168.40.12'}},
                    {'event_id': 'dns-p1', 'source': 'syslog_min', 'kind': 'dns_query', 'subject': 'gov-login.example', 'severity': 60, 'confidence': 0.70, 'attrs': {'query': 'gov-login.example', 'result': 'resolved'}},
                    {'event_id': 'flow-p1', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.23->192.168.40.12:80/TCP', 'severity': 45, 'confidence': 0.65, 'attrs': {'src_ip': '10.0.0.23', 'dst_ip': '192.168.40.12', 'dst_port': 80, 'flow_state': 'suspicious', 'app_proto': 'http'}},
                ],
                'scoring': {
                    'scenario_id': 'disaster_phishing_demo',
                    'response_time_sec': None,
                    'correct_action': None,
                    'runbook_proposed': None,
                    'drills_completed': 0,
                },
            },
            'evacuation_network_demo': {
                'description': 'Shelter entry network degradation with DHCP stress and ARP spoof indicators.',
                'demo': {
                    'title': 'Evacuation network stress drill',
                    'summary': 'NOC degradation and ARP threat indicators are correlated before bounded control is selected.',
                    'attack_label': 'ARP Spoof + DHCP Degradation',
                    'default_hold_sec': 9,
                    'talk_track': 'The replay demonstrates NOC/SOC split handling under evacuation-time network instability.',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'NOC HEALTH: DEGRADED',
                            'detail': 'Path health and lease behavior degrade during high client churn.',
                        },
                        'second_pass': {
                            'headline': 'SOC SIGNAL: ARP SPOOF',
                            'detail': 'Gateway impersonation pattern increases suspicion on a specific source.',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: THROTTLE THEN ISOLATE REVIEW',
                            'detail': 'Deterministic response starts reversible and escalates only with sustained evidence.',
                        },
                    },
                },
                'events': [
                    {'event_id': 'noc-e1', 'source': 'noc_probe', 'kind': 'service_health', 'subject': 'dhcp', 'severity': 75, 'confidence': 0.90, 'attrs': {'service': 'dhcp', 'state': 'degraded'}},
                    {'event_id': 'soc-e1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': 'arp-gateway', 'severity': 80, 'confidence': 0.86, 'attrs': {'sid': 9901211, 'attack_type': 'arp spoof', 'category': 'bad-unknown', 'target_port': 0, 'risk_score': 80, 'confidence_raw': 86, 'src_ip': '10.0.0.77', 'dst_ip': '192.168.40.1'}},
                    {'event_id': 'noc-e2', 'source': 'noc_probe', 'kind': 'dhcp_leases', 'subject': 'lease-pool', 'severity': 68, 'confidence': 0.82, 'attrs': {'lease_failures': 15, 'pool_utilization': 95}},
                ],
                'scoring': {
                    'scenario_id': 'evacuation_network_demo',
                    'response_time_sec': None,
                    'correct_action': None,
                    'runbook_proposed': None,
                    'drills_completed': 0,
                },
            },
        }

    def stage_order(self) -> List[str]:
        return list(self.scenarios().keys())

    def metadata_for(self, scenario_id: str) -> Dict[str, Any]:
        scenario = self.scenarios().get(str(scenario_id)) or {}
        return self._normalize_demo_metadata(str(scenario_id), scenario)

    def list_items(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for scenario_id, scenario in self.scenarios().items():
            meta = self._normalize_demo_metadata(str(scenario_id), scenario)
            items.append(
                {
                    'scenario_id': str(scenario_id),
                    'title': str(meta.get('title') or scenario_id),
                    'description': str(scenario.get('description') or ''),
                    'summary': str(meta.get('summary') or ''),
                    'attack_label': str(meta.get('attack_label') or ''),
                    'default_hold_sec': int(meta.get('default_hold_sec') or 8),
                    'event_count': len(scenario.get('events', [])),
                }
            )
        return items

    @staticmethod
    def _normalize_demo_metadata(scenario_id: str, scenario: Dict[str, Any]) -> Dict[str, Any]:
        raw = scenario.get('demo') if isinstance(scenario.get('demo'), dict) else {}
        decision_path = raw.get('decision_path') if isinstance(raw.get('decision_path'), dict) else {}
        proofs = raw.get('proofs') if isinstance(raw.get('proofs'), dict) else {}
        title = str(raw.get('title') or scenario.get('description') or scenario_id)
        summary = str(raw.get('summary') or scenario.get('description') or '')
        return {
            'title': title,
            'summary': summary,
            'attack_label': str(raw.get('attack_label') or ''),
            'default_hold_sec': int(raw.get('default_hold_sec') or 8),
            'talk_track': str(raw.get('talk_track') or ''),
            'decision_path': copy.deepcopy(decision_path),
            'proofs': copy.deepcopy(proofs),
        }


class DemoScenarioRunner:
    CAPABILITY_BOUNDARY = {
        'implemented_now': [
            'deterministic_evidence_to_evaluation_pipeline',
            'deterministic_action_arbiter',
            'decision_explanation',
            'dashboard_demo_replay',
        ],
        'demo_only': [
            'synthetic_scenario_replay_overlay',
        ],
        'experimental': [
            'local_ai_operator_assist',
            'ti_sigma_yara_helpers',
        ],
        'non_goals': [
            'enterprise_siem_replacement',
            'fully_autonomous_response',
            'high_throughput_datacenter_edge',
        ],
    }

    def __init__(self):
        self.pack = DemoScenarioPack()
        self.noc = NocEvaluator()
        self.soc = SocEvaluator(
            sigma_rules=[{'id': 'sigma.ssh.bruteforce', 'title': 'SSH brute force support', 'source': 'suricata_eve', 'kind': 'alert', 'attrs': {'target_port': 22}, 'min_severity': 70}],
            yara_rules=[{'id': 'yara.loader.alpha', 'title': 'Loader alpha helper', 'contains_any': ['loader_beacon_alpha'], 'source': 'suricata_eve'}],
        )
        self.arbiter = ActionArbiter(policy=load_soc_policy())
        self.explainer = DecisionExplainer(output_path='/tmp/azazel-edge-demo-explanations.jsonl')

    def run(self, scenario_id: str) -> Dict[str, Any]:
        scenario = self.pack.scenarios().get(str(scenario_id))
        if not scenario:
            raise KeyError(f'unknown_scenario:{scenario_id}')
        events = scenario.get('events', [])
        noc_eval = self.noc.evaluate(events)
        soc_eval = self.soc.evaluate(events)
        client_impact = {'score': 0, 'affected_client_count': 0, 'critical_client_count': 0}
        arbiter = self.arbiter.decide(self.noc.to_arbiter_input(noc_eval), self.soc.to_arbiter_input(soc_eval), client_impact=client_impact)
        explanation = self.explainer.explain(
            noc=noc_eval,
            soc=soc_eval,
            arbiter=arbiter,
            trace_id=f'demo:{scenario_id}',
            target='demo-target',
        )
        demo_meta = self.pack.metadata_for(str(scenario_id))
        result = {
            'scenario_id': scenario_id,
            'description': scenario.get('description', ''),
            'event_count': len(events),
            'execution': {
                'mode': 'deterministic_replay',
                'ai_used': False,
                'live_telemetry': False,
                'local_only': True,
                'offline_demo': True,
                'source': 'demo_scenario_pack',
            },
            'capability_boundary': self.capability_boundary(),
            'noc': noc_eval,
            'soc': soc_eval,
            'arbiter': arbiter,
            'explanation': explanation,
        }
        result['demo'] = {
            **demo_meta,
            'operator_wording': str(explanation.get('operator_wording') or ''),
            'next_checks': list(explanation.get('next_checks') or []),
        }
        result['presentation'] = {
            'title': str(demo_meta.get('title') or scenario_id),
            'summary': str(demo_meta.get('summary') or scenario.get('description') or ''),
            'attack_label': str(demo_meta.get('attack_label') or ''),
        }
        return result

    @classmethod
    def capability_boundary(cls) -> Dict[str, List[str]]:
        return {key: list(value) for key, value in cls.CAPABILITY_BOUNDARY.items()}
