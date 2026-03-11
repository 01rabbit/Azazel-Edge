from __future__ import annotations

from typing import Any, Dict, List

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.evaluators import NocEvaluator, SocEvaluator
from azazel_edge.explanations import DecisionExplainer


class DemoScenarioPack:
    def scenarios(self) -> Dict[str, Dict[str, Any]]:
        return {
            'soc_redirect_demo': {
                'description': 'High-confidence SOC path leading to redirect-capable decision.',
                'events': [
                    {'event_id': 'soc-1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.5->192.168.40.10:443/TCP', 'severity': 88, 'confidence': 0.92, 'attrs': {'sid': 210001, 'attack_type': 'DNS C2 Beacon', 'category': 'Potentially Bad Traffic', 'target_port': 443, 'risk_score': 88, 'confidence_raw': 92, 'src_ip': '10.0.0.5', 'dst_ip': '192.168.40.10'}},
                    {'event_id': 'flow-1', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.5->192.168.40.10:443/TCP', 'severity': 45, 'confidence': 0.70, 'attrs': {'src_ip': '10.0.0.5', 'dst_ip': '192.168.40.10', 'dst_port': 443, 'flow_state': 'failed', 'app_proto': 'tls'}},
                    {'event_id': 'probe-1', 'source': 'noc_probe', 'kind': 'icmp_probe', 'subject': '192.168.40.1', 'severity': 0, 'confidence': 0.95, 'attrs': {'reachable': True}},
                ],
            },
            'noc_degraded_demo': {
                'description': 'NOC degradation path with poor path health and degraded device state.',
                'events': [
                    {'event_id': 'icmp-1', 'source': 'noc_probe', 'kind': 'icmp_probe', 'subject': '192.168.40.1', 'severity': 80, 'confidence': 0.95, 'attrs': {'reachable': False}},
                    {'event_id': 'iface-1', 'source': 'noc_probe', 'kind': 'iface_stats', 'subject': 'eth1', 'severity': 70, 'confidence': 0.95, 'attrs': {'interface': 'eth1', 'operstate': 'down', 'carrier': 0}},
                    {'event_id': 'sys-1', 'source': 'noc_probe', 'kind': 'cpu_mem_temp', 'subject': 'azazel-edge', 'severity': 70, 'confidence': 0.95, 'attrs': {'cpu_percent': 95, 'memory': {'percent': 88}, 'temperature_c': 84}},
                ],
            },
            'mixed_correlation_demo': {
                'description': 'Cross-source pair that demonstrates correlation, Sigma/YARA assist, and explanation payloads.',
                'events': [
                    {'event_id': 'soc-2', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.5->192.168.40.10:22/TCP', 'severity': 82, 'confidence': 0.88, 'attrs': {'sid': 210020, 'attack_type': 'SSH Brute Force', 'category': 'Attempted Administrator Privilege Gain', 'target_port': 22, 'risk_score': 82, 'confidence_raw': 88, 'src_ip': '10.0.0.5', 'dst_ip': '192.168.40.10', 'sample_name': 'loader_beacon_alpha'}, 'evidence_refs': ['sample:loader_beacon_alpha']},
                    {'event_id': 'flow-2', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.5->192.168.40.10:22/TCP', 'severity': 45, 'confidence': 0.70, 'attrs': {'src_ip': '10.0.0.5', 'dst_ip': '192.168.40.10', 'dst_port': 22, 'flow_state': 'failed', 'app_proto': 'ssh'}},
                    {'event_id': 'syslog-2', 'source': 'syslog_min', 'kind': 'syslog_line', 'subject': '10.0.0.5->192.168.40.10:22/TCP', 'severity': 60, 'confidence': 0.75, 'attrs': {'message': 'failed ssh auth burst', 'host': 'edge', 'tag': 'sshd'}},
                ],
            },
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
        self.arbiter = ActionArbiter()
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
        return {
            'scenario_id': scenario_id,
            'description': scenario.get('description', ''),
            'event_count': len(events),
            'execution': {
                'mode': 'deterministic_replay',
                'ai_used': False,
                'live_telemetry': False,
                'local_only': True,
                'source': 'demo_scenario_pack',
            },
            'capability_boundary': self.capability_boundary(),
            'noc': noc_eval,
            'soc': soc_eval,
            'arbiter': arbiter,
            'explanation': explanation,
        }

    @classmethod
    def capability_boundary(cls) -> Dict[str, List[str]]:
        return {key: list(value) for key, value in cls.CAPABILITY_BOUNDARY.items()}
