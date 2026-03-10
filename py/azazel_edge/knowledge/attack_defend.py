from __future__ import annotations

from typing import Any, Dict, List


class AttackDefendKnowledge:
    ATTACK_TO_D3FEND: Dict[str, List[str]] = {
        'T1071 Application Layer Protocol': ['D3-DNSAL', 'D3-NTF'],
        'T1110 Brute Force': ['D3-AFA', 'D3-ANCI'],
        'T1190 Exploit Public-Facing Application': ['D3-WAF', 'D3-SFW'],
        'T1021 Remote Services': ['D3-NSEG', 'D3-ATD'],
        'T1595 Active Scanning': ['D3-NTA', 'D3-HNTA'],
    }

    D3FEND_LABELS: Dict[str, str] = {
        'D3-DNSAL': 'DNS allowlisting',
        'D3-NTF': 'Network traffic filtering',
        'D3-AFA': 'Adaptive file/account authentication',
        'D3-ANCI': 'Account use notification / control',
        'D3-WAF': 'Web application firewall',
        'D3-SFW': 'Service firewalling',
        'D3-NSEG': 'Network segmentation',
        'D3-ATD': 'Access trust differentiation',
        'D3-NTA': 'Network traffic analysis',
        'D3-HNTA': 'Host-network traffic analysis',
    }

    def build_visualization(self, attack_candidates: List[str], ti_matches: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        attacks = [str(x) for x in attack_candidates if str(x)]
        ti = [item for item in (ti_matches or []) if isinstance(item, dict)]
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        for attack in attacks:
            attack_id = f'attack:{attack}'
            nodes.append({'id': attack_id, 'type': 'attack', 'label': attack})
            for d3 in self.ATTACK_TO_D3FEND.get(attack, []):
                defend_id = f'd3fend:{d3}'
                if not any(node['id'] == defend_id for node in nodes):
                    nodes.append({
                        'id': defend_id,
                        'type': 'd3fend',
                        'label': self.D3FEND_LABELS.get(d3, d3),
                        'ref': d3,
                    })
                edges.append({'from': attack_id, 'to': defend_id, 'type': 'countermeasure'})

        for item in ti:
            indicator_type = str(item.get('indicator_type') or 'indicator')
            value = str(item.get('value') or '')
            if not value:
                continue
            node_id = f'ti:{indicator_type}:{value}'
            nodes.append({'id': node_id, 'type': 'indicator', 'label': f'{indicator_type}:{value}'})
            for attack in attacks[:3]:
                edges.append({'from': node_id, 'to': f'attack:{attack}', 'type': 'supports'})

        return {
            'format_version': 'v1',
            'nodes': nodes,
            'edges': edges,
            'attack_count': len(attacks),
            'd3fend_count': len([node for node in nodes if node.get('type') == 'd3fend']),
            'indicator_count': len([node for node in nodes if node.get('type') == 'indicator']),
        }
