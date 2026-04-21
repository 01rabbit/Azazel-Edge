from __future__ import annotations

import copy

from typing import Any, Dict, List

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.evaluators import NocEvaluator, SocEvaluator
from azazel_edge.explanations import DecisionExplainer


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


ARSENAL_I18N_OVERRIDES: Dict[str, Dict[str, Dict[str, Any]]] = {
    "arsenal_low_watch": {
        "ja": {
            "title": "Ping sweep が WATCH 帯域へ入る",
            "talk_track": "Suricata が ping sweep を検知しました。決定論的 Mock-LLM scorer は WATCH に入りますが、まだ可逆制御は発動しません。",
            "attack_label": "Ping Sweep",
            "decision_path": {
                "first_pass": {
                    "headline": "MOCK-LLM SCORE 38",
                    "detail": "決定論的な一次判定が reconnaissance を分類し、ゲートウェイを WATCH に据え置きます。",
                },
                "ollama_review": {
                    "headline": "OLLAMA 不要",
                    "detail": "スコアが曖昧帯域の外側にあるため、一次判定をそのまま採用します。",
                    "evidence": "曖昧帯域に入っていない",
                },
                "final_policy": {
                    "headline": "FINAL POLICY: WATCH",
                    "detail": "セグメントは維持したまま、記録と観測を継続します。",
                },
            },
            "proofs": {
                "tc": {
                    "headline": "TC STANDBY",
                    "detail": "WATCH 帯域では遅延や帯域制御はまだ有効化されていません。",
                    "evidence": "tc qdisc 変更はまだ要求されていません。",
                },
                "firewall": {
                    "headline": "MICRO-POLICY READY",
                    "detail": "nftables / iptables は、スコアが制御閾値を超えるまで observe のままです。",
                    "evidence": "不審フロー向けポリシーレーンを確保済み。",
                },
                "decoy": {
                    "headline": "DECOY STANDBY",
                    "detail": "OpenCanary redirect は武装済みですが、WATCH 帯域ではまだ選択されません。",
                    "evidence": "redirect selector は idle のままです。",
                },
                "offline": {
                    "headline": "OFFLINE ACTIVE",
                    "detail": "Suricata、スコアリング、制御ロジックはすべてローカルで動作しています。",
                    "evidence": "決定論 scorer とローカル制御経路のみを使用。",
                },
                "epd": {
                    "headline": "EPD SYNC READY",
                    "detail": "電子ペーパーは WARNING を表示し、詳細確認のために WebUI を開くよう促します。",
                    "evidence": "想定パネル状態: WARNING / CHECK WEB",
                },
            },
        },
    },
    "arsenal_throttle": {
        "ja": {
            "title": "SSH brute force が review 帯域へ入る",
            "talk_track": "SSH brute force が曖昧帯域に入るため、ゲートウェイは Ollama によるローカル二次判定を行い、その後で bounded tc control を適用します。",
            "attack_label": "SSH Brute Force",
            "decision_path": {
                "first_pass": {
                    "headline": "MOCK-LLM SCORE 67",
                    "detail": "決定論的な一次判定が曖昧帯域に入っています。",
                },
                "ollama_review": {
                    "headline": "OLLAMA REVIEWED",
                    "detail": "ローカル Ollama が failed-auth の反復挙動を確認し、bounded control を維持します。",
                    "evidence": "model=qwen3.5:2b | verdict=throttle | confidence=0.78",
                },
                "final_policy": {
                    "headline": "FINAL POLICY: THROTTLE",
                    "detail": "メインセグメントを維持したまま、可逆な tc shaping を適用します。",
                },
            },
            "proofs": {
                "tc": {
                    "headline": "TC THROTTLE ACTIVE",
                    "detail": "不審フローに対して bounded delay と帯域制御が有効です。",
                    "evidence": "netem delay 120ms + tbf rate 2mbit burst 32kbit",
                },
                "firewall": {
                    "headline": "MICRO-POLICY ACTIVE",
                    "detail": "不審なフローは可逆なポリシーレーンに収められています。",
                    "evidence": "nft counter: 48 packets / 5.2 KiB",
                },
                "decoy": {
                    "headline": "DECOY ON HOLD",
                    "detail": "traffic shaping が吸収している間、OpenCanary redirect はまだ保留です。",
                    "evidence": "redirect band にはまだ達していません。",
                },
                "offline": {
                    "headline": "OFFLINE ACTIVE",
                    "detail": "スコア判定も制御判断もローカルで完結しています。",
                    "evidence": "リモートモデルや cloud API は不要です。",
                },
                "epd": {
                    "headline": "EPD SYNC READY",
                    "detail": "電子ペーパーは DANGER を表示し、WebUI への注意を促す想定です。",
                    "evidence": "想定パネル状態: DANGER / CHECK WEB",
                },
            },
        },
    },
    "arsenal_ollama_review": {
        "ja": {
            "title": "曖昧な admin login burst が Ollama review に入る",
            "talk_track": "このケースでは一次判定だけでは安全に決め切れないため、ゲートウェイはローカル Ollama に admin login burst の再判定をさせた上で bounded control を適用します。",
            "attack_label": "Suspicious Admin Login Burst",
            "decision_path": {
                "first_pass": {
                    "headline": "MOCK-LLM SCORE 67",
                    "detail": "決定論的な一次判定が曖昧帯域に入り、この段階だけでは安全に分類できません。",
                },
                "ollama_review": {
                    "headline": "OLLAMA REVIEWED",
                    "detail": "ローカル Ollama が repeated 401 burst、admin URI targeting、cross-source timing を相関し bounded control を確定します。",
                    "evidence": "model=qwen3.5:2b | verdict=throttle | confidence=0.81",
                },
                "final_policy": {
                    "headline": "FINAL POLICY: THROTTLE",
                    "detail": "正規クライアントのサービス経路を保ちながら、可逆な tc shaping を適用します。",
                },
            },
            "proofs": {
                "tc": {
                    "headline": "TC THROTTLE ACTIVE",
                    "detail": "login burst の再判定中も bounded delay と帯域制御が有効です。",
                    "evidence": "netem delay 90ms + tbf rate 3mbit burst 32kbit",
                },
                "firewall": {
                    "headline": "MICRO-POLICY ACTIVE",
                    "detail": "不審な admin endpoint は可逆なポリシーレーンに固定されています。",
                    "evidence": "nft counter: 33 packets / 3.8 KiB on tcp dport 8443",
                },
                "decoy": {
                    "headline": "DECOY ON HOLD",
                    "detail": "リスクが redirect 帯域を超えるまでは OpenCanary redirect は保留です。",
                    "evidence": "redirect selector は decoy threshold 未満です。",
                },
                "offline": {
                    "headline": "OFFLINE ACTIVE",
                    "detail": "決定論 scorer も Ollama review も gateway 内で完結しています。",
                    "evidence": "review path に外部 API 依存はありません。",
                },
                "epd": {
                    "headline": "EPD SYNC READY",
                    "detail": "電子ペーパーは DANGER を表示し、WebUI への注意を促す想定です。",
                    "evidence": "想定パネル状態: DANGER / CHECK WEB",
                },
            },
        },
    },
    "arsenal_decoy_redirect": {
        "ja": {
            "title": "高信頼シグナルをデコイへ redirect する",
            "talk_track": "スコアが最上位帯域に入ったため、ゲートウェイは本来セグメントを維持したまま、不審フローだけを OpenCanary デコイへ選択的に redirect します。",
            "attack_label": "Exploit Probe / RCE Beacon",
            "decision_path": {
                "first_pass": {
                    "headline": "MOCK-LLM SCORE 100",
                    "detail": "決定論的な一次判定だけで最上位帯域に到達しています。",
                },
                "ollama_review": {
                    "headline": "OLLAMA SKIPPED",
                    "detail": "スコアがすでに決定的なため、二次 review は不要です。",
                    "evidence": "redirect threshold を上回っている",
                },
                "final_policy": {
                    "headline": "FINAL POLICY: DECOY REDIRECT",
                    "detail": "メインセグメントを維持したまま、不審フローを OpenCanary へ誘導します。",
                },
            },
            "proofs": {
                "tc": {
                    "headline": "TC GUARD ACTIVE",
                    "detail": "redirect lane が有効な間も traffic shaping はガードレールとして残ります。",
                    "evidence": "delay 80ms + ceiling 1mbit on suspicious lane",
                },
                "firewall": {
                    "headline": "MICRO-POLICY ACTIVE",
                    "detail": "不審フローは選択的 redirect ポリシーに固定されています。",
                    "evidence": "nft dnat counter: 91 packets / 11.4 KiB",
                },
                "decoy": {
                    "headline": "OPENCANARY REDIRECT",
                    "detail": "不審フローは OpenCanary デコイサービスへ誘導されています。",
                    "evidence": "Redirect hit count: 1 flow -> 172.16.0.77:443",
                },
                "offline": {
                    "headline": "OFFLINE ACTIVE",
                    "detail": "検知、スコア、redirect 判断はすべて gateway ローカルで完結しています。",
                    "evidence": "Suricata + 決定論 scorer + ローカル policy path のみ",
                },
                "epd": {
                    "headline": "EPD SYNC READY",
                    "detail": "電子ペーパーは DANGER を表示し、WebUI への注意を促す想定です。",
                    "evidence": "想定パネル状態: DANGER / CHECK WEB",
                },
            },
        },
    },
}


class DemoScenarioPack:
    def scenarios(self) -> Dict[str, Dict[str, Any]]:
        return {
            'arsenal_low_watch': {
                'description': 'Arsenal-compatible low band scenario showing a ping sweep in WATCH without active control.',
                'arsenal': {
                    'title': 'Ping sweep enters WATCH band',
                    'default_hold_sec': 8,
                    'scorer_features': {
                        'suricata_sev': 4,
                        'suricata_sid': 210101,
                        'suricata_signature': 'ET SCAN ping sweep reconnaissance',
                        'suricata_category': 'attempted-recon',
                        'suricata_action': 'allowed',
                        'target_port': 0,
                    },
                    'talk_track': 'Suricata detected a ping sweep. The deterministic Mock-LLM scorer enters WATCH, but no bounded control is applied yet.',
                    'attack_label': 'Ping Sweep',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'MOCK-LLM SCORE 38',
                            'detail': 'Deterministic first pass classifies reconnaissance and holds the gateway in WATCH.',
                        },
                        'ollama_review': {
                            'status': 'not-needed',
                            'headline': 'OLLAMA NOT NEEDED',
                            'detail': 'The score is outside the ambiguity band, so the first pass is accepted as-is.',
                            'evidence': 'Ambiguity window not entered',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: WATCH',
                            'detail': 'Log and observe while keeping the segment online.',
                        },
                    },
                    'proofs': {
                        'tc': {
                            'status': 'standby',
                            'headline': 'TC STANDBY',
                            'detail': 'No delay or bandwidth shaping is active in the WATCH band.',
                            'evidence': 'No tc qdisc change has been requested yet.',
                        },
                        'firewall': {
                            'status': 'observe',
                            'headline': 'MICRO-POLICY READY',
                            'detail': 'nftables / iptables stay in observe mode until the score crosses the control threshold.',
                            'evidence': 'Counter lane reserved for suspicious flow policy.',
                        },
                        'decoy': {
                            'status': 'standby',
                            'headline': 'DECOY STANDBY',
                            'detail': 'OpenCanary redirect is armed but not selected in the WATCH band.',
                            'evidence': 'Redirect selector remains idle.',
                        },
                        'offline': {
                            'status': 'active',
                            'headline': 'OFFLINE ACTIVE',
                            'detail': 'Suricata, scoring, and policy logic are running locally with no cloud dependency.',
                            'evidence': 'Deterministic scorer and local control path only.',
                        },
                        'epd': {
                            'status': 'sync',
                            'headline': 'EPD SYNC READY',
                            'detail': 'The e-paper panel raises WARNING and prompts the operator to open the WebUI for detail.',
                            'evidence': 'Expected panel state: WARNING / CHECK WEB.',
                        },
                    },
                },
                'events': [
                    {'event_id': 'ars-low-1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.5->172.16.0.20:0/ICMP', 'severity': 42, 'confidence': 0.62, 'attrs': {'sid': 210101, 'attack_type': 'Ping Sweep', 'category': 'Attempted Information Leak', 'target_port': 0, 'risk_score': 42, 'confidence_raw': 62, 'src_ip': '10.0.0.5', 'dst_ip': '172.16.0.20'}},
                    {'event_id': 'ars-low-2', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.5->172.16.0.20:0/ICMP', 'severity': 20, 'confidence': 0.55, 'attrs': {'src_ip': '10.0.0.5', 'dst_ip': '172.16.0.20', 'dst_port': 0, 'flow_state': 'open', 'app_proto': 'icmp'}},
                ],
            },
            'arsenal_throttle': {
                'description': 'Arsenal-compatible mid band scenario showing SSH brute force reviewed through Ollama before reversible throttle.',
                'arsenal': {
                    'title': 'SSH brute force enters review band',
                    'default_hold_sec': 10,
                    'scorer_features': {
                        'suricata_sev': 4,
                        'suricata_sid': 210201,
                        'suricata_signature': 'ET POLICY ssh brute force burst',
                        'suricata_category': 'attempted-recon',
                        'suricata_action': 'allowed',
                        'target_port': 22,
                    },
                    'talk_track': 'An SSH brute force lands in the ambiguity band, so Ollama performs a local second review before the gateway applies bounded tc control.',
                    'attack_label': 'SSH Brute Force',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'MOCK-LLM SCORE 67',
                            'detail': 'The deterministic first pass lands inside the ambiguity band.',
                        },
                        'ollama_review': {
                            'status': 'used',
                            'headline': 'OLLAMA REVIEWED',
                            'detail': 'Local Ollama confirms repeated failed-auth behavior and preserves bounded control.',
                            'evidence': 'model=qwen3.5:2b | verdict=throttle | confidence=0.78',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: THROTTLE',
                            'detail': 'Apply reversible tc shaping while the main segment stays online.',
                        },
                    },
                    'proofs': {
                        'tc': {
                            'status': 'active',
                            'headline': 'TC THROTTLE ACTIVE',
                            'detail': 'Bounded delay and bandwidth control are active on the suspicious flow.',
                            'evidence': 'netem delay 120ms + tbf rate 2mbit burst 32kbit',
                        },
                        'firewall': {
                            'status': 'active',
                            'headline': 'MICRO-POLICY ACTIVE',
                            'detail': 'The suspicious 443/TLS flow is held inside a reversible policy lane.',
                            'evidence': 'nft counter: 48 packets / 5.2 KiB',
                        },
                        'decoy': {
                            'status': 'standby',
                            'headline': 'DECOY ON HOLD',
                            'detail': 'OpenCanary redirect is still withheld while traffic shaping absorbs the flow.',
                            'evidence': 'Redirect selector stays below the redirect band.',
                        },
                        'offline': {
                            'status': 'active',
                            'headline': 'OFFLINE ACTIVE',
                            'detail': 'The score and enforcement decision are both computed locally.',
                            'evidence': 'No remote model or cloud API is required.',
                        },
                        'epd': {
                            'status': 'sync',
                            'headline': 'EPD SYNC READY',
                            'detail': 'The e-paper panel should raise DANGER and push attention toward the WebUI.',
                            'evidence': 'Expected panel state: DANGER / CHECK WEB.',
                        },
                    },
                },
                'events': [
                    {'event_id': 'ars-throttle-1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.5->172.16.0.20:22/TCP', 'severity': 76, 'confidence': 0.86, 'attrs': {'sid': 210201, 'attack_type': 'SSH Brute Force', 'category': 'Attempted Administrator Privilege Gain', 'target_port': 22, 'risk_score': 76, 'confidence_raw': 86, 'src_ip': '10.0.0.5', 'dst_ip': '172.16.0.20'}},
                    {'event_id': 'ars-throttle-2', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.5->172.16.0.20:22/TCP', 'severity': 40, 'confidence': 0.72, 'attrs': {'src_ip': '10.0.0.5', 'dst_ip': '172.16.0.20', 'dst_port': 22, 'flow_state': 'failed', 'app_proto': 'ssh'}},
                    {'event_id': 'ars-throttle-3', 'source': 'syslog_min', 'kind': 'syslog_line', 'subject': '172.16.0.20', 'severity': 38, 'confidence': 0.70, 'attrs': {'message': 'failed ssh auth burst promoted to bounded control review', 'host': 'edge', 'tag': 'azazel-demo'}},
                ],
            },
            'arsenal_decoy_redirect': {
                'description': 'Arsenal-compatible high band scenario showing decoy redirect to OpenCanary.',
                'arsenal': {
                    'title': 'High confidence signal redirects to decoy',
                    'default_hold_sec': 12,
                    'scorer_features': {
                        'suricata_sev': 1,
                        'suricata_sid': 210301,
                        'suricata_signature': 'ET command injection rce beacon',
                        'suricata_category': 'attempted-admin',
                        'suricata_action': 'allowed',
                        'target_port': 443,
                    },
                    'talk_track': 'The score enters the highest band, so the gateway keeps the main segment online and selectively redirects the suspicious flow into an OpenCanary decoy.',
                    'attack_label': 'Exploit Probe / RCE Beacon',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'MOCK-LLM SCORE 100',
                            'detail': 'The deterministic first pass already reaches the highest band.',
                        },
                        'ollama_review': {
                            'status': 'not-needed',
                            'headline': 'OLLAMA SKIPPED',
                            'detail': 'The score is already decisive, so no second review is needed.',
                            'evidence': 'Above redirect threshold',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: DECOY REDIRECT',
                            'detail': 'Keep the main segment online and steer the suspicious flow into OpenCanary.',
                        },
                    },
                    'proofs': {
                        'tc': {
                            'status': 'active',
                            'headline': 'TC GUARD ACTIVE',
                            'detail': 'Traffic shaping remains available while the redirect lane is engaged.',
                            'evidence': 'Guard rail profile: delay 80ms + ceiling 1mbit on suspicious lane',
                        },
                        'firewall': {
                            'status': 'active',
                            'headline': 'MICRO-POLICY ACTIVE',
                            'detail': 'The suspicious flow is pinned into a selective redirect policy.',
                            'evidence': 'nft dnat counter: 91 packets / 11.4 KiB',
                        },
                        'decoy': {
                            'status': 'redirect',
                            'headline': 'OPENCANARY REDIRECT',
                            'detail': 'The suspicious flow is being steered into the OpenCanary decoy service.',
                            'evidence': 'Redirect hit count: 1 flow -> 172.16.0.77:443',
                        },
                        'offline': {
                            'status': 'active',
                            'headline': 'OFFLINE ACTIVE',
                            'detail': 'Detection, score, and redirect choice stay local to the gateway.',
                            'evidence': 'Suricata + deterministic scorer + local policy path only.',
                        },
                        'epd': {
                            'status': 'sync',
                            'headline': 'EPD SYNC READY',
                            'detail': 'The e-paper panel should raise DANGER and push attention toward the WebUI.',
                            'evidence': 'Expected panel state: DANGER / CHECK WEB.',
                        },
                    },
                },
                'events': [
                    {'event_id': 'ars-decoy-1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.5->172.16.0.20:443/TCP', 'severity': 92, 'confidence': 0.95, 'attrs': {'sid': 210301, 'attack_type': 'RCE Beacon', 'category': 'Attempted Administrator Privilege Gain', 'target_port': 443, 'risk_score': 92, 'confidence_raw': 95, 'src_ip': '10.0.0.5', 'dst_ip': '172.16.0.20'}},
                    {'event_id': 'ars-decoy-2', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.5->172.16.0.20:443/TCP', 'severity': 55, 'confidence': 0.80, 'attrs': {'src_ip': '10.0.0.5', 'dst_ip': '172.16.0.20', 'dst_port': 443, 'flow_state': 'failed', 'app_proto': 'tls'}},
                    {'event_id': 'ars-decoy-3', 'source': 'syslog_min', 'kind': 'syslog_line', 'subject': '172.16.0.20', 'severity': 65, 'confidence': 0.82, 'attrs': {'message': 'honeypot redirect eligibility raised', 'host': 'edge', 'tag': 'azazel-demo'}},
                ],
            },
            'arsenal_ollama_review': {
                'description': 'Ambiguous admin login burst that requires a local Ollama review before bounded control is selected.',
                'arsenal': {
                    'title': 'Ambiguous admin login burst enters Ollama review',
                    'default_hold_sec': 10,
                    'scorer_features': {
                        'suricata_sev': 3,
                        'suricata_sid': 210251,
                        'suricata_signature': 'ET POLICY suspicious admin login burst',
                        'suricata_category': 'attempted-admin',
                        'suricata_action': 'allowed',
                        'target_port': 443,
                    },
                    'talk_track': 'The first pass is not decisive here, so the gateway asks local Ollama to review the admin login burst before applying bounded control.',
                    'attack_label': 'Suspicious Admin Login Burst',
                    'decision_path': {
                        'first_pass': {
                            'headline': 'MOCK-LLM SCORE 67',
                            'detail': 'The deterministic first pass lands in the ambiguity band and cannot safely classify the activity alone.',
                        },
                        'ollama_review': {
                            'status': 'used',
                            'headline': 'OLLAMA REVIEWED',
                            'detail': 'Local Ollama correlates repeated 401 bursts, admin URI targeting, and cross-source timing before confirming bounded control.',
                            'evidence': 'model=qwen3.5:2b | verdict=throttle | confidence=0.81',
                        },
                        'final_policy': {
                            'headline': 'FINAL POLICY: THROTTLE',
                            'detail': 'Apply reversible tc shaping while preserving the service path for legitimate clients.',
                        },
                    },
                    'proofs': {
                        'tc': {
                            'status': 'active',
                            'headline': 'TC THROTTLE ACTIVE',
                            'detail': 'Bounded delay and bandwidth control are active while the login burst is under review.',
                            'evidence': 'netem delay 90ms + tbf rate 3mbit burst 32kbit',
                        },
                        'firewall': {
                            'status': 'active',
                            'headline': 'MICRO-POLICY ACTIVE',
                            'detail': 'The suspicious admin endpoint is pinned into a reversible policy lane.',
                            'evidence': 'nft counter: 33 packets / 3.8 KiB on tcp dport 8443',
                        },
                        'decoy': {
                            'status': 'standby',
                            'headline': 'DECOY ON HOLD',
                            'detail': 'OpenCanary redirect is withheld until the risk crosses the redirect band.',
                            'evidence': 'Redirect selector remains below decoy threshold.',
                        },
                        'offline': {
                            'status': 'active',
                            'headline': 'OFFLINE ACTIVE',
                            'detail': 'Both the deterministic scorer and the Ollama review stay local to the gateway.',
                            'evidence': 'No external API dependency in the review path.',
                        },
                        'epd': {
                            'status': 'sync',
                            'headline': 'EPD SYNC READY',
                            'detail': 'The e-paper panel should raise DANGER and push attention toward the WebUI.',
                            'evidence': 'Expected panel state: DANGER / CHECK WEB.',
                        },
                    },
                },
                'events': [
                    {'event_id': 'ars-ollama-1', 'source': 'suricata_eve', 'kind': 'alert', 'subject': '10.0.0.5->172.16.0.20:443/TCP', 'severity': 71, 'confidence': 0.73, 'attrs': {'sid': 210251, 'attack_type': 'Suspicious Admin Login Burst', 'category': 'Attempted Administrator Privilege Gain', 'target_port': 443, 'risk_score': 71, 'confidence_raw': 73, 'src_ip': '10.0.0.5', 'dst_ip': '172.16.0.20'}},
                    {'event_id': 'ars-ollama-2', 'source': 'flow_min', 'kind': 'flow_summary', 'subject': '10.0.0.5->172.16.0.20:443/TCP', 'severity': 38, 'confidence': 0.64, 'attrs': {'src_ip': '10.0.0.5', 'dst_ip': '172.16.0.20', 'dst_port': 443, 'flow_state': 'open', 'app_proto': 'tls'}},
                    {'event_id': 'ars-ollama-3', 'source': 'syslog_min', 'kind': 'syslog_line', 'subject': '172.16.0.20', 'severity': 44, 'confidence': 0.69, 'attrs': {'message': 'admin ui repeated 401 burst from single source', 'host': 'edge', 'tag': 'reverse-proxy'}},
                ],
            },
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

    def localized_arsenal_meta(self, stage_id: str, lang: str = "en") -> Dict[str, Any]:
        scenario = self.scenarios().get(str(stage_id)) or {}
        meta = scenario.get("arsenal") if isinstance(scenario.get("arsenal"), dict) else {}
        if not isinstance(meta, dict):
            return {}
        if str(lang or "en").strip().lower() != "ja":
            return copy.deepcopy(meta)
        override = (
            ARSENAL_I18N_OVERRIDES.get(str(stage_id), {}).get("ja", {})
            if isinstance(ARSENAL_I18N_OVERRIDES.get(str(stage_id), {}), dict)
            else {}
        )
        if not isinstance(override, dict) or not override:
            return copy.deepcopy(meta)
        return _deep_merge(meta, override)


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
