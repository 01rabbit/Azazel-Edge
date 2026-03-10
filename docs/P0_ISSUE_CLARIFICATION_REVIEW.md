# Azazel-Edge P0 Issue Clarification Review

最終更新: 2026-03-10
対象: GitHub Issues `#8` - `#17`
目的: Issue 記載の曖昧さを潰し、実装着手時の齟齬を防ぐ

## 1. 前提

P0 issue は方向性として妥当だが、現状実装には以下のズレがある。

- 既存実装は `Suricata -> normalized event -> AI advisory -> snapshot/log` が先行している
- `SoT / NOC collector / NOC-SOC evaluator separation / Action Arbiter formalization` は未成立または部分成立
- そのまま着手すると「既存部品の延長で済む」と「新規モジュールが必要」が混同される

この文書は、否定的レビュワー 5 名と反論する専門家 5 名の仮想討議を 8 ラウンド行い、P0 issue の最終解釈を固定した結果である。

## 2. 参加ロール

### 2.1 否定的レビュワー

- `Minimal Scope Skeptic`
- `Operations Skeptic`
- `Reliability Skeptic`
- `Security Boundary Skeptic`
- `Integration Skeptic`

### 2.2 反論する専門家

- `Evidence Plane Architect`
- `NOC Monitoring Architect`
- `SOC Evaluation Architect`
- `Control / Arbiter Architect`
- `Governance / Audit Architect`

## 3. 協議ラウンド

### Round 1: SoT は本当に P0 に必要か

`Minimal Scope Skeptic`:
- P0 は動くもの優先でよく、SoT は後回しでもよい
- `known_wifi.json` や `first_minute.yaml` の断片利用で十分ではないか

`Evidence Plane Architect`:
- SoT が無いと「想定内」「想定外」の区別が不能
- NOC/SOC の説明責任で、許可対象と期待経路は最低限必要

`Governance / Audit Architect`:
- SoT を後回しにすると説明と通知がすべて暫定ロジックになる

合意:
- P0 の SoT は「最小意図状態」に限定して残す
- CMDB や動的同期は非目標

### Round 2: Evidence Plane は Suricata 正規化だけでよいか

`Integration Skeptic`:
- 現状 Rust core が Suricata を正規化しているなら、それを Evidence Plane と呼べば済む

`Evidence Plane Architect`:
- それでは `suricata adapter` に過ぎない
- P0 要件は multi-source normalization であり、`suricata_eve / noc_probe / syslog_min` の 3 入力を同一契約へ落とす必要がある

`SOC Evaluation Architect`:
- SOC/NOC Evaluator を分けるには、入力差異を先に吸収する層が要る

合意:
- 既存 Rust core は Evidence Plane の 1 adapter と見なす
- P0 完了条件は multi-source 化

### Round 3: NOC collector はどこまで集めるべきか

`Operations Skeptic`:
- ICMP, interface stats, CPU/memory/temp, DHCP, ARP, service health を全部やると重い

`NOC Monitoring Architect`:
- P0 は深い telemetry ではなく「一次切り分けに必要な最小セット」
- DHCP/ARP を外すと client health が空論になる

`Reliability Skeptic`:
- 外部コマンド依存が増えると壊れやすい

合意:
- P0 は best-effort collector とする
- 取得失敗は collector failure event として Evidence Plane に載せる
- hard dependency 化しない

### Round 4: SOC Evaluator は LLM 付き recommendation で代替できるか

`Security Boundary Skeptic`:
- 既存 AI advisory があるので SOC Evaluator を別に作る必要は薄い

`SOC Evaluation Architect`:
- advisory は説明補助であり、deterministic evaluator の代替ではない
- `Suspicion / Confidence / Technique likelihood / Blast radius` を固定契約で返す必要がある

`Governance / Audit Architect`:
- AI 出力と evaluator 出力が混ざると監査不能

合意:
- SOC Evaluator は deterministic を主とし、AI は補助
- P0 で AI は evaluator の外側に置く

### Round 5: NOC Evaluator は snapshot enrich で十分か

`Minimal Scope Skeptic`:
- `network_health` の status と `user_state` があるなら、それで十分ではないか

`NOC Monitoring Architect`:
- それは collector 判定の副作用であり evaluator ではない
- Availability / Path / Device / Client の 4 出力と evidence ID が必要

`Control / Arbiter Architect`:
- Arbiter に渡す契約が無いと後段統合が壊れる

合意:
- `network_health` enrich は再利用するが、NOC Evaluator を独立モジュール化する

### Round 6: Action Arbiter は既存 defense decision でよいか

`Integration Skeptic`:
- Rust core に `block_and_honeypot / delay_and_observe / observe` があるので Arbiter は既にある

`Control / Arbiter Architect`:
- それは Suricata 即応 path であり、NOC/SOC 評価統合の Arbiter ではない
- P0 Arbiter は `observe / notify / throttle` のみ扱う上位判断層

`Security Boundary Skeptic`:
- 既存即応 path と混ぜると責務が衝突する

合意:
- Rust core の immediate defense は別経路
- P0 Action Arbiter は上位意思決定層として新設

### Round 7: AI 統治はすでに完成しているか

`Minimal Scope Skeptic`:
- 曖昧帯 routing と strict JSON があるので十分ではないか

`Governance / Audit Architect`:
- 概ね前進しているが、issue の意味では「いつ呼ぶか」「何を渡すか」「何を返すか」「採否をどう残すか」を固定しないと不十分

`Security Boundary Skeptic`:
- raw log を渡さない原則と実行権限を持たせない原則を文書で固定すべき

合意:
- AI 統治は P0 の中では最も進んでいる
- ただし「完成」ではなく、契約化で閉じる

### Round 8: Notification と Audit は後回しでよいか

`Operations Skeptic`:
- Arbiter ができてから通知と監査を作ればよい

`Governance / Audit Architect`:
- 既存部品があるので完全後回しは非効率
- ただし Arbiter 前提で仕様だけ先に固定し、実装統合は後段に寄せる方が安全

`Evidence Plane Architect`:
- event/evaluation/action/notification の系譜が追えないと P0 の価値が落ちる

合意:
- Notification / Audit は既存ログ群を再編して締める
- 先に schema を固定し、Arbiter 実装時に接続する

## 4. 最終採用案

### 4.1 横断原則

1. P0 は「最小成立ライン」であり、完全自動防御ではない
2. 既存実装は捨てずに adapter / collector / evaluator / arbiter として再編する
3. deterministic evaluator を主、AI を補助に置く
4. 評価結果とアクション決定には必ず evidence ID を持たせる
5. 取得失敗・評価不能もイベントとして残す

### 4.2 用語固定

- `SoT`: 許可対象と期待状態を保持する read-only 参照面
- `collector`: 外部状態を取ってくる層
- `Evidence Plane`: 入力を共通 schema に正規化する層
- `Evaluator`: 共通 schema を評価して NOC/SOC 判定を返す層
- `Action Arbiter`: NOC/SOC 判定から最終アクションを選ぶ層

## 5. P0 issue ごとの明確化事項

### #8 軽量SoT機能 v1

- P0 schema は `devices / networks / services / expected_paths` の 4 項目に限定
- `devices` は最低限 `id`, `hostname`, `ip`, `mac`, `criticality`, `allowed_networks`
- `networks` は最低限 `id`, `cidr`, `zone`, `gateway`
- `services` は最低限 `id`, `proto`, `port`, `owner`, `exposure`
- `expected_paths` は最低限 `src`, `dst`, `service_id`, `via`, `policy`
- YAML と JSON の両方を読めるか、どちらか片方を canonical にして他方を optional import にする
- P0 非目標: 自動 discovery, 外部 CMDB 同期, 差分検知

### #9 軽量NOC監視機能 v1

- collector 対象は `icmp`, `iface_stats`, `cpu_mem_temp`, `dhcp_leases`, `arp_table`, `service_health`
- 取得失敗は silent ignore せず collector event にする
- service health は `control-daemon`, `ai-agent`, `web`, `suricata`, `opencanary` を最低対象とする
- DHCP/ARP は client inventory の暫定ソースとして扱う
- P0 非目標: 高頻度 flow telemetry, 長期時系列分析, SNMP 統合

### #10 Evidence Plane v1

- P0 入力源は `suricata_eve`, `noc_probe`, `syslog_min`
- 共通 schema 必須項目は `event_id`, `ts`, `source`, `kind`, `subject`, `severity`, `confidence`, `attrs`
- `attrs` は source 依存の追加情報を入れる
- normalized event は queue または JSONL fanout で後段へ渡せればよい
- P0 非目標: 高度相関, multi-tenant, 複雑な schema registry

### #11 NOC Evaluator v1

- 出力必須項目は `availability`, `path_health`, `device_health`, `client_health`, `summary`, `evidence_ids`
- score は数値とラベルの両方を返す
- SoT が未設定でも degraded mode で動作し、`sot_missing` を理由へ含める
- P0 非目標: 最適経路計算, 容量予測, 履歴学習

### #12 SOC Evaluator v1

- 出力必須項目は `suspicion`, `confidence`, `technique_likelihood`, `blast_radius`, `summary`, `evidence_ids`
- ATT&CK candidate は補助情報であり、判定本体ではない
- LLM は補助説明に使えても evaluator の一次出力を置換しない
- P0 非目標: TI 照合, flow 相関, YARA/Sigma 連携

### #13 Action Arbiter v1

- 入力は NOC Evaluator と SOC Evaluator の固定 schema のみ
- 出力必須項目は `action`, `reason`, `chosen_evidence_ids`, `rejected_alternatives`
- `observe`: 外部副作用なし。ログ・UI 表示のみ
- `notify`: 外部通知を許可
- `throttle`: 可逆かつ限定的な制御のみ
- 既存 Rust core の immediate defense は本 issue の充足条件に含めない

### #14 Decision Explanation v1

- 説明は `why chosen`, `why not others`, `evidence_ids`, `operator wording`
- 人間向け文面と機械可読構造の両方を持つ
- P0 ではテンプレート生成でよく、自然言語生成品質は追わない

### #15 AI補助の統治層 v1

- AI へ渡すのは sanitized payload のみ
- raw log 全文、秘密情報、実行コマンド全文は渡さない
- AI は `advice / summary / candidate` のみ返す
- AI の採用・却下・fallback は必ず監査ログ化する

### #16 通知機能 v1

- notification source は Action Arbiter の `notify` 決定のみ
- 通知内容には `action`, `reason`, `target`, `evidence_ids` を含める
- Mattermost と ntfy のどちらか一方でもよいが、adapter を分離する
- P0 非目標: 自動エスカレーションルール多段化

### #17 最小監査ログ基盤 v1

- P0 ログ系列は `event_receive`, `evaluation`, `action_decision`, `notification`, `ai_assist`
- すべて JSONL とし、共通項目 `ts`, `kind`, `trace_id`, `source` を持たせる
- 既存ログ群は削除せず、traceable に再編する

## 6. 実装順の再確定

1. `#10 Evidence Plane v1`
2. `#9 軽量NOC監視機能 v1`
3. `#11 NOC Evaluator v1`
4. `#12 SOC Evaluator v1`
5. `#13 Action Arbiter v1`
6. `#8 軽量SoT機能 v1`
7. `#14` / `#15` / `#16` / `#17` を既存部品の整理として締める

## 7. 実装上の注意

- 既存 `normalized-events.jsonl`, `ai-events.jsonl`, `ai-llm.jsonl`, `runbook-events.jsonl`, `decision_explanations.jsonl` は再利用前提
- 既存 `network_health.py` と `system_metrics.py` は collector へ寄せて使う
- 既存 WebUI の guidance は Action Arbiter の代用品ではなく、一時的な operator assistance と位置づける
