# Evidence Plane v1 Implementation Plan

最終更新: 2026-03-10
対象 Issue: GitHub `#10 Evidence Plane v1 を実装する`
状態: 完了 / close 済み

## 1. 目的

既存の `Suricata -> normalized event -> AI advisory` 先行実装を土台にしつつ、P0 の Evidence Plane を
`suricata_eve / noc_probe / syslog_min` の 3 入力を単一契約に落とす共通基盤として成立させる。

完了実装:

- [`schema.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/schema.py)
- [`bus.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/bus.py)
- [`suricata.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/suricata.py)
- [`noc_probe.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/noc_probe.py)
- [`syslog_min.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/syslog_min.py)
- [`service.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/service.py)

## 2. 現状資産

再利用前提の既存資産:

- Rust core の Suricata 正規化出力
  - `/var/log/azazel-edge/normalized-events.jsonl`
  - [`rust/azazel-edge-core/src/main.rs`](/home/azazel/Azazel-Edge/rust/azazel-edge-core/src/main.rs)
- NOC 側の断片実装
  - [`py/azazel_edge/sensors/network_health.py`](/home/azazel/Azazel-Edge/py/azazel_edge/sensors/network_health.py)
  - [`py/azazel_edge/sensors/system_metrics.py`](/home/azazel/Azazel-Edge/py/azazel_edge/sensors/system_metrics.py)
- 既存ログ群
  - `ai-events.jsonl`
  - `ai-llm.jsonl`
  - `runbook-events.jsonl`
  - `decision_explanations.jsonl`

不足しているもの:

- 共通 event schema
- source adapter の統一インターフェース
- syslog minimal parser
- NOC probe event 化
- 後段 consumer が参照する共通 bus

## 3. 採用方針

### 3.1 実装言語

P0 v1 は Python で実装する。

理由:

- 既存 NOC collector 断片が Python にある
- Web/UI/AI 側との接続が既に Python で整っている
- Rust core は当面 `suricata adapter` として扱う方が安全

### 3.2 責務分離

- Rust core:
  - Suricata の即応 path
  - 既存 normalized event 生成
- Evidence Plane v1:
  - multi-source normalization
  - event ID / timestamp / confidence 整形
  - queue or JSONL fanout
- Evaluator:
  - Evidence Plane の出力だけを入力にする

## 4. 共通 schema v1

必須項目:

- `event_id`: 文字列。一意 ID
- `ts`: ISO8601 UTC
- `source`: `suricata_eve` | `noc_probe` | `syslog_min`
- `kind`: source 内での事象種別
- `subject`: 評価対象の最小識別子
- `severity`: `0..100`
- `confidence`: `0.0..1.0`
- `attrs`: source 依存情報

推奨項目:

- `status`: `ok` | `warn` | `fail` | `info`
- `evidence_refs`: 元ログ参照や内部参照の配列
- `tags`: 補助タグ配列

### 4.1 event_id 生成

`event_id` は以下の材料から SHA-256 の先頭 16 bytes を hex 化して生成する。

- `source`
- `ts`
- `kind`
- `subject`
- source 固有 digest

これにより source を跨いでも一貫して識別できる。

### 4.2 subject の扱い

P0 では複雑な object にせず、最小文字列を採用する。

例:

- Suricata: `src=10.0.0.2,dst=10.0.0.1,sid=200001`
- NOC probe: `host=control-daemon`
- syslog_min: `host=azazel-edge,prog=suricata`

## 5. 入力 source ごとの仕様

### 5.1 Suricata adapter

入力:

- 既存 Rust core の normalized JSONL

変換:

- `source=suricata_eve`
- `kind=alert`
- `severity` は既存 `risk_score` を優先、無ければ `severity` を正規化
- `confidence` は既存 `confidence` があれば流用、無ければ `sid` 有無から推定

補足:

- P0 v1 では Rust core の出力を Evidence Plane の入口として認める
- 直接 eve.json を読む adapter は将来追加でよい

### 5.2 NOC probe adapter

入力:

- `network_health.py`
- `system_metrics.py`
- service active check
- DHCP lease read
- ARP table read

変換:

- `source=noc_probe`
- `kind` は `icmp`, `iface_stats`, `resource`, `dhcp_lease`, `arp_entry`, `service_health`, `collector_failure`
- service / host / client 単位で event を出す

補足:

- 1 回の probe から複数 event を出してよい
- 取得失敗は event 化する

### 5.3 syslog_min adapter

入力:

- ファイル tail または行入力

対象:

- RFC3164 ライクな最小形式
- host / program / message を取り出せればよい

変換:

- `source=syslog_min`
- `kind=syslog`
- `severity` は PRI が取れれば変換、無ければ 20 固定
- `confidence=0.4` を初期値としてよい

非目標:

- 完全 RFC 準拠 parser
- journald 直接統合

## 6. 実装スライス

### Slice 1: schema と bus

追加候補:

- `py/azazel_edge/evidence_plane/__init__.py`
- `py/azazel_edge/evidence_plane/schema.py`
- `py/azazel_edge/evidence_plane/bus.py`

内容:

- `NormalizedEvidenceEvent` dataclass
- `make_event_id()`
- `EventBus` または `JsonlFanout`

完了条件:

- 任意 source event を同一 JSON へ serialize できる

### Slice 2: Suricata adapter

追加候補:

- `py/azazel_edge/evidence_plane/adapters/suricata.py`

内容:

- 既存 `normalized-events.jsonl` の行を読み、共通 schema に再整形

完了条件:

- 既存 Suricata normalized event を Evidence Plane schema に変換できる

### Slice 3: NOC probe adapter

追加候補:

- `py/azazel_edge/evidence_plane/adapters/noc.py`
- `py/azazel_edge/sensors/service_health.py`

内容:

- network/system/service/DHCP/ARP を event 化

完了条件:

- `noc_probe` source で複数 kind を出せる

### Slice 4: syslog_min adapter

追加候補:

- `py/azazel_edge/evidence_plane/adapters/syslog_min.py`

内容:

- syslog line parser
- parse failure は drop ではなく error counter or collector_failure

完了条件:

- 最小 syslog line を schema に落とせる

### Slice 5: dispatch / consumer interface

追加候補:

- `py/azazel_edge/evidence_plane/service.py`

内容:

- adapter から bus への接続
- Evaluator が subscribe/pull できる最低 API

完了条件:

- NOC/SOC Evaluator が source 差分を意識せず event を読める

### Slice 6: tests

追加候補:

- `tests/test_evidence_plane_schema.py`
- `tests/test_evidence_plane_suricata_adapter.py`
- `tests/test_evidence_plane_noc_adapter.py`
- `tests/test_evidence_plane_syslog_min_adapter.py`

完了条件:

- 3 source の正規化がテストで担保される

## 7. 受け入れテスト

### Test A: Suricata normalized input

Given:

- 既存 Rust normalized event 1 件

Expect:

- `source=suricata_eve`
- `kind=alert`
- `event_id`, `ts`, `severity`, `confidence`, `attrs` が埋まる

### Test B: NOC probe snapshot

Given:

- network health + resource + service + DHCP/ARP の mock

Expect:

- `noc_probe` source の複数 event が生成される
- 失敗時も `collector_failure` が出る

### Test C: Minimal syslog line

Given:

- `"<34>Oct 11 22:14:15 azazel suricata: link down"` 相当

Expect:

- `source=syslog_min`
- host/program/message が `attrs` に入る

### Test D: consumer contract

Given:

- 3 source から混在 event

Expect:

- 後段 consumer が source 差分を見ずに `event_id`, `source`, `kind`, `severity`, `confidence`, `attrs` を読める

## 8. 実装順

1. schema / bus
2. Suricata adapter
3. NOC probe adapter
4. syslog_min adapter
5. dispatch/service
6. tests

## 9. 明示的な非目標

- 高度相関
- TI 連携
- flow 連携
- 複数ノード分散 bus
- durable message queue 導入
- 完全な syslog/journald 互換
