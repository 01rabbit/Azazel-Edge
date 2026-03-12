# Azazel-Edge

<p align="center">
  <a href="./README.md">
    <img alt="English" src="https://img.shields.io/badge/Language-English-1f6feb?style=for-the-badge">
  </a>
  <a href="./README_ja.md">
    <img alt="日本語" src="https://img.shields.io/badge/Language-日本語-2ea44f?style=for-the-badge">
  </a>
</p>

Azazel-Edge は、Raspberry Pi クラスで動く operator-aware defensive edge appliance です。  
管理されたゲートウェイ、決定論的な SOC/NOC 評価、明示的な action arbitration、監査可能な decision explanation、そして統治されたローカル AI 補助を、現場運用向けに 1 つへまとめています。

<p align="center">
  <img src="https://img.shields.io/badge/-Raspberry%20Pi-C51A4A.svg?logo=raspberry-pi&style=flat">
  <img src="https://img.shields.io/badge/-Python-F9DC3E.svg?logo=python&style=flat">
  <img src="https://img.shields.io/badge/-Rust-000000.svg?logo=rust&style=flat">
  <img src="https://img.shields.io/badge/-Flask-000000.svg?logo=flask&style=flat">
  <img src="https://img.shields.io/badge/-Mattermost-0058CC.svg?logo=mattermost&style=flat">
  <img src="https://img.shields.io/badge/-Ollama-111111.svg?style=flat">
</p>

## Azazel-Edge が目を引く理由

- **AI より先に deterministic**  
  一次判断は Evidence Plane、NOC/SOC evaluator、Action Arbiter、Decision Explanation が担います。AI は bounded assist layer であり、主制御ではありません。
- **SOC と NOC と gateway を 1 台へ統合**  
  IDS 可視化だけでも、LLM ラッパーだけでもありません。エッジ gateway、共通 evidence、運用監視、脅威評価、operator action を 1 台で回します。
- **制約ハードウェア前提で設計**  
  Raspberry Pi 5 クラスでも、AI 経路が CPU、メモリ、運用判断を食い潰さないように組んでいます。
- **operator surface を最初から持つ**  
  Dashboard、`ops-comm`、Mattermost `/mio`、TUI、EPD が、それぞれ役割分担された運用面として用意されています。
- **再現しやすく、見せやすい**  
  installer で現行 runtime を再現でき、deterministic demo replay で live state を汚さずに判断経路を見せられます。

## 何ができるか

- **管理された内部セグメントと uplink gateway** を構築する
- **Suricata / flow / NOC probe / syslog** を共通 evidence に正規化する
- **運用障害** と **脅威兆候** を分離して評価し、action を選ぶ
- **Runbook / triage state machine / M.I.O.** で、プロ担当者と臨時担当の両方を支援する
- **deterministic scenario replay** でデモや検証を行う
- モデルの勘に頼らず、**説明可能で監査可能な判断** を残す

## Core Architecture

1. **Evidence inputs**
   - `suricata_eve`
   - `flow_min`
   - `noc_probe`
   - `syslog_min`
2. **Evidence Plane**
   - `event_id`, `ts`, `source`, `kind`, `subject`, `severity`, `confidence`, `attrs` を持つ共通 schema
3. **Deterministic evaluation**
   - NOC evaluator: availability, path health, device health, client health
   - SOC evaluator: suspicion, confidence, technique likelihood, blast radius
4. **Action Arbiter**
   - `observe`, `notify`, `throttle`, `redirect`, `isolate`
5. **Decision Explanation / Audit**
   - why chosen / why not others / evidence IDs / operator wording / JSONL trail
6. **Governed assist layer**
   - Ollama 上の M.I.O. が曖昧事象、質問応答、Runbook 補助を担当

## Operator Surfaces

### Dashboard
現在 posture、threat evidence、NOC health、action、demo replay、M.I.O. 概観をまとめて見る主盤面です。

### `ops-comm`
M.I.O. との直接対話、triage state machine、Runbook review、Mattermost bridge、demo control を扱う作業面です。

### Mattermost `/mio`
operator の質問、review 済み runbook 候補提示、handoff に使う chat 入口です。

### TUI / EPD
ローカルで状態を素早く把握するための軽量表示面です。

## Platform Capabilities

### Managed edge gateway
- `br0` を中心とした内部ネットワーク基盤
- 既定内部アドレス: `172.16.0.254/24`
- AP モード内部接続と外部 uplink への NAT/forwarding
- `NetworkManager`, `dnsmasq`, `nftables`, systemd を使った host-side orchestration

### Deterministic NOC/SOC pipeline
- adapter による evidence 正規化
- AI より前に評価が完結する一次判断経路
- explicit で reviewable な action selection
- default で残る explanation と audit trail

### Governed local AI
- 現行 Ollama モデル:
  - `qwen3.5:2b`
  - `qwen3.5:0.8b`
- AI の用途:
  - 曖昧アラート補助
  - operator 質問応答
  - runbook suggestion support
  - bilingual guidance output
- AI は primary decision-maker ではありません

### Guided triage and runbooks
- temporary / beginner 向け deterministic triage state machine
- diagnostic state からの runbook selector
- runbook review / approval flow
- triage session から Mattermost への handoff

### 研究拡張ライン
- config drift audit
- multi-segment NOC evaluation
- cross-source correlation
- ATT&CK / D3FEND visualization payloads
- Sigma assist execution
- YARA / YARA-X assist matching
- upstream integration envelopes / sinks
- deterministic demo scenario pack

## インストールと再現

### Unified installer

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_INTERNAL_NETWORK=1 \
     ENABLE_APP_STACK=1 \
     ENABLE_AI_RUNTIME=1 \
     ENABLE_DEV_REMOTE_ACCESS=0 \
     bash installer/internal/install_all.sh
```

主な切替:
- `ENABLE_INTERNAL_NETWORK=1|0`
- `ENABLE_APP_STACK=1|0`
- `ENABLE_AI_RUNTIME=1|0`
- `ENABLE_DEV_REMOTE_ACCESS=1|0`
- `ENABLE_RUST_CORE=1|0`

### App stack のみ

```bash
sudo ENABLE_SERVICES=1 bash installer/internal/install_migrated_tools.sh
```

### AI runtime のみ

```bash
sudo ENABLE_OLLAMA=1 ENABLE_MATTERMOST=1 bash installer/internal/install_ai_runtime.sh
```

## Quick Tour

既定の主要エンドポイント:
- Dashboard: `https://172.16.0.254/`
- M.I.O. ops console: `https://172.16.0.254/ops-comm`
- Mattermost: `http://172.16.0.254:8065/`
- local backend: `http://127.0.0.1:8084/`

Mattermost の基本操作:

```text
/mio 現在の最優先懸念は何か
```

deterministic demo replay:

```bash
bin/azazel-edge-demo list
bin/azazel-edge-demo run mixed_correlation_demo
```

## リポジトリ構成

| Path | 役割 |
|---|---|
| `py/azazel_edge/` | Evidence Plane、evaluator、arbiter、audit、SoT、triage、demo、研究/runtime extension |
| `py/azazel_edge_control/` | control daemon と action handler |
| `py/azazel_edge_ai/` | AI agent integration と M.I.O. assist path |
| `azazel_edge_web/` | Flask backend、dashboard、ops-comm UI |
| `rust/azazel-edge-core/` | Rust defense core |
| `runbooks/` | Runbook registry |
| `systemd/` | service / timer units |
| `security/` | compose stack と security-side assets |
| `installer/` | unified installer と staged install scripts |
| `docs/` | 公開向け architecture、AI operation、persona、demo 文書 |
| `tests/` | unit / regression coverage |

## ドキュメント

- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [AI build and operation detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md)
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)
- [Demo guide](docs/DEMO_GUIDE.md)
- [Demo guide (Japanese)](docs/DEMO_GUIDE_JA.md)


## Current Status

- P0, P1, P2 実装ラインがリポジトリに含まれています
- installer は現行 runtime module と asset を配備できる状態です
- 現在このリポジトリには **38** 個の Python test module と **15** 個の runbook 定義があります

## License

`LICENSE` がある場合はそれを参照してください。
