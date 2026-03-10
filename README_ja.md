# Azazel-Edge

<p align="center">
  <a href="./README.md">
    <img alt="English" src="https://img.shields.io/badge/Language-English-1f6feb?style=for-the-badge">
  </a>
  <a href="./README_ja.md">
    <img alt="日本語" src="https://img.shields.io/badge/Language-日本語-2ea44f?style=for-the-badge">
  </a>
</p>

Azazel-Edge は、小規模内部ネットワーク向けの Raspberry Pi クラス防御エッジゲートウェイです。  
内部ネットワーク基盤、決定論的な NOC/SOC 評価、運用者向け UI、そして統治された AI 補助を一体化しています。

<p align="center">
  <img src="https://img.shields.io/badge/-Raspberry%20Pi-C51A4A.svg?logo=raspberry-pi&style=flat">
  <img src="https://img.shields.io/badge/-Python-F9DC3E.svg?logo=python&style=flat">
  <img src="https://img.shields.io/badge/-Rust-000000.svg?logo=rust&style=flat">
  <img src="https://img.shields.io/badge/-Flask-000000.svg?logo=flask&style=flat">
  <img src="https://img.shields.io/badge/-Mattermost-0058CC.svg?logo=mattermost&style=flat">
  <img src="https://img.shields.io/badge/-Ollama-111111.svg?style=flat">
</p>

## コンセプト

Azazel-Edge は単なるダッシュボードやパケットフィルタではありません。  
以下を一貫した運用装置としてまとめています。

- 管理された内部セグメントと uplink gateway
- 継続的なネットワーク/サービス健全性監視
- セキュリティ/運用イベントの共通 Evidence Plane への正規化
- NOC / SOC の決定論的な一次評価
- Action Arbiter による明示的な行動選択
- Decision Explanation と監査ログ
- その後段に限定された AI 補助

設計上の主眼は、特に Raspberry Pi 5 クラスの制約下でも、AI 経路が中核防御機能を圧迫しないことです。

## できること

### 1. 内部エッジゲートウェイ
- `br0` を中心とした内部ネットワーク基盤の構築
- 既定内部アドレス: `172.16.0.254/24`
- AP モードの内部接続と外部 uplink への NAT/forwarding
- `NetworkManager`、`dnsmasq`、`nftables` ベースのホスト側制御

### 2. 運用 control plane
- WebUI / TUI / EPD が共通で参照する runtime snapshot を維持
- control daemon 経由で各種 action を実行
- mode 変更、reprobe、contain、Wi-Fi scan/connect などを提供

### 3. 決定論的 NOC/SOC パイプライン
- Evidence Plane が正規化する入力:
  - `suricata_eve`
  - `flow_min`
  - `noc_probe`
  - `syslog_min`
- NOC evaluator の評価軸:
  - availability
  - path health
  - device health
  - client health
- SOC evaluator の評価軸:
  - suspicion
  - confidence
  - technique likelihood
  - blast radius
- Action Arbiter が選ぶ action:
  - `observe`
  - `notify`
  - `throttle`
  - `redirect`
  - `isolate`

### 4. 統治された AI 補助
- Ollama 上のローカルモデルを補助経路として利用
- 現行モデル:
  - `qwen3.5:2b`
  - `qwen3.5:0.8b`
- AI の用途:
  - 曖昧な Suricata アラートの補助判断
  - オペレータからの質問対応
  - Runbook 候補提示
- AI は一次判断主体ではありません

### 5. オペレータ向けインターフェース
- Web ダッシュボード
- `/ops-comm` M.I.O. assist console
- Mattermost `/mio`
- TUI
- E-paper 表示

## 現行 runtime architecture

高レベルの判断パイプライン:

1. Evidence inputs
2. Evidence Plane
3. NOC / SOC evaluators
4. Action Arbiter
5. Decision Explanation
6. Notification / AI governance
7. Audit logging

関連資料:
- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [AI build and operation detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md)

## 機能ハイライト

### Unified evidence and evaluation
- 共通イベント schema:
  - `event_id`
  - `ts`
  - `source`
  - `kind`
  - `subject`
  - `severity`
  - `confidence`
  - `attrs`
- 入力元ごとの差異を adapter で吸収し、後段は同じ形式で扱う

### 研究拡張ライン
- config drift audit
- multi-segment NOC evaluation
- cross-source correlation
- ATT&CK / D3FEND visualization payload
- Sigma assist execution
- YARA / YARA-X assist matching
- upstream integration envelope/sink
- demo scenario pack

### M.I.O. operator assistance
M.I.O. は以下で使うオペレータ補助人格です。

- dashboard assist
- `/ops-comm`
- Mattermost `/mio`

M.I.O. は unrestricted agent ではなく、統治された補助層として設計しています。

参照:
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)

## インストール

### Unified installer

現在の Azazel-Edge を他ホストに再現する主導線です。

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
cd /home/azazel/Azazel-Edge
sudo ENABLE_SERVICES=1 bash installer/internal/install_migrated_tools.sh
```

### AI runtime のみ

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_OLLAMA=1 ENABLE_MATTERMOST=1 bash installer/internal/install_ai_runtime.sh
```

## 主なアクセス先

インストール後の既定エンドポイント:

- Dashboard: `https://172.16.0.254/`
- M.I.O. ops console: `https://172.16.0.254/ops-comm`
- Mattermost: `http://172.16.0.254:8065/`
- ローカル web backend: `http://127.0.0.1:8084/`

Mattermost の基本操作:

```text
/mio 現在の警戒ポイントは？
```

## 主要 systemd service

- `azazel-edge-control-daemon.service`
- `azazel-edge-web.service`
- `azazel-edge-ai-agent.service`
- `azazel-edge-core.service`
- `azazel-edge-epd-refresh.service`
- `azazel-edge-epd-refresh.timer`
- `azazel-edge-opencanary.service`
- `azazel-edge-suricata.service`

## クイック確認

```bash
systemctl status azazel-edge-control-daemon --no-pager
systemctl status azazel-edge-web --no-pager
systemctl status azazel-edge-ai-agent --no-pager
systemctl status azazel-edge-core --no-pager
curl http://127.0.0.1:8084/health
curl http://127.0.0.1:8084/api/state
```

AI runtime:

```bash
sudo docker exec azazel-edge-ollama ollama list
curl -sS http://127.0.0.1:8084/api/ai/capabilities | jq
```

## リポジトリ構成

| Path | 役割 |
|---|---|
| `py/azazel_edge/` | core runtime library、evaluator、arbiter、AI governance、研究拡張 |
| `py/azazel_edge_control/` | control daemon と action handler |
| `py/azazel_edge_ai/` | AI agent と M.I.O. assist path |
| `azazel_edge_web/` | Web backend、dashboard、ops-comm UI |
| `rust/azazel-edge-core/` | Rust defense core |
| `runbooks/` | Runbook registry |
| `systemd/` | service/timer units |
| `security/` | compose stack と security-side assets |
| `installer/` | unified installer と staged installer |
| `docs/` | architecture、AI operation、redesign、implementation notes |
| `tests/` | P0-P2 の unit/regression coverage |

## 参照資料

- [Architecture redesign notes](docs/ARCHITECTURE_REDESIGN.md)
- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [AI build and operation detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md)
- [Dashboard plan](docs/AZAZEL_EDGE_SOC_NOC_DASHBOARD_PLAN.md)

## ステータス

このリポジトリには、P0、P1、P2 の issue ラインで実装した runtime/library slice が含まれています。  
installer も、現行 Azazel-Edge の再現に必要な P0-P2 runtime module と asset を配布できる状態まで更新済みです。

## License

`LICENSE` がある場合はそれを参照してください。
