# Azazel-Edge

<p align="center">
  <a href="./README.md">
    <img alt="English" src="https://img.shields.io/badge/Language-English-1f6feb?style=for-the-badge">
  </a>
  <a href="./README_ja.md">
    <img alt="日本語" src="https://img.shields.io/badge/Language-日本語-2ea44f?style=for-the-badge">
  </a>
</p>

Azazel-Edge は、Raspberry Pi 向けのエッジ運用スタックです。主に以下を統合します。
- 内部ネットワーク/ゲートウェイ構成
- 決定論的な NOC/SOC 評価とアクション選択
- オペレータ向け Web UI + API + Runbook運用ワークフロー
- ローカル AI 補助（Ollama + Mattermost 連携、任意）

この README は、**2026-03-15 時点**でリポジトリ内のコード、スクリプト、テスト、git 履歴、GitHub issue/PR 情報を照合して作成しています。

<p align="center">
  <img src="https://img.shields.io/badge/-Raspberry%20Pi-C51A4A.svg?logo=raspberry-pi&style=flat">
  <img src="https://img.shields.io/badge/-Python-F9DC3E.svg?logo=python&style=flat">
  <img src="https://img.shields.io/badge/-Rust-000000.svg?logo=rust&style=flat">
  <img src="https://img.shields.io/badge/-Flask-000000.svg?logo=flask&style=flat">
  <img src="https://img.shields.io/badge/-Mattermost-0058CC.svg?logo=mattermost&style=flat">
  <img src="https://img.shields.io/badge/-Ollama-111111.svg?style=flat">
</p>

## 言語間の意味統一

`README.md` と `README_ja.md` は、技術的な意味が一致するように維持します。

- コマンド、APIパス、環境変数、サービス名、ファイルパスは両ファイルで同一表記を維持します。
- 差分は表現や言語ローカライズに限定し、挙動や機能主張は一致させます。
- 日付や検証スナップショットも両ファイルで一致させます。

両ファイルで使う用語対応:

Canonical term | `README_ja.md` での対応語
---|---
deterministic demo replay | 決定論デモ
operator workflow | 運用ワークフロー
controlled execution | 制御実行
token-protected endpoint | トークン保護エンドポイント
optional AI assist path | 任意の AI 補助経路

## 検証済みの目的

このリポジトリで実装されている目的は次の通りです。

1. `br0` を中心とした内部セグメント（DHCP/NAT/forwarding）を構築し、運用面を提供する。
2. 正規化イベントを取り込み、NOC/SOC 状態を決定論的に評価する。
3. `observe` / `notify` / `throttle` / `redirect` / `isolate` を明示的に選択し、説明と監査情報を出力する。
4. ダッシュボード、トリアージ、Runbook、Mattermost 連携、決定論的デモを提供する。
5. 必要に応じて Ollama によるローカル LLM 補助を行う（デモのコア経路には必須ではない）。

根拠:
- ゲートウェイ基盤: `installer/internal/install_internal_network.sh`
- アクション選択: `py/azazel_edge/arbiter/action.py`
- Web/API 面: `azazel_edge_web/app.py`
- 決定論デモ: `bin/azazel-edge-demo`, `py/azazel_edge/demo/scenarios.py`
- AI ランタイム: `py/azazel_edge_ai/agent.py`, `systemd/azazel-edge-ai-agent.service`

## コアアーキテクチャ

1. **イベント取り込みと正規化**
   - Rust core が Suricata EVE (`AZAZEL_EVE_PATH`, 既定 `/var/log/suricata/eve.json`) を監視し、正規化 alert イベントを生成。
   - Unix socket (`/run/azazel-edge/ai-bridge.sock`) と JSONL ログへ転送可能。
2. **決定論評価**
   - NOC evaluator / SOC evaluator は `py/azazel_edge/evaluators/` 配下に実装。
   - Arbiter が却下理由付きで明示アクションを選択。
3. **運用プレーン**
   - Flask が dashboard (`/`), demo (`/demo`), ops workspace (`/ops-comm`), `/api/*` を提供。
   - Control daemon は `/run/azazel-edge/control.sock` で制御を受け付け。
4. **任意のAI補助プレーン**
   - AI agent が正規化イベント/手動問い合わせを処理し、advisory/metrics/audit JSONL を出力。
   - Ollama / Mattermost は compose ベーススクリプトで任意導入。

## 起動点とインターフェース

### サービス起動点
- Web app: `azazel_edge_web/app.py`（`systemd/azazel-edge-web.service` 経由で gunicorn 起動）
- Control daemon: `py/azazel_edge_control/daemon.py`（`systemd/azazel-edge-control-daemon.service`）
- AI agent: `py/azazel_edge_ai/agent.py`（`systemd/azazel-edge-ai-agent.service`）
- Rust core: `rust/azazel-edge-core/src/main.rs`（`systemd/azazel-edge-core.service`）
- EPD refresh timer: `systemd/azazel-edge-epd-refresh.timer`

### ウェブルート
- UI: `/`, `/demo`, `/ops-comm`
- Health: `/health`（トークン不要）
- CA メタ/ダウンロード: `/api/certs/azazel-webui-local-ca/meta`, `/api/certs/azazel-webui-local-ca.crt`

### 主要 API 群
- state/stream: `/api/state`, `/api/state/stream`
- control/mode/action: `/api/mode`, `/api/action`, `/api/wifi/*`, `/api/portal-viewer*`
- dashboard: `/api/dashboard/*`
- triage: `/api/triage/*`
- runbooks: `/api/runbooks*`
- demo: `/api/demo/*`
- AI/Mattermost: `/api/ai/*`, `/api/mattermost/*`

### ソケット
- Control socket: `/run/azazel-edge/control.sock`
- AI bridge socket: `/run/azazel-edge/ai-bridge.sock`

### 認証挙動
- 多くの `/api/*` エンドポイントはトークン検証あり。
- ただし token file が無い場合は `verify_token()` が通過させる実装。
- token 候補には `~/.azazel-edge/web_token.txt` を含む（`web_token_candidates()` 参照）。

## 機能トレーサビリティ

実装機能 | コード根拠 | 履歴根拠
---|---|---
ライブダッシュボードとデモ画面の分離 | `azazel_edge_web/app.py` (`/demo`), `azazel_edge_web/templates/demo.html` | PR #74, commit `d084852`
NOCランタイム投影の統合 | `py/azazel_edge_control/daemon.py`, `tests/test_noc_runtime_integration_v1.py` | PR #88, commit `8d3937a`
SOC状態次元の統合 | `py/azazel_edge/evaluators/soc.py`, `tests/test_soc_evaluator_v1.py` | PR #86, commits `a4a6fa0`, `bebdd13`
認証契約とi18n整備 | `azazel_edge_web/app.py`, `tests/test_api_auth_contract.py`, `tests/test_i18n_*` | PR #87, commit `72e9253`
初学者デフォルトUI | `azazel_edge_web/templates/index.html`, `azazel_edge_web/static/app.js` | PR #95, commit `7773624`

## 要件

### インストーラスクリプトが導入する主な依存
- コア/アプリスタック: `python3`, `python3-venv`, `network-manager`, `iw`, `dnsmasq`, `nginx`, `openssl`, `rustc`, `cargo` ほか
- セキュリティスタック（任意）: `docker.io`, `suricata`
- AIランタイム（任意）: `docker.io`, `qemu-user-static`, `binfmt-support`, `jq`

### Python 依存
`requirements/runtime.txt`:
- `Flask`
- `gunicorn`
- `rich`
- `textual`
- `Pillow`
- `requests`
- `PyYAML`

### 任意外部サービス
- Ollama (`security/docker-compose.ollama.yml`)
- Mattermost + PostgreSQL (`security/docker-compose.mattermost.yml`)
- OpenCanary (`security/docker-compose.yml`)

## インストールと再現

### 統合インストーラ

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

### アプリスタックのみ

```bash
sudo ENABLE_SERVICES=1 bash installer/internal/install_migrated_tools.sh
```

### AIランタイムのみ

```bash
sudo ENABLE_OLLAMA=1 ENABLE_MATTERMOST=1 bash installer/internal/install_ai_runtime.sh
```

導入後（既定）:
- 実体は `/opt/azazel-edge`
- ランチャは `/usr/local/bin`
- systemd unit は配置され、設定により有効化される

## 設定

### インストーラトグル
- `ENABLE_INTERNAL_NETWORK=1|0`
- `ENABLE_APP_STACK=1|0`
- `ENABLE_AI_RUNTIME=1|0`
- `ENABLE_DEV_REMOTE_ACCESS=1|0`
- `ENABLE_RUST_CORE=1|0`

### 主な設定ファイル
- `/etc/default/azazel-edge-web`（Web/Mattermost 環境変数）
- `/etc/default/azazel-edge-security`（例: `SURICATA_IFACE`）
- `/etc/azazel-edge/first_minute.yaml`（例: `suppress_auto_wifi`）

### 主要環境変数（抜粋）
- Web bind: `AZAZEL_WEB_HOST`, `AZAZEL_WEB_PORT`
- Rust core: `AZAZEL_EVE_PATH`, `AZAZEL_AI_SOCKET`, `AZAZEL_NORMALIZED_EVENT_LOG`, `AZAZEL_DEFENSE_ENFORCE`
- AI agent: `AZAZEL_OLLAMA_ENDPOINT`, `AZAZEL_LLM_MODEL_PRIMARY`, `AZAZEL_LLM_MODEL_DEGRADED`
- Mattermost command: `AZAZEL_MATTERMOST_COMMAND_TRIGGER`, `AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE`
- Runbook 制御実行ゲート: `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC`

### トークン認証
- `X-AZAZEL-TOKEN`（または `X-Auth-Token` / `?token=`）を受け付ける。
- token file 未配置時は保護 API でも実質オープンになる実装。

## 使い方

### サービス状態確認
```bash
sudo systemctl status \
  azazel-edge-control-daemon \
  azazel-edge-web \
  azazel-edge-ai-agent \
  azazel-edge-core
```

### 主要アクセス先（既定構成）
- Webバックエンド: `http://127.0.0.1:8084/`
- 内部ネットワーク + HTTPSプロキシ導入時: `https://172.16.0.254/`
- Mattermost（有効時）: `http://172.16.0.254:8065/`

### API 例
```bash
TOKEN="$(cat ~/.azazel-edge/web_token.txt)"
curl -sS -H "X-AZAZEL-TOKEN: ${TOKEN}" http://127.0.0.1:8084/api/state | jq .
```

### 決定論デモ

```bash
bin/azazel-edge-demo list
bin/azazel-edge-demo run mixed_correlation_demo
```

### RunbookブローカーCLI
```bash
python3 py/azazel_edge_runbook_broker.py list
python3 py/azazel_edge_runbook_broker.py show rb.noc.service.status.check
python3 py/azazel_edge_runbook_broker.py propose --question "Wi-Fi intermittent disconnects"
```

## 開発

### ローカルセットアップ
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip wheel setuptools
pip install -r requirements/runtime.txt
```

### systemdを使わない直接起動
```bash
PYTHONPATH=. python3 azazel_edge_web/app.py
PYTHONPATH=. python3 py/azazel_edge_control/daemon.py
PYTHONPATH=. python3 py/azazel_edge_ai/agent.py
```

補足:
- 一部テストは `azazel_edge_web` をトップレベル import するため `PYTHONPATH=.` が必要。
- `py/azazel_edge_status.py` は常駐表示系（Ctrl-C で終了）で、一般的な `--help` CLI ではない。

## テスト

実行:
```bash
PYTHONPATH=. .venv/bin/pytest -q
```

2026-03-15 検証結果: **183 passed in 3.57s**

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

## 運用・デプロイ

### 含まれるsystemdユニット
- `azazel-edge-control-daemon.service`
- `azazel-edge-web.service`
- `azazel-edge-ai-agent.service`
- `azazel-edge-core.service`
- `azazel-edge-epd-refresh.service`
- `azazel-edge-epd-refresh.timer`
- `azazel-edge-opencanary.service`
- `azazel-edge-suricata.service`

### セキュリティ/AIスタック導入スクリプト
- セキュリティスタック: `installer/internal/install_security_stack.sh`
- AIランタイム: `installer/internal/install_ai_runtime.sh`
- Composeアセット: `security/`

### 主なランタイムログ/成果物
- `/var/log/azazel-edge/normalized-events.jsonl`
- `/var/log/azazel-edge/ai-events.jsonl`
- `/var/log/azazel-edge/ai-llm.jsonl`
- `/var/log/azazel-edge/triage-audit.jsonl`
- `/run/azazel-edge/ui_snapshot.json`

## ドキュメント

- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [AI build and operation detail](docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md)
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)
- [Demo guide](docs/DEMO_GUIDE.md)
- [Demo guide (Japanese)](docs/DEMO_GUIDE_JA.md)

## 制約

- Rust enforcement は既定でプレースホルダ:
  - `systemd/azazel-edge-core.service` で `AZAZEL_DEFENSE_ENFORCE=false`
  - Rust の `maybe_enforce()` はフックのみ
- `python3 py/azazel_edge_epd.py --help` は現時点で `ValueError: incomplete format` で失敗
- CI workflow は未配置（`.github/workflows` が見つからない）
- ルート `LICENSE` ファイルは未配置

## 既知の問題（2026-03-15 時点）

GitHub の open issue 例:
- #96 P1着手: Azazelらしさラインの実装分解
- #97 P1-1: M.I.O.文体統一レイヤ
- #98 P1-2: Decision Trust Capsule
- #99 P1-3: Handoff Brief Pack
- #100 P1-4: 初動Progress Checklist
- #101 P1-5: Beginnerオンボーディング

## 現在の状態

- 直近のマージ済み PR: #95, #94, #88, #87, #86
- Python test module 数: **44**
- runbook YAML 数: **15**
- 利用可能なデモ: `mixed_correlation_demo`, `noc_degraded_demo`, `soc_redirect_demo`

## 検証ノート

2026-03-15 検証:
- `PYTHONPATH=. .venv/bin/pytest -q` -> `183 passed`
- `find tests -maxdepth 1 -type f -name 'test_*.py' | wc -l` -> `44`
- `find runbooks -type f -name '*.yaml' | wc -l` -> `15`
- `python3 py/azazel_edge_epd.py --help` -> 失敗（`ValueError: incomplete format`）
- GitHub open issue に #96-#101 を確認（`gh issue list --state open`）

## ライセンス

このリポジトリのルートには `LICENSE` ファイルが存在しません（status: unknown）。
