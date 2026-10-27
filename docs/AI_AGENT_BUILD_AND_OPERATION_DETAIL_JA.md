# エージェントAI構築手順書（詳細）

最終更新: 2026-10-27  
対象: Azazel-Edge（Raspberry Pi 5 / arm64）

関連人格設計: `docs/MIO_PERSONA_PROFILE.md`

## 1. 目的

- Suricataアラートの補助判定とSOC/NOC支援を、`azazel-edge-ai-agent` 中心で実装する。
- LLMは補助用途に限定し、最終制御はTactical Engine側に残す。
- PicoClawは現時点では本番経路に組み込まない（将来再評価）。

## 2. 現在の実装ステータス

- 実装済み:
  - Ollama + `qwen3.5:2b` / `qwen3.5:0.8b`
  - 曖昧帯判定（`60-79`）でのLLM起動
  - 相関エスカレーション（反復・SID多様化）
  - Opsエスカレーション（高リスク直行 + メモリ/スワップガード）
  - Analyst/Ops JSONスキーマ検証
  - Runbookレジストリ（YAML）/ ローダ / ブローカー骨格
  - Runbook reviewer 多層評価
  - `controlled_exec` の安全ゲート
  - 手動質問 API (`/api/ai/ask`)
  - Mattermost slash command (`/mio`, legacy alias `/azops`)
  - Web API: `GET /api/runbooks`, `GET /api/runbooks/<id>`, `GET /api/runbooks/<id>/review`, `POST /api/runbooks/propose`, `POST /api/runbooks/act`, `POST /api/runbooks/execute`
- 未実装（今後）:
  - 多段対話ベースの聞き取り
  - 初心者向け症状別ウィザード
  - 半年ごとのモデル比較運用の自動化

## 3. 前提条件

1. 64bit Linux（Raspberry Pi OS / Debian系）で `sudo` 権限があること。  
2. Suricataが動作し、JSONイベントが取得可能であること。  
3. Docker/Composeが利用可能であること。  
4. `azazel-edge-ai-agent` が systemd 管理される構成であること。

## 4. Ollama導入・モデル準備

現行は `security/docker-compose.ollama.yml` を利用する。

```bash
docker compose -f security/docker-compose.ollama.yml up -d
sudo docker exec azazel-edge-ollama ollama pull qwen3.5:2b
sudo docker exec azazel-edge-ollama ollama pull qwen3.5:0.8b
sudo docker exec azazel-edge-ollama ollama rm qwen3.5:4b || true
sudo docker exec azazel-edge-ollama ollama list
```

期待:
- `qwen3.5:2b` と `qwen3.5:0.8b` が表示される
- `qwen3.5:4b` は表示されない

## 4.1 再現インストール

現行環境は unified installer で再現可能。

```bash
sudo ENABLE_INTERNAL_NETWORK=1 \
     ENABLE_APP_STACK=1 \
     ENABLE_AI_RUNTIME=1 \
     ENABLE_DEV_REMOTE_ACCESS=0 \
     bash installer/internal/install_all.sh
```

この経路で再現されるもの:
- `/opt/azazel-edge` 配下のアプリ本体
- WebUI/TUI/EPD/control/AI agent/systemd
- Runbook レジストリと broker
- nginx HTTPS reverse proxy
- Ollama コンテナ
- `qwen3.5:2b` / `qwen3.5:0.8b`
- Mattermost / PostgreSQL コンテナ（x86_64 のみ。aarch64（Raspberry Pi 5）では既定で入らない。公式イメージは amd64 だけで、16K ページのカーネル上の qemu-user での動作は未確認のため。試すときは `ENABLE_MATTERMOST=1` を明示する）
- `azazelops` ユーザ、`azazelops` チーム、`soc-noc` チャンネル
- WebUI 用 bot token / incoming webhook / slash command `/mio`（legacy alias `/azops`）
- `/etc/azazel-edge/mattermost-credentials.env`
- `/etc/azazel-edge/mattermost-command-token`

## 5. AIエージェント統合

対象ファイル:
- `py/azazel_edge_ai/agent.py`
- `systemd/azazel-edge-ai-agent.service`

反映手順:

```bash
sudo install -m 0644 py/azazel_edge_ai/agent.py /opt/azazel-edge/py/azazel_edge_ai/agent.py
sudo install -m 0644 systemd/azazel-edge-ai-agent.service /etc/systemd/system/azazel-edge-ai-agent.service
sudo systemctl daemon-reload
sudo systemctl restart azazel-edge-ai-agent
systemctl is-active azazel-edge-ai-agent
```

## 6. 推奨運用パラメータ（現行）

`/etc/systemd/system/azazel-edge-ai-agent.service` の Environment で設定:

- モデル:
  - `AZAZEL_LLM_MODEL_PRIMARY=qwen3.5:2b`
  - `AZAZEL_LLM_MODEL_DEGRADED=qwen3.5:0.8b`
  - `AZAZEL_OPS_MODEL=qwen3.5:2b`
  - `AZAZEL_OPS_MODEL_CHAIN=qwen3.5:2b,qwen3.5:0.8b`
- 曖昧帯:
  - `AZAZEL_LLM_AMBIG_MIN=60`
  - `AZAZEL_LLM_AMBIG_MAX=79`
  - `AZAZEL_LLM_AMBIG_MIN_DEGRADED=70`
- 相関:
  - `AZAZEL_CORR_ENABLED=1`
  - `AZAZEL_CORR_WINDOW_SEC=300`
  - `AZAZEL_CORR_REPEAT_THRESHOLD=4`
  - `AZAZEL_CORR_SID_DIVERSITY_THRESHOLD=3`
  - `AZAZEL_CORR_MIN_RISK_SCORE=20`
  - `AZAZEL_CORR_MAX_HISTORY_PER_SRC=32`
- 実行制約:
  - `AZAZEL_LLM_QUEUE_MAX=8`
  - `AZAZEL_LLM_TIMEOUT_SEC=45`
  - `AZAZEL_LLM_NUM_THREAD=2`
  - `AZAZEL_LLM_NUM_CTX=256`
  - `AZAZEL_LLM_NUM_PREDICT=120`
  - `AZAZEL_MANUAL_QUERY_TIMEOUT_SEC=18`
  - `AZAZEL_MANUAL_TOTAL_TIMEOUT_SEC=20`
  - `AZAZEL_MANUAL_MODEL_CHAIN=qwen3.5:0.8b,qwen3.5:2b`
  - `AZAZEL_MANUAL_NUM_CTX=192`
  - `AZAZEL_MANUAL_NUM_PREDICT=64`
  - `AZAZEL_MANUAL_KEEP_ALIVE=5m`
  - `AZAZEL_OPS_MIN_MEM_AVAILABLE_MB=1400`
  - `AZAZEL_OPS_MAX_SWAP_USED_MB=512`

## 7. LLM入出力方針

- Analyst:
  - 入力: 正規化アラート（SID, severity, risk_score, src/dst, category など）
  - 出力: `verdict/confidence/reason/suggested_action/escalation`
  - 検証: 型・範囲・長さ不正時はフォールバック
- Ops:
  - 出力: `runbook_id/summary/operator_note` を正規化
  - 検証: 必須項目不足や不正値は拒否

## 7.1 M.I.O. 人格反映方針

- M.I.O. は「強いキャラクター」ではなく「運用人格」として使う
- プロンプトへ直接長文設定を流し込まず、以下へ分解して反映する
  - 文体
  - 出力順序
  - 初心者向け制約
  - 危険操作時の抑制
- 具体的には次を固定する
  - operator 向け: 状況、推定、確認、推奨 Runbook、判断
  - beginner 向け: 現在わかっていること、最大3手順、改善しない場合
  - 不確実時: 断定回避、追加確認要求、暫定安全策
- 詳細は `docs/MIO_PERSONA_PROFILE.md` を参照
- 共通症状 (`Wi-Fi`, `DNS`, `service`, `gateway`, `EPD`, `AI logs`) は `manual_router` で先に処理し、LLM を使わずに即時返答する
- 現段階での UI 実装対象は `ops-comm` と Mattermost を主とする
- Dashboard (`/`) は Azazel-Edge 向け再設計前提のため、M.I.O. の本格統合は後段で実施する

## 8. 検証手順（実運用相当）

### 8.1 監視

AI エージェントは `azazel-agent` アカウントで動き（Edge#471 段階 2）、自分のディレクトリにだけ書く。

- `/run/azazel-edge-agent/`: `ai_metrics.json`・`ai_advisory.json`・`ai_runtime_policy.json`・`ai_snapshot.json`（2750 `azazel-agent:azazel-web`）
- `/var/log/azazel-edge/ai/`: `ai-events.jsonl`・`ai-llm.jsonl`・`ai-deferred.jsonl`・`ai-audit.jsonl` など（2750 `azazel-agent:azazel-web`）
- `/run/azazel-edge-ai/ai-bridge.sock`: core（root）からのイベント受け口（ディレクトリ 0700・ソケット 0600 `azazel-agent`）
- `/run/azazel-edge-agent-query/agent-query.sock`: Web UI からの `manual_query` 専用（root と `azazel-web` だけ）

どれも一般ユーザーからは読めないので、確認は `sudo` で行う。

```bash
systemctl is-active azazel-edge-ai-agent
sudo jq '{processed_events,llm_requests,llm_completed,llm_failed,llm_schema_invalid_count,ops_requests,ops_completed,ops_schema_invalid_count,last_error}' /run/azazel-edge-agent/ai_metrics.json
sudo tail -n 5 /var/log/azazel-edge/ai/ai-llm.jsonl
```

### 8.2 疑似イベント投入（曖昧帯）

`ai-bridge.sock` には root（と `azazel-agent`）しか接続できない。一般ユーザーで実行すると
`PermissionError: [Errno 13]`（EACCES）になるので、`sudo` で実行する。

```bash
sudo python3 - <<'PY'
import json, socket
sock='/run/azazel-edge-ai/ai-bridge.sock'
ev={"normalized":{"sid":996001,"severity":3,"attack_type":"port scan","category":"attempted-recon","action":"allowed","target_port":80,"protocol":"tcp","src_ip":"10.66.0.1","dst_ip":"10.0.0.1"}}
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.connect(sock)
    s.sendall((json.dumps(ev)+'\n').encode())
print("event_sent")
PY
```

結果確認:

```bash
sudo tail -n 1 /var/log/azazel-edge/ai/ai-llm.jsonl
sudo jq '{llm_requests,llm_completed,llm_failed,last_error}' /run/azazel-edge-agent/ai_metrics.json
```

### 8.3 テスト実行

```bash
python3 -m unittest -v tests/test_phase5_operational_hardening.py
```

## 9. 異常時対応

- WebUI値が検証残りで高止まり:

```bash
sudo systemctl stop azazel-edge-ai-agent
sudo bash -lc ': > /var/log/azazel-edge/ai/ai-events.jsonl; : > /var/log/azazel-edge/ai/ai-llm.jsonl; : > /var/log/azazel-edge/ai/ai-deferred.jsonl; rm -f /run/azazel-edge-agent/ai_metrics.json /run/azazel-edge-agent/ai_advisory.json /run/azazel-edge-agent/ai_runtime_policy.json /run/azazel-edge-agent/ai_snapshot.json /run/azazel-edge/ui_snapshot.json'
sudo systemctl start azazel-edge-ai-agent
```

`ai-audit.jsonl`・`core-decision-audit.jsonl`（監査の連鎖）は消さない。`/run/azazel-edge/ui_snapshot.json` は control daemon が作り直す（AI の欄はエージェントの `ai_snapshot.json` から取り込む）。

- LLM失敗/遅延調査:

```bash
sudo jq '{llm_requests,llm_completed,llm_failed,llm_fallback_count,llm_schema_invalid_count,ops_schema_invalid_count,llm_latency_ms_last,last_error,policy_mode}' /run/azazel-edge-agent/ai_metrics.json
sudo journalctl -u azazel-edge-ai-agent -n 100 --no-pager
sudo docker logs --tail 100 azazel-edge-ollama
```

## 10. Runbook基盤

実装済み:
- `runbooks/**/*.yaml` に Runbook 定義を配置
- `py/azazel_edge/runbooks.py` でロード/検証
- `py/azazel_edge/runbook_review.py` で複数専門家レビューを実装
- `py/azazel_edge_runbook_broker.py` で CLI 実行
- Web API から一覧/詳細/レビュー/提案/承認/実行が可能

初期Runbook:
- `rb.noc.service.status.check`
- `rb.noc.service.restart.controlled`
- `rb.noc.default-route.check`
- `rb.noc.ui-snapshot.check`
- `rb.noc.dhcp.failure.check`
- `rb.noc.dns.failure.check`
- `rb.ops.logs.ai.recent`
- `rb.ops.epd.state.check`
- `rb.soc.alert.triage.basic`
- `rb.soc.contain.recommend`
- `rb.user.first-contact.network-issue`
- `rb.user.reconnect-guide`
- `rb.user.device-onboarding-guide`
- `rb.user.incident-status-brief`

Reviewer構成:
- `soc_analyst_ai`
- `noc_operator_ai`
- `user_support_ai`
- `security_architect_ai`
- `runbook_qa_ai`

CLI例:

```bash
/usr/local/bin/azazel-edge-runbook-broker list
/usr/local/bin/azazel-edge-runbook-broker show rb.noc.service.status.check
/usr/local/bin/azazel-edge-runbook-broker review rb.user.first-contact.network-issue
/usr/local/bin/azazel-edge-runbook-broker propose --question 'Wi-Fi に繋がらない'
/usr/local/bin/azazel-edge-runbook-broker execute rb.ops.logs.ai.recent --args-json '{"lines":5}'
```

Web API例:

Web UI の API はトークンが要る（無い・違うと HTTP 403。一部の API は 401）。トークンは
`/etc/azazel-edge/web_token.txt`（`0640 root:azazel-web`、読むには `sudo`）にある。
コマンドラインの引数やシェル履歴に出さないよう、`X-AZAZEL-TOKEN` ヘッダを curl の
標準入力から渡す（`-H @-`）。

```bash
auth() { sudo sed -n '1s/^/X-AZAZEL-TOKEN: /p' /etc/azazel-edge/web_token.txt; }
auth | curl -sS -H @- http://127.0.0.1:8084/api/runbooks
auth | curl -sS -H @- http://127.0.0.1:8084/api/runbooks/rb.noc.default-route.check
auth | curl -sS -H @- http://127.0.0.1:8084/api/runbooks/rb.user.first-contact.network-issue/review
auth | curl -sS -H @- -X POST http://127.0.0.1:8084/api/runbooks/propose \
  -H 'Content-Type: application/json' \
  -d '{"question":"DNS が引けない","audience":"beginner"}'
auth | curl -sS -H @- -X POST http://127.0.0.1:8084/api/runbooks/act \
  -H 'Content-Type: application/json' \
  -d '{"runbook_id":"rb.ops.logs.ai.recent","action":"preview","args":{"lines":5},"question":"AIログを確認したい"}'
auth | curl -sS -H @- -X POST http://127.0.0.1:8084/api/runbooks/execute \
  -H 'Content-Type: application/json' \
  -d '{"runbook_id":"rb.ops.logs.ai.recent","args":{"lines":5},"dry_run":true}'
```

レビュー方針:
- Pi 5 同居前提のため reviewer を別 LLM 多重起動にはしない
- 代わりに複数専門家ロールごとのポリシー評価を固定化する
- 初心者向け Runbook は `user_message_template` と段階的手順を必須とする
- 封じ込めや認証系の Runbook は approval が無い場合 reject する
- `runbook-events.jsonl` に preview/approve/execute を記録し、承認履歴を残す

## 11. 将来拡張（Runbookブローカー）

将来の設計方針:
- `runbook_id` + `args` のみLLMに返させる
- 実コマンドはブローカーがYAML定義を検証して実行
- 実行権限は `sudoers` で最小化

現状:
- `read_only` Runbook は broker から実行可能
- `operator_guidance` は提案のみ
- `controlled_exec` は `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=1` + approval 条件でのみ許可
- LLMが直接コマンド実行しない原則は維持

有効化例:

```bash
sudo tee -a /etc/default/azazel-edge-web >/dev/null <<'EOF'
AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=1
EOF
sudo systemctl restart azazel-edge-web
```

## 12. Mattermost連携（WebUI専用サイト）

### 11.1 MattermostをDocker導入

> aarch64（Raspberry Pi 5）では `install_ai_runtime.sh` は既定で Mattermost を入れない（`ENABLE_MATTERMOST` の既定が `0`。x86_64 は `1`）。公式イメージは amd64 だけで、Pi 5 の 16K ページのカーネル上で qemu-user 経由で動くかは未確認のため。試すときは `sudo ENABLE_OLLAMA=0 ENABLE_MATTERMOST=1 installer/internal/install_ai_runtime.sh` とし、結果を `docs/HARDWARE_FIRST_RUN_CHECKLIST_JA.md` の 3.8 に記録する。

```bash
sudo docker run --privileged --rm tonistiigi/binfmt --install amd64
# DB パスワードを機器ごとにランダム生成（/etc/azazel-edge/mattermost-db.env、0600 root）。
# compose ファイルはこのファイルからだけパスワードを読む。無いと起動しない。
sudo installer/internal/mattermost_db_secret.sh
sudo docker compose -f security/docker-compose.mattermost.yml up -d
sudo docker compose -f security/docker-compose.mattermost.yml ps
# 管理者・チーム・チャンネル・Bot トークン・Webhook と LAN 向け nginx を用意
sudo installer/internal/provision_mattermost_workspace.sh
```

公開範囲（Edge#477）:
- コンテナは `127.0.0.1:18065` にだけ公開する（Docker が全インターフェースに公開したポートはホストのファイアウォールを通らず、WAN からも届いていた）。
- LAN からは nginx（`provision_mattermost_workspace.sh` が `/etc/nginx/sites-available/azazel-edge-mattermost.conf` を書く）経由で `http://172.16.0.254:8065` に届く。nginx は `172.16.0.0/24` と loopback だけを通し、それ以外には 403 を返す。nginx が無い場合は loopback からだけ使える。
- 以前の版で全インターフェースに公開したコンテナが 8065 を握っている間は nginx の設定を入れず、エラーで終わる。新しい compose ファイルでコンテナを作り直してから `provision_mattermost_workspace.sh` をもう一度実行する。
- このリポジトリはホストの nftables に input の規則を書かない（`azazel_internal` は nat と forward だけ）。OS の nftables で input を絞っている機器では、LAN から 8065/tcp（nginx）を許可する必要がある。実機で確認する。

資格情報（Edge#477）:
- DB パスワード: `/etc/azazel-edge/mattermost-db.env`（0600 root）。以前の固定値で作られた DB は、`mattermost_db_secret.sh` が新しいランダム値に置き換えてからファイルを書く。
- 管理者パスワード: 初回にランダム生成して `/etc/azazel-edge/mattermost-credentials.env`（0600 root）の `MATTERMOST_PASSWORD=` に保存する。画面やログには出さない。確認はこのファイルを root で読む。

> **要対応（以前の版で導入した機器）**: 管理者パスワードが以前の版の固定値のままだと、`provision_mattermost_workspace.sh` は `[ACTION REQUIRED]` を出して終了コード 3 で終わる（成功表示はしない。パスワードは自動では変えない）。次の手順で変える。
>
> 1. LAN の端末から `http://172.16.0.254:8065` に管理者（`azazelops`）でログインし、Profile > Security > Password で新しいパスワードに変える。
> 2. 新しいパスワードを `/etc/azazel-edge/mattermost-credentials.env`（0600 root）の `MATTERMOST_PASSWORD=` に書く（`sudoedit` などで。コマンドラインの引数やシェル履歴に残さない）。
> 3. 導入に使った Azazel-Edge のチェックアウトで `sudo ENABLE_OLLAMA=0 ENABLE_MATTERMOST=1 installer/internal/install_ai_runtime.sh` を再実行し、エラーなく `[DONE]` で終わることを確かめる（ワークスペースの設定、slash command の登録、Web UI と AI エージェントの再起動まで通る。`ENABLE_OLLAMA=0` はモデルの再取得を省くだけ。`ENABLE_MATTERMOST=1` は Mattermost が既定で入らない aarch64 で要る）。`/opt/azazel-edge/install_ai_runtime.sh` の複製は、置き場所からリポジトリを見つけられないので使わない。`install_all.sh` 経由で導入した場合は、そこで止まったために `install_all.sh` の後の段階も走っていないので、有効にしていたもの（`set_dev_remote_access.sh`・`install_vector.sh`・`install_sensors.sh`）も `install_all.sh` と同じ環境変数で実行する。

- `provision_mattermost_workspace.sh` は、LAN から Mattermost に届かない状態では成功表示をせず終了コード 1 で終わる: nginx が入っていない場合（`install_https_proxy.sh` を実行してから）、以前のコンテナが 8065 を全インターフェースに公開したままの場合。どちらも上と同じく `install_ai_runtime.sh` を再実行する（コンテナの作り直しも含む）。

### 11.2 Mattermost slash command を導入

```bash
sudo installer/internal/provision_mattermost_command.sh
```

結果:
- trigger: `/mio`
- alias: `/azops`
- audience prefix:
  - `temp:` / `temporary:` / `beginner:`
  - `pro:` / `operator:` / `professional:`
- callback URL: `http://172.16.0.254/api/mattermost/command`
- token sync: `/etc/azazel-edge/mattermost-command-token`

注意:
- nginx は `/api/mattermost/command` のみ HTTP:80 で WebUI へ直通させる
- それ以外の WebUI パスは HTTPS へリダイレクトする
- Mattermost 側は `AllowedUntrustedInternalConnections=172.16.0.254` を設定して callback を許可する

注記:
- イメージは `mattermost/mattermost-team-edition:12.0.1` に固定（`latest` は使わない）。
- Mattermost の公式イメージ（team / enterprise とも）は Docker Hub に `linux/amd64` しかなく、arm64 版は無い（2026-10 時点で確認）。Pi5(arm64) では qemu-user による `linux/amd64` エミュレーションで動かす。遅く、Pi 5 の既定の 16K ページのカーネルではエミュレーションした amd64 プログラムが動かない可能性がある。実機での動作は確認していない。
- 初回起動はイメージが大きく時間がかかる。

### 11.2 WebUI専用サイト

- URL: `/ops-comm`
- 機能:
  - Mattermost到達性表示
  - WebUIからメッセージ送信
  - 手動質問 (`Ask AI + Post`) による `ai-agent` 対話呼び出し
  - 直近メッセージ一覧表示（Bot APIモード時）
  - Runbook 候補の preview / approve / execute

### 11.4 手動質問API（ai-agent連携）

- エンドポイント: `POST /api/ai/ask`
- 入力:
  - `question` (required)

### 11.5 Mattermost command 連携

- エンドポイント: `POST /api/mattermost/command`
- 用途:
  - Mattermost slash command または outgoing webhook から AI 質問を受ける
  - 返答には AI 要約と Runbook 候補/Review を含める
- 推奨:
  - token は `/etc/azazel-edge/mattermost-command-token`（`0640 root:azazel-web`。Web UI が `azazel-web` で読む）へ保存する
  - `AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE` は必要時のみ変更する
  - `sender` (optional)
  - `source` (optional)
  - `context` (optional object)
- 動作:
  - WebUIが `/run/azazel-edge-agent-query/agent-query.sock` に `action=manual_query` を送信（`ai-bridge.sock` は core 専用で、query socket が動いている間は `manual_query` を拒否する）
  - `azazel-edge-ai-agent` が Ops 系モデルで応答生成
  - 応答JSONを同期返却
- `/api/mattermost/message` では `ask_ai=true` 指定で投稿内容を同時にAI問い合わせし、応答を Mattermost に追記可能

設定例（通常は `provision_mattermost_command.sh` が作る。手で置く場合）:

```bash
# ファイルが無い場合だけ、空のファイルを 0640 root:azazel-web で作る
# （install は既存のファイルを空にするので、[ -e ] で守る）。それから sudoedit で
# token を書く（コマンドラインの引数やシェル履歴に残さない）。/etc/azazel-edge の
# 権限は変えない。
sudo test -e /etc/azazel-edge/mattermost-command-token \
  || sudo install -m 0640 -o root -g azazel-web /dev/null /etc/azazel-edge/mattermost-command-token
sudoedit /etc/azazel-edge/mattermost-command-token
sudo systemctl restart azazel-edge-web
```

注意: sudoedit は一時ファイルをユーザーの権限で編集するので、エディタのスワップ・
バックアップ・アンドゥのファイル（vim の `.swp` や `~` ファイルなど）に token が残る
ことがある。それらを作らない設定のエディタを使うか、編集後に残っていないことを確かめる。

slash command 例:
- Command Trigger: `/mio`
- Legacy Trigger: `/azops`
- Request URL: `https://<host>/api/mattermost/command`
- Method: `POST`

### 11.3 環境変数（`/etc/default/azazel-edge-web`）

```bash
AZAZEL_MATTERMOST_HOST=172.16.0.254
AZAZEL_MATTERMOST_PORT=8065
AZAZEL_MATTERMOST_BASE_URL=
AZAZEL_MATTERMOST_TEAM=azazelops
AZAZEL_MATTERMOST_CHANNEL=soc-noc
AZAZEL_MATTERMOST_OPEN_URL=
AZAZEL_MATTERMOST_WEBHOOK_URL=
AZAZEL_MATTERMOST_BOT_TOKEN=
AZAZEL_MATTERMOST_CHANNEL_ID=
AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE=/etc/azazel-edge/mattermost-command-token
AZAZEL_MATTERMOST_TIMEOUT_SEC=8
AZAZEL_MATTERMOST_FETCH_LIMIT=40
AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=0
```

運用モード:
- Webhookモード: `AZAZEL_MATTERMOST_WEBHOOK_URL` を設定
- Bot APIモード: `AZAZEL_MATTERMOST_BOT_TOKEN` と `AZAZEL_MATTERMOST_CHANNEL_ID` を設定

補足:
- Webhookモードは WebUI -> Mattermost 投稿が可能（読み戻しは不可）。
- Bot APIモードは投稿 + 直近メッセージ読み戻しが可能。
- `Open Mattermost` は `AZAZEL_MATTERMOST_OPEN_URL` を優先し、未設定時は `http://<AZAZEL_MATTERMOST_HOST>:<AZAZEL_MATTERMOST_PORT>/<team>/channels/<channel>` を自動生成する。
- Bot API（トークンとチャンネル ID）も Webhook も設定されていない（Mattermost 未導入）ときは、送信・読み戻し・handoff は HTTP 503（`not_configured: true`）を返し、状態は `configured: false`、`Open Mattermost` のリンクは表示しない（Edge#477）。
- ログイン情報は `/etc/azazel-edge/mattermost-credentials.env`（権限 `0600`）に保管する。

反映:

```bash
sudo systemctl restart azazel-edge-web
```
