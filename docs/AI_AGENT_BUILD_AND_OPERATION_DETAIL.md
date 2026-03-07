# エージェントAI構築手順書（詳細）

最終更新: 2026-03-06  
対象: Azazel-Edge（Raspberry Pi 5 / arm64）

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
  - Web API: `GET /api/runbooks`, `GET /api/runbooks/<id>`, `POST /api/runbooks/execute`
- 未実装（今後）:
  - Runbook reviewer多層評価
  - controlled_exec 系の承認実行層
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

## 8. 検証手順（実運用相当）

### 8.1 監視

```bash
systemctl is-active azazel-edge-ai-agent
jq '{processed_events,llm_requests,llm_completed,llm_failed,llm_schema_invalid_count,ops_requests,ops_completed,ops_schema_invalid_count,last_error}' /run/azazel-edge/ai_metrics.json
tail -n 5 /var/log/azazel-edge/ai-llm.jsonl
```

### 8.2 疑似イベント投入（曖昧帯）

```bash
python3 - <<'PY'
import json, socket
sock='/run/azazel-edge/ai-bridge.sock'
ev={"normalized":{"sid":996001,"severity":3,"attack_type":"port scan","category":"attempted-recon","action":"allowed","target_port":80,"protocol":"tcp","src_ip":"10.66.0.1","dst_ip":"10.0.0.1"}}
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.connect(sock)
    s.sendall((json.dumps(ev)+'\n').encode())
print("event_sent")
PY
```

結果確認:

```bash
tail -n 1 /var/log/azazel-edge/ai-llm.jsonl
jq '{llm_requests,llm_completed,llm_failed,last_error}' /run/azazel-edge/ai_metrics.json
```

### 8.3 テスト実行

```bash
python3 -m unittest -v tests/test_phase5_operational_hardening.py
```

## 9. 異常時対応

- WebUI値が検証残りで高止まり:

```bash
sudo systemctl stop azazel-edge-ai-agent
sudo bash -lc ': > /var/log/azazel-edge/ai-events.jsonl; : > /var/log/azazel-edge/ai-llm.jsonl; : > /var/log/azazel-edge/ai-deferred.jsonl; rm -f /run/azazel-edge/ui_snapshot.json /run/azazel-edge/ai_metrics.json /run/azazel-edge/ai_advisory.json /run/azazel-edge/ai_runtime_policy.json'
sudo systemctl start azazel-edge-ai-agent
```

- LLM失敗/遅延調査:

```bash
jq '{llm_requests,llm_completed,llm_failed,llm_fallback_count,llm_schema_invalid_count,ops_schema_invalid_count,llm_latency_ms_last,last_error,policy_mode}' /run/azazel-edge/ai_metrics.json
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

```bash
curl http://127.0.0.1:8084/api/runbooks
curl http://127.0.0.1:8084/api/runbooks/rb.noc.default-route.check
curl http://127.0.0.1:8084/api/runbooks/rb.user.first-contact.network-issue/review
curl -X POST http://127.0.0.1:8084/api/runbooks/propose \
  -H 'Content-Type: application/json' \
  -d '{"question":"DNS が引けない","audience":"beginner"}'
curl -X POST http://127.0.0.1:8084/api/runbooks/act \
  -H 'Content-Type: application/json' \
  -d '{"runbook_id":"rb.ops.logs.ai.recent","action":"preview","args":{"lines":5},"question":"AIログを確認したい"}'
curl -X POST http://127.0.0.1:8084/api/runbooks/execute \
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

```bash
sudo docker run --privileged --rm tonistiigi/binfmt --install amd64
docker compose -f security/docker-compose.mattermost.yml up -d
docker compose -f security/docker-compose.mattermost.yml ps
```

初回アクセス:
- `http://<host>:8065` で管理者アカウントを作成
- チーム/チャンネルを作成

注記:
- 現行の Mattermost 公式イメージは Pi5(arm64) で `linux/amd64` エミュレーション起動。
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
  - `AZAZEL_MATTERMOST_COMMAND_TOKEN` を設定し、Mattermost 側の token と一致させる
  - 設定先は `/etc/default/azazel-edge-web`
  - `sender` (optional)
  - `source` (optional)
  - `context` (optional object)
- 動作:
  - WebUIが `/run/azazel-edge/ai-bridge.sock` に `action=manual_query` を送信
  - `azazel-edge-ai-agent` が Ops 系モデルで応答生成
  - 応答JSONを同期返却
- `/api/mattermost/message` では `ask_ai=true` 指定で投稿内容を同時にAI問い合わせし、応答を Mattermost に追記可能

設定例:

```bash
sudo tee -a /etc/default/azazel-edge-web >/dev/null <<'EOF'
AZAZEL_MATTERMOST_COMMAND_TOKEN=replace-with-mattermost-token
EOF
sudo systemctl restart azazel-edge-web
```

slash command 例:
- Command Trigger: `/azops`
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
AZAZEL_MATTERMOST_COMMAND_TOKEN=
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
- ログイン情報は `/etc/azazel-edge/mattermost-credentials.env`（権限 `0600`）に保管する。

反映:

```bash
sudo systemctl restart azazel-edge-web
```
