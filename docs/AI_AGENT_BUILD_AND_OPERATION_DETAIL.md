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
- 未実装（今後）:
  - Runbookレジストリ + ブローカー実行層
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

## 10. 将来拡張（Runbookブローカー）

将来の設計方針:
- `runbook_id` + `args` のみLLMに返させる
- 実コマンドはブローカーがYAML定義を検証して実行
- 実行権限は `sudoers` で最小化

この層は未実装のため、現時点では「LLMが直接コマンド実行しない」原則を厳守する。

## 11. Mattermost連携（WebUI専用サイト）

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
  - 直近メッセージ一覧表示（Bot APIモード時）

### 11.3 環境変数（`/etc/default/azazel-edge-web`）

```bash
AZAZEL_MATTERMOST_BASE_URL=http://<host-ip>:8065
AZAZEL_MATTERMOST_OPEN_URL=http://<host-ip>:8065/<team>/channels/<channel>
AZAZEL_MATTERMOST_WEBHOOK_URL=
AZAZEL_MATTERMOST_BOT_TOKEN=
AZAZEL_MATTERMOST_CHANNEL_ID=
AZAZEL_MATTERMOST_TIMEOUT_SEC=8
AZAZEL_MATTERMOST_FETCH_LIMIT=40
```

運用モード:
- Webhookモード: `AZAZEL_MATTERMOST_WEBHOOK_URL` を設定
- Bot APIモード: `AZAZEL_MATTERMOST_BOT_TOKEN` と `AZAZEL_MATTERMOST_CHANNEL_ID` を設定

補足:
- Webhookモードは WebUI -> Mattermost 投稿が可能（読み戻しは不可）。
- Bot APIモードは投稿 + 直近メッセージ読み戻しが可能。
- `Open Mattermost` は `AZAZEL_MATTERMOST_OPEN_URL` を優先して開く。
- ログイン情報は `/etc/azazel-edge/mattermost-credentials.env`（権限 `0600`）に保管する。

反映:

```bash
sudo systemctl restart azazel-edge-web
```
