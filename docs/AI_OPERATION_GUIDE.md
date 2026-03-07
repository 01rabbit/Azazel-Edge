# Azazel-Edge AI運用要領（現行）

最終更新: 2026-03-06

詳細手順: `docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md`

## 1. 目的

- Suricataアラートのうち「曖昧帯」のみLLMで補助判断する。
- クリティカルはLLM判定を待たずに初動し、必要時にOps Coachを走らせる。
- 同居運用でSuricata優先を維持し、LLM暴走で本体機能を阻害しない。

## 2. モデル構成（Ollama）

- Analyst Primary: `qwen3.5:2b`
- Analyst Degraded: `qwen3.5:0.8b`
- Ops Coach Primary: `qwen3.5:2b`
- Ops Coach Fallback Chain: `qwen3.5:2b,qwen3.5:0.8b`
- 不使用: `qwen3.5:4b`（削除済み）

確認コマンド:

```bash
sudo docker exec azazel-edge-ollama ollama list
```

## 3. 判定フロー（運用）

1. Tactical EngineがSuricataイベントをスコア化
2. `risk_score` が曖昧帯 (`60-79`) の場合のみ Analyst LLM を実行
3. 低スコアでも相関条件（同一送信元の短時間反復/シグネチャ多様化）を満たした場合は Analyst LLM を強制実行
4. 非曖昧はLLMをスキップ
5. `risk_score >= 85` は direct critical としてOps Coachキュー投入
6. Ops Coachはメモリ/スワップ閾値を満たす場合のみ実行

## 4. 現行しきい値

- LLM曖昧帯:
  - `AZAZEL_LLM_AMBIG_MIN=60`
  - `AZAZEL_LLM_AMBIG_MAX=79`
  - `AZAZEL_LLM_AMBIG_MIN_DEGRADED=70`
- 相関エスカレーション:
  - `AZAZEL_CORR_ENABLED=1`
  - `AZAZEL_CORR_WINDOW_SEC=300`
  - `AZAZEL_CORR_REPEAT_THRESHOLD=4`
  - `AZAZEL_CORR_SID_DIVERSITY_THRESHOLD=3`
  - `AZAZEL_CORR_MIN_RISK_SCORE=20`
  - `AZAZEL_CORR_MAX_HISTORY_PER_SRC=32`
- キュー:
  - `AZAZEL_LLM_QUEUE_MAX=8`
- LLM実行:
  - `AZAZEL_LLM_TIMEOUT_SEC=45`
  - `AZAZEL_LLM_NUM_THREAD=2`
  - `AZAZEL_LLM_NUM_CTX=256`
  - `AZAZEL_LLM_NUM_PREDICT=120`
  - `AZAZEL_LLM_KEEP_ALIVE=5m`
- Ops Guard:
  - `AZAZEL_OPS_MIN_MEM_AVAILABLE_MB=1400`
  - `AZAZEL_OPS_MAX_SWAP_USED_MB=512`
  - `AZAZEL_OPS_ESCALATE_MIN_RISK=70`
  - `AZAZEL_OPS_ESCALATE_LOW_CONF=0.60`
  - `AZAZEL_OPS_ESCALATE_COOLDOWN_SEC=180`
  - `AZAZEL_OPS_KEEP_ALIVE=0s`
  - `AZAZEL_OPS_NUM_PREDICT=80`

## 5. 監視対象ファイル

- ソケット: `/run/azazel-edge/ai-bridge.sock`
- 最新助言: `/run/azazel-edge/ai_advisory.json`
- UIスナップショット: `/run/azazel-edge/ui_snapshot.json`
- メトリクス: `/run/azazel-edge/ai_metrics.json`
- イベントログ: `/var/log/azazel-edge/ai-events.jsonl`
- LLM結果ログ: `/var/log/azazel-edge/ai-llm.jsonl`
- Deferredログ: `/var/log/azazel-edge/ai-deferred.jsonl`
- Ops連携UI: `/ops-comm`（Mattermost連携専用サイト）

## 6. 日常確認手順

```bash
systemctl is-active azazel-edge-ai-agent
jq '{processed_events,llm_requests,llm_completed,llm_failed,llm_schema_invalid_count,ops_requests,ops_completed,ops_schema_invalid_count,last_error}' /run/azazel-edge/ai_metrics.json
tail -n 5 /var/log/azazel-edge/ai-llm.jsonl
```

## 7. 異常時の一次対応

### A. WebUI数値が異常に高い

- 多くは検証イベントの累積値。
- クリア手順:

```bash
sudo systemctl stop azazel-edge-ai-agent
sudo bash -lc ': > /var/log/azazel-edge/ai-events.jsonl; : > /var/log/azazel-edge/ai-llm.jsonl; : > /var/log/azazel-edge/ai-deferred.jsonl; rm -f /run/azazel-edge/ui_snapshot.json /run/azazel-edge/ai_metrics.json /run/azazel-edge/ai_advisory.json /run/azazel-edge/ai_runtime_policy.json'
sudo systemctl start azazel-edge-ai-agent
```

### B. LLM失敗/遅延が増加

```bash
jq '{llm_requests,llm_completed,llm_failed,llm_fallback_count,llm_schema_invalid_count,ops_schema_invalid_count,llm_latency_ms_last,last_error,policy_mode}' /run/azazel-edge/ai_metrics.json
sudo journalctl -u azazel-edge-ai-agent -n 100 --no-pager
sudo docker logs --tail 100 azazel-edge-ollama
```

## 8. 設定反映手順

```bash
sudo install -m 0644 systemd/azazel-edge-ai-agent.service /etc/systemd/system/azazel-edge-ai-agent.service
sudo systemctl daemon-reload
sudo systemctl restart azazel-edge-ai-agent
sudo systemctl show azazel-edge-ai-agent --property=Environment --no-pager
```

## 9. 運用ルール

- Suricata優先。LLMは補助であり、検知可用性を犠牲にしない。
- モデル追加は「メモリ上限・失敗率・遅延」を実測してから採用する。
- 同居運用では `4b` 以上を常用しない。上位モデルは別ホスト分離を前提とする。

## 10. 実行ロードマップ（2026-03-05更新）

- Phase A（運用固定）: 完了
  - `2b` 主系 / `0.8b` フェイルオーバー / `4b` 非採用を固定
- Phase B（相関エスカレーション）: 完了
  - 同一 `src_ip` の短時間反復、`sid` 多様化を LLM実行条件へ追加
- Phase C（JSONスキーマ厳格化）: 完了
  - Analyst/Opsの型・必須項目・文字列長を検証し、不正応答はフォールバック
- Phase D（定期モデル評価）: 未着手
  - 半年ごとのモデル比較（遅延/失敗率/常駐メモリ）を運用手順化予定
- Phase E（PicoClaw再評価）: 保留
  - マルチエージェント常時運用化時点で再評価

## 11. Mattermost運用

- ログイン情報の保管先（ローカル機密ファイル）: `/etc/azazel-edge/mattermost-credentials.env`（`0600`）
- WebUIのMattermost起動URL: `AZAZEL_MATTERMOST_OPEN_URL`（未設定時は `AZAZEL_MATTERMOST_BASE_URL` を利用）
- 運用の主画面: Mattermostダッシュボード
- WebUI(`/ops-comm`)の役割: 監視画面からの簡易投稿・疎通確認・直近メッセージ参照
