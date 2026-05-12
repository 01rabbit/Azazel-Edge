# Azazel-Edge AI運用要領（現行）

最終更新: 2026-03-10

詳細手順: `docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md`
人格設計: `docs/MIO_PERSONA_PROFILE.md`
P0 実装状態: `docs/P0_RUNTIME_ARCHITECTURE.md`

## 1. 目的

- Suricataアラートのうち「曖昧帯」のみLLMで補助判断する。
- クリティカルはLLM判定を待たずに初動し、必要時にOps Coachを走らせる。
- 同居運用でSuricata優先を維持し、LLM暴走で本体機能を阻害しない。

## 1.1 P0 との関係

- first-minute triage は Tactical Engine が担う
- second-pass の deterministic context は Evidence Plane と NOC/SOC evaluator が担う
- AI は補助に限定し、一次判断経路とは分離して扱う
- P0 の判断パイプラインは以下
  1. Tactical Engine
  2. Evidence Plane
  3. NOC/SOC Evaluator
  4. Action Arbiter
  5. Decision Explanation
  6. Notification / AI Assist
  7. Audit Logger
- 本書は主に AI 補助運用を扱い、P0 全体構成は `docs/P0_RUNTIME_ARCHITECTURE.md` を正とする

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

1. Tactical Engine が Suricata イベントを即時スコア化する
2. 同じ事象を Evidence Plane schema に再整形し、SOC second-pass context を付与する
3. first-pass の `risk_score` が曖昧帯 (`60-79`) の場合のみ Analyst LLM を実行する
4. 低スコアでも相関条件（同一送信元の短時間反復/シグネチャ多様化）を満たした場合は Analyst LLM を強制実行する
5. 非曖昧は LLM をスキップし、deterministic recommendation を維持する
6. `risk_score >= 85` は direct critical として Ops Coach キューへ投入する
7. Ops Coach はメモリ/スワップ閾値を満たす場合のみ実行する

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
- Manual Query:
  - 共通症状 (`Wi-Fi`, `DNS`, `service`, `gateway`, `EPD`, `AI logs`) は `manual_router` が即時返答
  - `AZAZEL_MANUAL_QUERY_TIMEOUT_SEC=18`
  - `AZAZEL_MANUAL_TOTAL_TIMEOUT_SEC=20`
  - `AZAZEL_MANUAL_MODEL_CHAIN=qwen3.5:0.8b,qwen3.5:2b`
  - `AZAZEL_MANUAL_NUM_CTX=192`
  - `AZAZEL_MANUAL_NUM_PREDICT=64`
  - `AZAZEL_MANUAL_KEEP_ALIVE=5m`
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
- M.I.O. は Dashboard、`ops-comm`、Mattermost の各面で役割を分けて運用する

## 6. 日常確認手順

```bash
systemctl is-active azazel-edge-ai-agent
jq '{processed_events,llm_requests,llm_completed,llm_failed,llm_schema_invalid_count,ops_requests,ops_completed,ops_schema_invalid_count,last_error}' /run/azazel-edge/ai_metrics.json
tail -n 5 /var/log/azazel-edge/ai-llm.jsonl
```

手動質問の確認:

```bash
jq '{manual_requests,manual_routed_count,manual_completed,manual_failed,last_error}' /run/azazel-edge/ai_metrics.json
tail -n 5 /var/log/azazel-edge/ai-llm.jsonl
```

Mattermost slash command:

```text
/mio 現在の警戒ポイントは？
/mio temp: Wi-Fi に繋がらない利用者へどう案内するか
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

Web dashboard alert queue の閾値調整（`/etc/default/azazel-edge-web`）:

- `AZAZEL_ALERT_QUEUE_NOW_THRESHOLD`（default: `80`）
- `AZAZEL_ALERT_QUEUE_WATCH_THRESHOLD`（default: `50`）
- `AZAZEL_ALERT_QUEUE_ESCALATE_THRESHOLD`（default: `90`）

Aggregator freshness 判定の調整（`/etc/default/azazel-edge-web`）:

- `AZAZEL_AGGREGATOR_POLL_INTERVAL_SEC`（default: `30`）
- `AZAZEL_AGGREGATOR_STALE_MULTIPLIER`（default: `2`）
- `AZAZEL_AGGREGATOR_OFFLINE_MULTIPLIER`（default: `6`）

## 9. 運用ルール

- Suricata優先。LLMは補助であり、検知可用性を犠牲にしない。
- モデル追加は「メモリ上限・失敗率・遅延」を実測してから採用する。
- 同居運用では `4b` 以上を常用しない。上位モデルは別ホスト分離を前提とする。

## 10. Mattermost運用

- ログイン情報の保管先（ローカル機密ファイル）: `/etc/azazel-edge/mattermost-credentials.env`（`0600`）
- WebUIのMattermost起動URL: `AZAZEL_MATTERMOST_OPEN_URL`（未設定時は `AZAZEL_MATTERMOST_HOST`/`AZAZEL_MATTERMOST_PORT`/`AZAZEL_MATTERMOST_TEAM`/`AZAZEL_MATTERMOST_CHANNEL` から自動生成）
- 運用の主画面: Mattermostダッシュボード
- WebUI(`/ops-comm`)の役割: 監視画面からの簡易投稿・疎通確認・直近メッセージ参照・手動AI質問
- 手動AI質問API: `POST /api/ai/ask`（`question`必須）
- Mattermost slash command / outgoing webhook 用エンドポイント: `POST /api/mattermost/command`
- Mattermost slash command trigger: `/mio`
- legacy alias: `/azops`
- audience prefix:
  - `temp:` / `temporary:` / `beginner:` は臨時担当向け
  - `pro:` / `operator:` / `professional:` はプロ向け

現在実装済みの M.I.O. 機能確認:

```bash
curl -sS http://127.0.0.1:8084/api/ai/capabilities | jq
```
- slash command callback URL: `http://172.16.0.254/api/mattermost/command`
- command token は `/etc/azazel-edge/mattermost-command-token`（`0600`）で管理
- token 未設定時は `POST /api/mattermost/command` を拒否
- `/api/mattermost/message` で `ask_ai=true` を指定すると、AI回答に加えて Runbook 候補も返す
- command の作成/更新:
  - `sudo installer/internal/provision_mattermost_command.sh`
- 設定場所:
  - `/etc/default/azazel-edge-web`
  - 例:
    - `AZAZEL_MATTERMOST_COMMAND_TOKEN_FILE=/etc/azazel-edge/mattermost-command-token`

## 11. Runbook運用

- レジストリ: `runbooks/**/*.yaml`
- API:
  - `GET /api/runbooks`
  - `GET /api/runbooks/<id>`
  - `GET /api/runbooks/<id>/review`
  - `POST /api/runbooks/propose`
  - `POST /api/runbooks/act`
  - `POST /api/runbooks/execute`
- 対象:
  - `read_only` Runbook は dry-run / 実行可能
  - `operator_guidance` は提案のみ
  - `controlled_exec` は安全ゲート付きで既定無効
- AI が返す `runbook_id` は候補提示として扱い、初心者運用では必ず UI かオペレータ承認を介す
- Runbook reviewer:
  - `SOC Analyst`
  - `NOC Operator`
  - `User Support`
  - `Security Architect`
  - `Runbook QA`
- reviewer は別 LLM 常駐ではなく、軽量なポリシー評価器として実装している
- `/api/ai/ask` の結果に `runbook_review` が付く場合は、その判定を優先して採否を決める
- `POST /api/runbooks/act` の扱い:
  - `preview`: dry-run / 手順確認
  - `approve`: guidance 承認記録
  - `execute`: `read_only` と `controlled_exec` を対象
- `POST /api/runbooks/execute` は後方互換用で、内部的には `act` フローへ統合済み
- `controlled_exec` の既定:
  - `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=1` が無い限り実行拒否
  - approval 必須
- 有効化場所:
  - `/etc/default/azazel-edge-web`
  - 例:
    - `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=1`
- 注意:
  - 有効化しても `requires_approval=true` の Runbook は承認無しで実行できない
  - 初心者向けフローでは `controlled_exec` を直接使わせない
- 実行/承認ログ: `/var/log/azazel-edge/runbook-events.jsonl`

## 12. M.I.O. 運用方針

- Azazel-Edge の SOC/NOC 支援AIの運用人格は `M.I.O. (Mission Intelligence Operator)` とする
- M.I.O. は「副官型」の運用人格であり、判断補佐・情報整理・手順提示を担う
- 応答では以下を優先する
  - 冷静
  - 明瞭
  - 簡潔
  - 条件付き表現
  - 初心者配慮
- 初心者向け応答では以下を守る
  - 1回答で最大3手順
  - 1手順ごとに1行動

## 13. 質問マップ

### 14.1 初心者向け (`Temporary / beginner`)

目的:
- 利用者対応を安全に進める
- 危険操作や過剰操作を避ける
- 返答の `user_message` をそのまま案内文として使えるようにする

処理経路:
1. 質問を `manual_router` で分類
2. 既知症状なら即時返答
3. `answer + user_message + runbook_id + rationale` を返す
4. 必要時のみ NOC/SOC 側 Runbook へ handoff

主な質問と設計:
- `初回接続できない`
  - 分類: `wifi_onboarding`
  - Runbook: `rb.user.device-onboarding-guide`
  - 考え方:
    - onboarding 手順として扱う
    - SSID 選択と接続試行を一度ずつ案内
  - 返答方針:
    - 利用者向けの短い案内
    - 失敗継続時は escalation
- `再接続できない`
  - 分類: `wifi_reconnect`
  - Runbook: `rb.user.reconnect-guide`
  - 考え方:
    - saved profile / 一時切断 / 単一端末障害を疑う
    - オフ/オンの一度きりの再試行に抑える
  - 返答方針:
    - Wi-Fi のオフ/オンを一度だけ案内
- `ポータルが出ない`
  - 分類: `portal`
  - Runbook: `rb.user.portal-access-guide`
  - 考え方:
    - portal 誘導失敗として扱う
    - 接続状態を維持したまま通常サイト表示を確認
  - 返答方針:
    - portal が出るかだけを確認させる
- `Wi-Fi に繋がらない`
  - 分類: `wifi_issue`
  - Runbook: `rb.user.first-contact.network-issue`
  - 考え方:
    - 単一端末か複数端末かを先に切り分ける
    - 再起動連打を抑止する
  - 返答方針:
    - 最初に何が使えないかを一つだけ聞く
- `DNS が引けない`
  - 分類: `dns`
  - Runbook: `rb.noc.dns.failure.check`
  - 考え方:
    - 利用者説明は簡潔に留める
    - 実切り分けは NOC 側へ渡す
  - 返答方針:
    - サイト名と IP 直打ち結果を聞く
- `いま何が起きているか`
  - 分類: 多くは `snapshot`
  - Runbook: `rb.noc.ui-snapshot.check`
  - 考え方:
    - 断定より状況説明を優先
  - 返答方針:
    - 「確認中」を維持し、次の案内だけ返す

### 14.2 ベテラン向け (`Professional / operator`)

目的:
- 状態、根拠、次手、Runbook を短く返す
- dashboard / ops-comm / Mattermost で同じ構造を返す

処理経路:
1. 既知症状なら `manual_router`
2. 非定型は LLM (`qwen3.5:0.8b -> qwen3.5:2b`)
3. LLM 失敗時は `tactical_snapshot` fallback
4. 返答は `answer / rationale / user guidance / suggested runbook / review / handoff`

主な質問と設計:
- `gateway / uplink を確認したい`
  - 分類: `route`
  - Runbook: `rb.noc.default-route.check`
  - 考え方:
    - 上位回線と経路の実状態確認を優先
    - `up_if / up_ip / gateway` を返答へ含める
- `DNS failure を確認したい`
  - 分類: `dns`
  - Runbook: `rb.noc.dns.failure.check`
  - 考え方:
    - DNS 障害と uplink 側障害の切り分け
    - resolver / gateway / captive portal の順で確認
- `service が異常か確認したい`
  - 分類: `service`
  - Runbook: `rb.noc.service.status.check`
  - 考え方:
    - UI 表示ズレより先に実サービス停止を確認
    - `status -> journal` の順で確認
- `EPD 差異を確認したい`
  - 分類: `epd`
  - Runbook: `rb.ops.epd.state.check`
  - 考え方:
    - EPD と WebUI/TUI の差異確認
- `AI ログを確認したい`
  - 分類: `ai_logs`
  - Runbook: `rb.ops.logs.ai.recent`
  - 考え方:
    - fallback、失敗、遅延要因の切り分け
- `既知分類に落ちない質問`
  - 分類: `snapshot` または LLM
  - Runbook: `rb.noc.ui-snapshot.check` から開始
  - 考え方:
    - snapshot / 最新 advisory / route 情報を LLM 文脈へ入れる
  - 返答方針:
    - 既知症状へ寄せられなければ LLM へ委譲

### 14.3 回答方針の差

- `beginner`
  - 利用者へ伝える文を優先
  - 危険操作は隠すか無効化
  - 1回答で 1-3 手順に抑える
- `operator`
  - 状態、根拠、次手、Runbook、review を優先
  - `handoff` で `ops-comm` または Mattermost へ継続可能にする
  - 専門語は短く言い換える
  - operator 作業を利用者へ直接指示しない
- 詳細な分類と利用範囲は `docs/MIO_PERSONA_PROFILE.md` を参照
