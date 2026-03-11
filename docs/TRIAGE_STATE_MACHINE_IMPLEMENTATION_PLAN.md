# Triage State Machine Implementation Plan

最終更新: 2026-03-11
対象: Azazel-Edge の初心者向け支援導線、Runbook selector、M.I.O. 補助層
対象ブランチ: `feature/ops-comm-usability`

## 1. 目的

本書は、初心者向け支援を

- 自由会話ベースの多段Q&Aではなく
- 症状別トリアージ状態機械 + Runbook selector

として実装するための完成計画を定義する。

本計画は、以下の 2 チームによる反復討論を前提に作成した。

### 設計チーム（提案側）
- `Triage Architect AI`
- `Beginner Support AI`
- `Runbook Systems AI`
- `SOC/NOC Workflow AI`
- `Human Factors AI`

### 批判チーム（否定側）
- `Security Skeptic AI`
- `Operations Failure AI`
- `State Explosion AI`
- `Observability Skeptic AI`
- `Reliability Skeptic AI`

本書では 10 ラウンド超の批判と修正を経て、現段階で手直しの必要が低い構成を最終案として固定する。

## 2. 最終結論

Azazel-Edge に実装すべきものは「多段Q&Aフレームワーク」ではなく、以下の 5 層である。

1. `Intent Classifier`
- 自由文を症状カテゴリへ落とす軽量分類器

2. `Triage State Machine`
- 症状ごとに固定分岐を持つ状態機械

3. `Diagnostic State`
- 質問の回答から形成される中間診断状態

4. `Runbook Selector`
- Diagnostic State を根拠に Runbook を選ぶ決定層

5. `LLM Assist / Human Handoff`
- 定型分岐で収まらないケースだけ補助的に使う層

重要なのは、LLM を質問制御の主体にしないことである。質問制御は deterministic に固定し、LLM は説明と例外整理に限定する。

## 3. 非目標

本計画では、以下を行わない。

- 自由会話型の長いマルチターンチャットエージェント化
- 初心者に対する自由生成の操作手順提示
- Runbook 乱立による「ほぼ同じ手順」の量産
- LLM による状態遷移の決定
- 端末やネットワークに対する自律操作

## 4. ラウンド討論記録

## Round 1: 基本構想レビュー

### 提案側
- 初心者向けには一問一答では足りない
- よって多段Q&Aで困りごとを細かく引き出し、その結果を使って Runbook へ誘導する

### 批判側
- `State Explosion AI`: 多段Q&Aという発想のままだと状態が自由化し、分岐数がすぐ制御不能になる
- `Security Skeptic AI`: 自由Q&Aは LLM を質問制御へ引き込みやすく、誤誘導や逸脱が起きる
- `Operations Failure AI`: オペレータがデバッグできない導線は本番で壊れる

### 修正
- 「多段Q&A」という抽象表現をやめる
- `症状別状態機械` を主語にする
- 質問は state transition の一部として定義する

### 裁定
- `多段Q&Aフレームワーク` ではなく `症状別トリアージ状態機械` を採用

## Round 2: 入力自由度レビュー

### 提案側
- 最初の症状だけは自由文入力でも受ける
- その後は固定質問へ移る

### 批判側
- `Reliability Skeptic AI`: 自由文分類が弱いと最初から誤分岐する
- `Human Factors AI`: 初心者は自由文で困りごとを書けないことがある

### 修正
- 入口は 2 系統に分離
  - `症状ボタン起点`
  - `自由文起点`
- 自由文は classifier で候補を 2 件まで返し、ユーザーに選ばせる
- 不確実な分類を黙って確定しない

### 裁定
- classifier は確定器ではなく `候補提示器` とする

## Round 3: 質問設計レビュー

### 提案側
- 各症状で 5〜8 問程度の質問フローを持つ

### 批判側
- `Beginner Support AI`: 8 問は長い。離脱する
- `Operations Failure AI`: 長すぎるフローは現場で使われない

### 修正
- 1 flow あたり原則 `3〜5 問`
- 超過する場合は 2 段階に分離
  - `first-pass triage`
  - `deeper branch`
- 最初の 2 問で粗く大別し、残りは補足確認に限定

### 裁定
- 各症状 flow は短く保ち、長い診断は枝分かれで吸収

## Round 4: Diagnostic State の必要性レビュー

### 提案側
- 回答結果から直接 Runbook を選ぶ

### 批判側
- `Runbook Systems AI`: Q&A と Runbook を直結すると、Runbook の増減が質問設計へ波及する
- `State Explosion AI`: 分岐と Runbook が密結合だと保守不能になる

### 修正
- `Diagnostic State` を中間層として導入
- 例:
  - `single_client_wifi_issue`
  - `multi_client_wifi_issue`
  - `dhcp_likely`
  - `dns_likely`
  - `portal_trigger_likely`
  - `service_health_uncertain`

### 裁定
- Q&A は Runbook ではなく Diagnostic State を生成する

## Round 5: Runbook 粒度レビュー

### 提案側
- 初心者向け Runbook を細かく分けて大量に作る

### 批判側
- `Runbook Systems AI`: 細かすぎる Runbook は重複が増える
- `Security Skeptic AI`: 微妙な差分の Runbook は誤実行を招く

### 修正
- Runbook は次の 3 層に分ける
  - `User Guidance Runbook`
  - `Operator Check Runbook`
  - `Controlled Action Runbook`
- 初心者導線で使うのは原則 `User Guidance` と `Operator Check` のみ
- `Controlled Action` は直接選ばせない

### 裁定
- Runbook は「対象者」と「危険度」で分層する

## Round 6: Handoff 設計レビュー

### 提案側
- 不明時だけ LLM に回す

### 批判側
- `Observability Skeptic AI`: 不明の定義が曖昧だと運用ログ上で追えない
- `Reliability Skeptic AI`: LLM へ回した理由が残らないと改善できない

### 修正
- handoff 理由を固定コード化
  - `classification_ambiguous`
  - `answers_inconsistent`
  - `user_cannot_answer`
  - `branch_exhausted`
  - `operator_override`
- すべて audit に残す

### 裁定
- LLM handoff と human handoff は必ず reason code を持つ

## Round 7: 人間工学レビュー

### 提案側
- Dashboard と `ops-comm` の両方にフローを出す

### 批判側
- `Human Factors AI`: 同じ導線が 2 箇所にあるとメンテが割れる
- `Beginner Support AI`: 初心者向け主導線は `ops-comm` に寄せた方がよい

### 修正
- 主導線は `ops-comm`
- Dashboard は
  - 症状カード
  - 現在の triage 状態
  - `Continue in ops-comm`
のみに留める

### 裁定
- 状態機械の本 UI は `ops-comm` とする

## Round 8: 観測性レビュー

### 提案側
- triage session をメモリだけで持つ

### 批判側
- `Observability Skeptic AI`: セッションの途中状態を追えない
- `Operations Failure AI`: ブラウザ更新で消えると現場で使えない

### 修正
- `triage_session` を JSON で保持
- 保持項目:
  - `session_id`
  - `audience`
  - `lang`
  - `intent_candidates`
  - `selected_intent`
  - `current_state`
  - `answers`
  - `diagnostic_state`
  - `proposed_runbooks`
  - `handoff_reason`
  - `updated_at`
- 監査ログへ state transition を出力

### 裁定
- triage は明示セッションとして保存する

## Round 9: 安全性レビュー

### 提案側
- 一部の Runbook は session の終盤で execute 可能にする

### 批判側
- `Security Skeptic AI`: 初心者向けフローに execute を混ぜるのは危険
- `Reliability Skeptic AI`: 誘導フローが成功したからといって action 実行まで自動で行う理由はない

### 修正
- triage flow では execute を禁止
- 出力は次のいずれかのみ
  - `user_guidance_ready`
  - `operator_check_ready`
  - `llm_assist_required`
  - `human_handoff_required`
- 実行は従来の承認系 UI に分離

### 裁定
- triage flow と実行系は分離する

## Round 10: 既存 M.I.O. 統合レビュー

### 提案側
- state machine の各質問文も M.I.O. が自由生成する

### 批判側
- `State Explosion AI`: 質問生成を自由化すると deterministic ではなくなる
- `Human Factors AI`: 同じ症状でも毎回聞き方が変わると初心者に不利

### 修正
- 質問文はテンプレート固定
- M.I.O. は次のみに使う
  - 質問前の短い前置き
  - 回答後の短い整理文
  - handoff 時の要約
- 質問そのものは deterministic

### 裁定
- M.I.O. は `質問生成器` ではなく `説明補助器`

## Round 11: 最終批判

### 批判側総括
- `Security Skeptic AI`: safety は許容範囲
- `Operations Failure AI`: session と reason code があるので運用追跡可能
- `State Explosion AI`: intent と diagnostic state を分けたので増殖リスクは抑制可能
- `Observability Skeptic AI`: audit と session 保存があれば改善可能
- `Reliability Skeptic AI`: LLM 依存を局所化している点は妥当

### 残る懸念
- 質問数が増えた時の保守コスト
- 言語切替時の全テンプレート管理
- intent classifier の初期精度

### 最終対処
- flow 定義は DSL / YAML 化する
- intent classifier は rule-first で開始
- すべての質問と遷移に `id` を持たせる

### 裁定
- 現段階で追加の構造修正は不要
- 実装へ進めてよい

## 5. 最終アーキテクチャ

## 5.1 コンポーネント

1. `intent_classifier`
- 入力: 自由文または症状カード
- 出力: `intent_candidates[]`

2. `triage_session_store`
- セッション永続化
- JSON ファイルまたは lightweight state store

3. `triage_flow_engine`
- 現在 state と回答を受け取り次の質問/診断状態を返す

4. `diagnostic_state_mapper`
- 回答集合から診断状態を確定

5. `runbook_selector`
- 診断状態から Runbook 候補を返す

6. `handoff_router`
- LLM or human handoff を決定

## 5.2 データモデル

### IntentCandidate
- `intent_id`
- `label`
- `confidence`
- `source`

### TriageSession
- `session_id`
- `audience`
- `lang`
- `selected_intent`
- `current_state`
- `answers`
- `diagnostic_state`
- `proposed_runbooks`
- `status`
- `handoff_reason`
- `created_at`
- `updated_at`

### TriageStep
- `step_id`
- `question_key`
- `answer_type`
- `choices`
- `transition_map`
- `fallback_transition`

### DiagnosticState
- `state_id`
- `severity`
- `summary_key`
- `user_guidance_key`
- `operator_note_key`

## 6. 最初に実装する intent

P1 として最初に作るべき intent は以下に限定する。

1. `wifi_connectivity`
2. `wifi_reconnect`
3. `wifi_onboarding`
4. `dns_resolution`
5. `portal_access`
6. `uplink_reachability`
7. `service_status`

理由:
- 既存 `manual_router` と Runbook に資産がある
- 初心者の実需要が高い
- NOC/SOC の両方に接続できる

## 7. 実装スライス

### Slice 1: セッションと flow 定義
- `triage/session.py`
- `triage/flows/*.yaml`
- `triage/types.py`

### Slice 2: classifier
- rule-first classifier
- 自由文から intent candidate 2 件まで提示

### Slice 3: flow engine
- 次質問
- 回答保存
- 遷移
- diagnostic state 確定

### Slice 4: runbook selector
- diagnostic state -> runbook candidates
- `User Guidance` / `Operator Check` 優先

### Slice 5: UI
- `ops-comm` に triage panel
- Dashboard は `continue in ops-comm` のみ

### Slice 6: audit/logging
- `triage_session_started`
- `triage_step_answered`
- `triage_state_changed`
- `triage_runbook_proposed`
- `triage_handoff`
- `triage_completed`

### Slice 7: M.I.O. 補助統合
- 質問前置き
- 回答整理文
- handoff explanation

## 8. 受け入れ条件

1. 初心者は症状カードまたは自由文から triage を開始できる
2. classifier が曖昧なときは候補を明示し、黙って確定しない
3. flow は 3〜5 問以内で first-pass 診断へ到達できる
4. flow は Runbook を直接選ばず Diagnostic State を経由する
5. すべての state transition と handoff reason が監査ログに残る
6. triage 中に execute は行わない
7. LLM は例外整理に限定され、質問遷移を決めない
8. `ja/en` 言語切替でも同じ flow が成立する

## 9. 実装順序

1. Session store
2. Flow definition schema
3. Rule-first intent classifier
4. Flow engine
5. Diagnostic state mapper
6. Runbook selector
7. Audit integration
8. `ops-comm` UI
9. Dashboard 連携
10. M.I.O. 補助統合

## 10. 最終裁定

本計画は

- 会話AI化による逸脱
- Runbook 乱立
- LLM 依存
- 観測不能な分岐
- 初心者向け UX の崩壊

を抑えながら、Azazel-Edge の現行資産

- `manual_router`
- `runbook review`
- `ops-comm`
- `M.I.O.`
- `audit logging`

を最大限再利用できる。

したがって、Azazel-Edge の初心者支援を次段へ進める実装計画として、本書を採用する。
