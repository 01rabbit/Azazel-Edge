# Azazel-Edge SOC/NOC Dashboard Plan

最終更新: 2026-03-08
対象ブランチ: `feature/dashboard-redesign-phase1`
前提: 現行 Dashboard は Azazel-Gadget 流用であり、Azazel-Edge 向け SOC/NOC 運用画面として再設計が必要

## 1. 目的

本計画書は、Azazel-Edge に適した SOC/NOC ダッシュボードを再設計するための計画案である。

本計画案は、以下の専門家ロールを仮想レビューアとして置き、6 ラウンドの協議を行って収束させた。

- `SOC Analyst AI`
- `NOC Operator AI`
- `Incident Commander AI`
- `Temporary Operator Support AI`
- `Frontend Architect AI`
- `Security Architect AI`
- `Observability Engineer AI`

## 2. 現状認識

現行 Dashboard は以下の問題を持つ。

1. Azazel-Gadget 流用のため、Azazel-Edge 固有の運用軸が弱い
2. SOC/NOC 兼用画面として情報の優先順位が未整理
3. 臨時担当とプロ運用者の両方に対して、情報密度の切替がない
4. M.I.O. の支援導線は `ops-comm` に偏っており、Dashboard 側の接続が弱い
5. Runbook、Mattermost、Suricata、Control Plane の統合ビューがない

## 3. 協議ラウンド

### Round 1: 問題定義

`SOC Analyst AI`:
- 脅威優先度、相関、封じ込め判断が見えない画面では SOC 用として弱い

`NOC Operator AI`:
- uplink、gateway、DNS、DHCP、service health が一望できないと NOC の一次切り分けが遅れる

`Temporary Operator Support AI`:
- 臨時担当が最初に見るべきものが整理されていない
- 画面内の「次に何をするか」が明示されていない

合意:
- Dashboard は「情報一覧」ではなく「判断順に並んだ作戦盤」にする

### Round 2: 情報設計

`Incident Commander AI`:
- 画面上部に「現在の運用状態」と「最優先の行動」が必要
- 各カードは独立ではなく、指揮順で並べるべき

`Frontend Architect AI`:
- 3 層に分けるのが妥当
  - Situation
  - Action
  - Evidence

`Observability Engineer AI`:
- リアルタイム値と履歴値を分離しないと誤読が出る

合意:
- ダッシュボードの主構造は以下とする
  1. `Command Strip`
  2. `Situation Board`
  3. `Action Board`
  4. `Evidence / Timeline`

### Round 3: 利用者レベル差分

`Temporary Operator Support AI`:
- 臨時担当向けには
  - 状況
  - 次の一手
  - 利用者へ伝える文
  の 3 つだけを先頭表示すべき

`SOC Analyst AI`:
- プロ向けには相関、confidence、deferred、queue、review 状態が必要

`NOC Operator AI`:
- NOC は uplink/route/service の現況を省略できない

合意:
- Dashboard 自体に `Audience Mode` を持たせる
  - `Professional`
  - `Temporary`
- 同じデータを見つつ、表示密度と行動導線だけ切り替える

### Round 4: M.I.O. の役割

`Security Architect AI`:
- M.I.O. を主役にしすぎると、根拠よりキャラクターが前に出る

`Incident Commander AI`:
- Dashboard の中心は Azazel-Edge の運用状態
- M.I.O. は「支援層」に配置すべき

`Frontend Architect AI`:
- まずは `Assistant Rail` として右側または上部に置く
- 中央の主盤面はシステム状態に譲る

合意:
- Dashboard 再設計後の M.I.O. は以下に限定
  - `Current Recommendation`
  - `User Guidance`
  - `Suggested Runbook`
  - `Ask M.I.O.` 導線

### Round 5: 必要コンポーネント

`SOC Analyst AI` が要求:
- Suricata 相関サマリ
- Tactical score 変動
- direct critical / ambiguous / deferred の件数

`NOC Operator AI` が要求:
- uplink、gateway、DNS mismatch、captive portal、service status
- user impact を伴う mode 変更履歴

`Observability Engineer AI` が要求:
- last event time
- stale detection
- queue / latency / fallback rate

`Temporary Operator Support AI` が要求:
- 「利用者へ伝える文」
- 「次に押すボタン」
- 「危険なので触らない操作」

合意:
- Phase 1 で入れるべき最小構成を確定

### Round 6: 収束

`Security Architect AI`:
- いきなり全面作り替えではなく、データモデル先行が必要

`Frontend Architect AI`:
- 既存 API を増やしてから UI を再設計するのが安全

`Incident Commander AI`:
- 画面を先に描くより、共通スナップショット設計を先に固めるべき

最終合意:
- 先に `Dashboard Data Contract` を作る
- その上で `Phase 1 -> Phase 2 -> Phase 3` の順で作る

## 4. 最終計画

### 4.1 設計原則

1. `Suricata / Tactical / NOC / AI / Runbook / Mattermost` を 1 画面で繋ぐ
2. `Professional` と `Temporary` を同じデータから切り替える
3. M.I.O. は補助線であり、中央主役には置かない
4. 状態、次アクション、根拠、監査の順で並べる
5. EPD/TUI/WebUI が参照する状態の差異を減らす

### 4.2 画面構造

#### A. Command Strip

画面最上部に常時表示する。

- 現在 mode
- current risk
- current uplink
- internet reachability
- direct critical 件数
- deferred 件数
- stale warning
- `Ask M.I.O.`
- `Open Mattermost`

#### B. Situation Board

左上の主盤面。

- `Threat Posture`
  - tactical risk
  - current recommendation
  - confidence
  - last alert
- `Network Health`
  - uplink
  - gateway
  - DNS
  - DHCP
  - captive portal
- `Service Health`
  - control-daemon
  - ai-agent
  - web
  - suricata
  - opencanary

#### C. Action Board

中央または右上。

- `Next Actions`
  - operator next check
  - recommended runbook
  - approval required
- `User Guidance`
  - 利用者へそのまま伝える文
- `M.I.O. Assist`
  - current answer
  - review
  - routed/llm status

#### D. Evidence / Timeline

下段全面。

- recent events
- LLM / routed activity
- runbook approvals / executes
- mattermost interactions
- mode changes

### 4.3 Audience Mode

#### Professional

- 相関、review、latency、queue、fallback を表示
- runbook preview/approve/execute を前面に出す
- evidence を詳細表示

#### Temporary

- 状況
- 次の一手
- 利用者へ伝える文
- 禁止事項
を前面に出す

抑制:
- queue 深掘り
- raw review findings
- service restart 系の実行ボタン

## 5. Dashboard Data Contract

Dashboard 再設計前に以下の API/スナップショットを整える。

### 5.1 必須 API

1. `/api/dashboard/summary`
- risk
- mode
- uplink
- gateway
- service health summary
- current recommendation

2. `/api/dashboard/actions`
- current operator actions
- current user guidance
- suggested runbook
- approval required

3. `/api/dashboard/evidence`
- recent alerts
- recent ai/manual_router outputs
- recent runbook events
- recent mode changes

4. `/api/dashboard/health`
- stale flags
- queue depth
- fallback rate
- last event timestamps

### 5.2 既存資産の再利用元

- `/run/azazel-edge/ui_snapshot.json`
- `/run/azazel-edge/ai_advisory.json`
- `/run/azazel-edge/ai_metrics.json`
- `/var/log/azazel-edge/ai-llm.jsonl`
- `/var/log/azazel-edge/runbook-events.jsonl`

## 6. Phase Plan

### Phase 1: Data Contract

目的:
- Dashboard 用 API を追加
- 既存データソースを正規化

実装:
- `dashboard summary/actions/evidence/health` API
- stale 判定
- current user guidance の統合

完了条件:
- UI を作らなくても API だけで状態要約が再現できる

実装状況:
- 完了
- 実装済み API:
  - `/api/dashboard/summary`
  - `/api/dashboard/actions`
  - `/api/dashboard/evidence`
  - `/api/dashboard/health`
- データソース:
  - `/run/azazel-edge/ui_snapshot.json`
  - `/run/azazel-edge/ai_advisory.json`
  - `/run/azazel-edge/ai_metrics.json`
  - `/var/log/azazel-edge/ai-events.jsonl`
  - `/var/log/azazel-edge/ai-llm.jsonl`
  - `/var/log/azazel-edge/runbook-events.jsonl`

### Phase 2: Layout Replacement

目的:
- 既存 Gadget 流用 UI を Azazel-Edge 用に置換

実装:
- Command Strip
- Situation Board
- Action Board
- Evidence Timeline
- Audience Mode toggle

完了条件:
- `Professional/Temporary` の両モードで操作順が自然

実装状況:
- 完了
- 実装済み:
  - `Command Strip`
  - `Situation Board`
  - `Action Board`
  - `Evidence Timeline`
  - `Audience Mode` toggle
- 備考:
  - 旧 Gadget 流用カード構造は撤去
  - Mode switch / Portal assist / Contain / Release は新盤面へ再配置

### Phase 3: M.I.O. Integration

目的:
- M.I.O. を Dashboard に統合

実装:
- Assistant Rail
- current recommendation
- user guidance
- Ask M.I.O. inline panel
- Mattermost deep link

完了条件:
- Dashboard 内から `ops-comm` へ遷移せずに、最低限の支援が完結する

実装状況:
- 完了
- 実装済み:
  - `Assistant Rail`
  - `current recommendation`
  - `user guidance`
  - `Ask M.I.O.` inline panel
  - `Mattermost` deep link
- 備考:
  - Dashboard から `/api/ai/ask` を直接利用可能
  - `Professional/Temporary` は M.I.O. 問い合わせ文脈にも反映

## 7. 今回時点で実装可能と判断するもの

Dashboard 本体を再設計せずに、今すぐ追加可能なのは以下。

1. `dashboard summary/actions/evidence/health` API の追加
2. `ops-comm` と Dashboard の導線統一
3. `Temporary` 向け user guidance の強化
4. Mattermost と Dashboard の state linkage

逆に、今はやらない方がよいもの:

1. Dashboard 中央への M.I.O. 常設大型パネル
2. Gadget 時代のカード構造のまま小修正を重ねること
3. raw ログ大量表示のまま audience 差分なしで出すこと

## 8. 成功条件

1. プロ運用者が 10 秒以内に状況把握できる
2. 臨時担当が 30 秒以内に「利用者へ伝える文」と「次の一手」を得られる
3. direct critical / uplink failure / service failure が同一画面で把握できる
4. M.I.O. の支援が主盤面を邪魔せず補助として機能する
5. WebUI/TUI/EPD の状態差異が再発しにくい

## 9. 推奨次手

1. `Phase 1` の API 設計を先に実装
2. その API を基準に Dashboard 再設計へ入る
3. M.I.O. の Dashboard 常設支援は `Phase 3` で扱う

## 10. 再協議 2026-03-08

前節までは「構想段階」の計画である。ここでは、Phase 1-3 の実装完了後に、現実装を前提として残課題と次段方針を再評価した結果をまとめる。

### 10.1 参加ロール

- `SOC Analyst AI`
- `NOC Operator AI`
- `Incident Commander AI`
- `Temporary Operator Support AI`
- `Frontend Architect AI`
- `Security Architect AI`
- `Observability Engineer AI`
- `Platform Reliability AI`

### 10.2 協議ラウンド

#### Round 1: 現在の完成度判定

`Incident Commander AI`:
- 盤面の骨格は成立している
- ただし「完成」ではなく「運用投入可能なベータ」

`Frontend Architect AI`:
- 情報構造は Gadget 流用段階を脱した
- ただし Action/Evidence の意味づけがまだ浅い

`SOC Analyst AI`:
- 重大イベントが無い時の盤面は静的でよい
- その一方、イベント発生時の因果表示が弱い

合意:
- 現在の完成度は 70-80%
- 次段は「見た目」より「判断密度の向上」を優先する

#### Round 2: Action Board の不足

`NOC Operator AI`:
- `Next Actions` は出ているが、「なぜその順番なのか」が不足
- たとえば uplink 問題と service 問題の切り分け順が明示されていない

`SOC Analyst AI`:
- `Runbook` が見えても、どのシグナルを根拠に推薦したかが無い

`Temporary Operator Support AI`:
- 初心者には「次に押すもの」だけでなく「押してはいけないもの」も必要

合意:
- `Action Board` は次段で以下へ分解する
  1. `Why now`
  2. `Do next`
  3. `Do not do`
  4. `Escalate if`

#### Round 3: Evidence Board の不足

`Observability Engineer AI`:
- 今の `recent_ai_activity` と `recent_runbook_events` は「ログ抜粋」に近い
- オペレータが読むべき優先度順に圧縮されていない

`Security Architect AI`:
- 古い M.I.O. 応答が誤って現況の助言に見える問題は、Evidence の時間管理不足が原因

`Platform Reliability AI`:
- stale / freshness は見えているが、盤面上の警告強度が弱い

合意:
- `Evidence` は次段で以下へ再編する
  1. `Current triggers`
  2. `Recent decision changes`
  3. `Operator interactions`
  4. `Background history`

#### Round 4: Audience Mode の不足

`Temporary Operator Support AI`:
- `Temporary` は表示抑制まではできている
- しかし症状別導線がまだ不足

`Incident Commander AI`:
- 臨時担当は観測値ではなく行動文と確認質問を先頭表示すべき

`NOC Operator AI`:
- `Professional` 側は逆に、サービス・経路・相関をもっと前面に出してよい

合意:
- `Temporary` に症状別フローを追加
  - Wi-Fi
  - DNS
  - uplink
  - service
- `Professional` は telemetry と evidence を強化

#### Round 5: M.I.O. の配置と権限境界

`Security Architect AI`:
- Dashboard 上の M.I.O. は「助言」と「問い合わせ入口」に留めるべき
- コマンド実行や強い誘導を主盤面へ混ぜると責務が曖昧になる

`SOC Analyst AI`:
- M.I.O. は観測根拠を短く添えられるようにすべき

`Frontend Architect AI`:
- 右レール配置は正しい
- ただし `Current status` と `Last asked advice` を分離した方が誤読が減る

合意:
- M.I.O. は次段で
  1. `Current assist`
  2. `Last manual ask`
  3. `Recommended runbook`
  に分離する

#### Round 6: データ鮮度と運用信頼性

`Platform Reliability AI`:
- stale flag が立っていても operator が気づきにくい
- `ai_metrics stale` と `runbook_events stale` は盤面の端ではなく header に近い位置で告知すべき

`Observability Engineer AI`:
- `Last Change` の human-readable 化は正しい
- 同様に `Last AI activity`、`Last runbook event` も相対時間付きに揃えるべき

`Incident Commander AI`:
- stale は UI 問題ではなく運用問題
- したがって表示だけでなく、閾値と suppression 条件を定義すべき

合意:
- 時刻表現と freshness 表現を全盤面で統一
- stale の閾値を運用設定として明文化

#### Round 7: 完成条件の再定義

`SOC Analyst AI`:
- 重大アラート発生時に 10 秒以内で状況把握できるかが第一

`NOC Operator AI`:
- 回線・ゲートウェイ・サービス障害の切り分けが 30 秒以内に始められるかが第二

`Temporary Operator Support AI`:
- 初心者が利用者に返す文を 15 秒以内に得られるかが第三

`Incident Commander AI`:
- 以上が揃って初めて「完成」と言える

最終合意:
- 完成判定は UI の見た目ではなく、判断時間短縮で測る

## 11. 残タスク

### 11.1 高優先

1. `Action Board` の因果表示
- 推奨理由
- 根拠シグナル
- 次に確認する項目
- 触るべきでない操作

2. `Evidence Board` の圧縮
- ログ列挙ではなく重要イベント要約
- stale な AI 応答と live 状態の視覚分離

3. `Temporary` 症状別導線
- Wi-Fi / DNS / uplink / service の 4 導線
- `利用者へ聞くこと` と `利用者へ伝えること` の分離

4. stale/freshness の全体統一
- `Last AI activity`
- `Last runbook event`
- `Last mode change`
- `Last snapshot`

### 11.2 中優先

1. M.I.O. 表示の 3 分割
- `Current assist`
- `Last manual ask`
- `Recommended runbook`

2. `Professional` 向け深掘り情報の追加
- queue
- fallback
- review result summary
- direct critical / deferred の推移

3. Evidence と Mattermost の接続強化
- slash command 実行結果を evidence に正しく畳み込む
- 手動問い合わせと自動支援を見分けやすくする

### 11.3 低優先

1. ダーク/ライトや細部トーン調整
2. モバイル最適化の細部
3. 視覚演出の追加

## 12. 今後の構築計画

### Phase 4: Decision Clarity

目的:
- `Action Board` を「理由付き行動盤」に変える

実装:
- `why_now`
- `do_next`
- `do_not_do`
- `escalate_if`
の各フィールドを `/api/dashboard/actions` へ追加

完了条件:
- 推奨 Runbook の理由を画面だけで説明できる

実装状況:
- 完了
- 実装済み:
  - `why_now`
  - `do_next`
  - `do_not_do`
  - `escalate_if`
  - `Action Board` への表示反映

### Phase 5: Evidence Compression

目的:
- `Evidence Board` をログ表示から判断支援表示へ変える

実装:
- `recent_alerts` を重要順に圧縮
- `recent_ai_activity` を `live/manual/background` に分類
- `runbook_events` を preview/approve/execute の要点へ圧縮

完了条件:
- 画面下段を 20 秒見れば「何が起きたか」が追える

実装状況:
- 完了
- 実装済み:
  - `current_triggers`
  - `decision_changes`
  - `operator_interactions`
  - `background_history`
  - `Evidence Board` の圧縮表示

### Phase 6: Temporary Flow

目的:
- 初心者導線を Dashboard 内で完結させる

実装:
- 症状カード
- 聞き取りテンプレート
- 利用者向け短文
- 危険操作の抑止表示

完了条件:
- `ops-comm` に飛ばなくても一次案内が可能

実装状況:
- 初期完了
- 実装済み:
  - `Temporary Triage`
  - `Ask the user`
  - `Tell the user`
  - 症状別ボタンからの M.I.O. 問い合わせ接続
- 継続課題:
  - 症状別導線の更なる細分化
  - 一次案内文の改善

### Phase 7: Reliability and Freshness

目的:
- stale 情報と live 情報の誤読を防ぐ

実装:
- 時刻表現の統一
- freshness badge
- stale threshold の設定化
- alert 無し時の quiet state 最適化

完了条件:
- 古い助言を現況と誤認しない

実装状況:
- 初期完了
- 実装済み:
  - freshness badge
  - stale / live の表示
  - `snapshot / ai metrics / ai activity / runbook event` の freshness 表示
- 継続課題:
  - stale 閾値の運用調整
  - quiet state 最適化の追加

### Phase 8: Final M.I.O. Integration

目的:
- M.I.O. を「主役ではなく強い補助線」として完成させる

実装:
- `Current assist`
- `Last asked advice`
- `Runbook with rationale`
- Mattermost / dashboard / ops-comm の体験統一

完了条件:
- どの入口から入っても、M.I.O. の役割と限界が一貫する

実装状況:
- 部分完了
- 実装済み:
  - `Current assist`
  - `Last manual ask`
  - `Recommended runbook`
  - `Rationale`
  - `Open Ops Comm / Open Mattermost`
  - `/api/ai/ask` の `rationale / handoff` 返却
  - Mattermost 応答への `Rationale / Continue` 追記
  の分離表示と共通構造化
- 継続課題:
  - Dashboard / Mattermost / ops-comm の文言・語順の最終統一
  - `Temporary` 向け症状導線の細分化

## 13. 現時点の方針

1. 新規 UI 部品を増やす前に、`Phase 4` の API 追加を優先する
2. `Temporary` 最適化は、見た目より先に症状別フローを作る
3. M.I.O. は常に補助であり、中央主盤面を奪わない
4. 完成判定は「見栄え」ではなく「判断時間短縮」で行う

## 14. 否定的レビューと改善ラウンド

前提:
- 各ラウンドでは、否定的立場のレビュワーが「このままでは運用で事故る」という前提で批判を出す
- その後、複数の専門家ロールが改善策を協議し、実装へ反映する

専門家ロール:
- `Adversarial SOC Reviewer`
- `Adversarial NOC Reviewer`
- `Adversarial Temporary-Operator Reviewer`
- `Security Architect`
- `Frontend Architect`
- `Incident Commander`
- `Observability Engineer`

### Round 1

否定的レビュー:
- `Dashboard / ops-comm / Mattermost` で M.I.O. の返答構造が一致していない
- 手動質問の返答から次の導線が読めず、入口を変えると体験が崩れる

改善協議:
- `Security Architect`: 補助AIの出力は構造を固定すべき
- `Frontend Architect`: `answer / rationale / guidance / runbook / review / handoff` に揃えるべき
- `Incident Commander`: 緊急時は「次にどこへ行くか」が最短で見える必要がある

実施:
- `/api/ai/ask` に `rationale / handoff` を追加
- `ops-comm` に `Rationale / Handoff` を追加
- Mattermost 応答へ `Rationale / Continue` を追加

### Round 2

否定的レビュー:
- `Temporary` モードが Wi-Fi / DNS / Uplink / Service の4分類だけでは粗すぎる
- 初回接続、再接続、ポータル表示失敗が切り分けられない

改善協議:
- `Temporary-Operator Reviewer`: 現場では「最初からつながらない」と「昨日まで使えた」が別問題
- `NOC Reviewer`: Portal は Wi-Fi と分けないと案内が崩れる
- `Frontend Architect`: 症状別ボタンを増やしても情報密度は保てる

実施:
- `Reconnect / Onboarding / Portal` を `Temporary Triage` に追加
- 症状別の `Ask the user / Tell the user` を細分化

### Round 3

否定的レビュー:
- `SAFE` 時でも `Current Triggers` が空欄だと「壊れている」のか「正常なのか」が分からない
- 静穏時の盤面が曖昧

改善協議:
- `Observability Engineer`: quiet state を明示しない監視UIは誤解を生む
- `SOC Reviewer`: 何も無いこと自体を証拠として表示すべき
- `Frontend Architect`: empty state は欠落ではなく状態表示に変えるべき

実施:
- `No active trigger` を `Current Triggers` の既定表示に追加

### Round 4

否定的レビュー:
- Dashboard から手動で M.I.O. に聞いた結果が、右ペインの構造と一致していない
- `mioAskResponse` だけ独自フォーマットで、レビューと handoff が見えない

改善協議:
- `Frontend Architect`: 手動応答欄も同じ語順に揃えるべき
- `Incident Commander`: 緊急時にレビュー状態と継続導線が欠けるのは不十分
- `Security Architect`: runbook 提案には常に review を添えるべき

実施:
- Dashboard の `Ask M.I.O.` 応答を共通構造へ変更
- `Rationale / User Guidance / Runbook / Review / Continue` を表示
- 右ペインの `Last Manual Ask / Rationale / Handoff` も即時更新

### Round 5

否定的レビュー:
- `Temporary` モードでも Gateway mode 変更ボタンが見えており、誤操作余地が残る
- 表示だけ切り替わっても、操作抑制が弱い

改善協議:
- `Security Architect`: 初心者向けモードでは危険操作を視覚上だけでなく操作上も抑止すべき
- `Temporary-Operator Reviewer`: 現場では押せるものは押される
- `NOC Reviewer`: mode change は初動の聞き取り担当に開けるべきではない

実施:
- `Temporary` モードでは `Portal / Shield / Scapegoat` ボタンを `disabled`
- tooltip で禁止理由を明示

### Round 6

否定的レビュー:
- Mattermost の応答順が Dashboard/ops-comm と一致しないと、オペレータ教育が分裂する
- 同じ M.I.O. なのに入口ごとに説明の順番が違うのは弱い

改善協議:
- `Incident Commander`: 現場教育では返答順序の一貫性が重要
- `SOC Reviewer`: `answer -> rationale -> guidance -> runbook -> review -> continue` に統一すべき
- `Frontend Architect`: 文言と順番の差異は最小化する

実施:
- Mattermost 応答順を Dashboard/ops-comm と同じ語順へ調整

### Round 7

否定的レビュー:
- 完成度は高いが、なお `Temporary` 症状導線の文言、Mattermost での長文圧縮、運用閾値の実測調整は継続余地がある
- 「改善余地がない」ではなく「現段階で優先度の高い欠陥が解消された」状態

改善協議:
- `Observability Engineer`: stale 閾値は実運用ログで再調整すべき
- `Temporary-Operator Reviewer`: 実地の日本語案内文は現場観察でさらに改善余地あり
- `Security Architect`: controlled action は将来も保守的に維持すべき

結論:
- 高優先の構造欠陥は解消済み
- 残るのは運用チューニングであり、現時点では実装阻害要因ではない
- 現段階の完成判定は「構造完成・運用改善フェーズ移行」とする

### Round 8

否定的レビュー:
- `Temporary Triage` に `Portal` を置いたのに、manual router 側で `portal` 分類が無く fallback に落ちる
- UI と backend の症状分類が一致していないのは設計欠陥

改善協議:
- `Adversarial NOC Reviewer`: portal は利用者体験に直結するため、個別ハンドラが必要
- `Security Architect`: UI にだけ存在する症状は誤誘導になる
- `Temporary-Operator Reviewer`: 現場では「ボタンを押したのに曖昧な答え」が最も不信感を生む

実施:
- `portal` 分類を manual router に追加
- `rb.user.portal-access-guide` を追加
- `Portal` 症状を routed 応答で即時処理するよう修正
