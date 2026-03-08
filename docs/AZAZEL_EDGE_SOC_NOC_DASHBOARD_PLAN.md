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
