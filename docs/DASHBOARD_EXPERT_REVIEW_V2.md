# Dashboard Expert Review V2

最終更新: 2026-03-10
対象: Azazel-Edge main dashboard (`/`)
対象ブランチ: `feature/ops-comm-usability`

## 1. 目的

本書は、現行 Azazel-Edge main dashboard が

- 人間工学的に見やすいか
- SOC として十分機能しているか
- NOC として十分機能しているか

を、複数専門家ロールによる反復レビューで評価し、再設計方針を確定するための文書である。

今回は以下の 8 ロールを置き、否定的レビューを前提に 6 ラウンドの分析、協議、再設計、再レビューを行った。

- `SOC Analyst AI`
- `NOC Operator AI`
- `Incident Commander AI`
- `Temporary Operator Support AI`
- `Frontend Architect AI`
- `Security Architect AI`
- `Observability Engineer AI`
- `Human Factors AI`

## 2. 現状評価

### 2.1 結論

現行 dashboard は「運用可能なベータ」であり、以下の評価に留まる。

- 人間工学: `72 / 100`
- SOC dashboard として: `68 / 100`
- NOC dashboard として: `78 / 100`
- 総合: `73 / 100`

### 2.2 現在の強み

1. `Command Strip` により現在 posture の骨格は見える
2. `Situation / Action / Evidence / M.I.O.` の 4 層構造は成立している
3. `Temporary` と `Professional` のモード差分は一応存在する
4. stale / freshness の概念が UI に入っている
5. demo overlay により live state を汚さず説明可能

### 2.3 現在の弱み

1. 1 画面で見るべき優先順位がまだ強くない
2. SOC の判断材料が `Threat Posture` に圧縮されすぎている
3. NOC は比較的見えるが、経路・サービス・利用者影響の因果が分離しきれていない
4. `Action Board` が「次に何をすべきか」を十分に強く誘導できていない
5. `M.I.O. Assist` が便利だが、根拠盤面との往復導線が弱い
6. `Temporary` モードは安全寄りだが、初心者の視線誘導としてはまだ重い

## 3. Round 1: 人間工学レビュー

### 否定的レビュー

`Human Factors AI`:
- 画面上のカード数が多く、初見では視線の入口が分散する
- `Command Strip` の後に何を見るべきかが明確でない
- 重要カードと背景カードのコントラスト差が弱い

`Frontend Architect AI`:
- 見出しの階層はあるが、優先度の段差が弱い
- `Action Board` と `Situation Board` の重みが近く、意思決定に必要な視線誘導が足りない

`Temporary Operator Support AI`:
- Temporary でも画面全体がまだ重い
- まず一手目を明示する「大きな 1 カード」が必要

### 協議結果

- main dashboard の最優先導線を `Current Mission` として独立させるべき
- `Action Board` の中でも、最初に見るべき 1 枚を最前面に出すべき
- 一般カードと critical カードの視覚差を拡大すべき

### 修正方針

1. `Action Board` を再分割
2. `Current Mission` カードを新設
3. `Evidence` を一段沈める

## 4. Round 2: SOC 観点レビュー

### 否定的レビュー

`SOC Analyst AI`:
- Threat Posture に score はあるが、SOC オペレータが次に見るべき threat evidence への導線が弱い
- 相関、ATT&CK、Sigma、YARA、TI が explanation の内側に入り、盤面上の存在感が薄い
- 「なぜ今 throttle / redirect / isolate でないのか」が即読できない

`Security Architect AI`:
- 強い action を抑制した理由が UI 上で見えにくいのは危険
- operator が「もっと強く止めるべきか」を判断する材料が弱い

### 協議結果

- SOC 専用の `Threat Evidence Summary` が必要
- `Action Board` に `why not stronger action` を独立表示すべき
- `ATT&CK / D3FEND / Sigma / YARA / TI` は explanation 埋め込みではなく要約カード化すべき

### 修正方針

1. `Threat Evidence Summary` 新設
2. `Rejected Stronger Actions` を前面化
3. ATT&CK 系は SOC ビューの 1 段目へ引き上げ

## 5. Round 3: NOC 観点レビュー

### 否定的レビュー

`NOC Operator AI`:
- 現在の NOC 情報はあるが、どの障害が uplink 由来で、どれが service 由来で、どれが user impact 由来かが視覚的に分かれない
- `Gateway / DNS / Captive Portal / Services` が並列表示のため、切り分け順序が UI から読み取れない
- multi-segment / multi-uplink を評価できるのに UI では出し切れていない

`Observability Engineer AI`:
- 経路異常と service 異常を同一レベルで出すのは誤読の元
- `NOC Path`, `NOC Services`, `NOC Client Impact` は別ブロックに分けるべき

### 協議結果

- NOC 部分は現在の 1 カードでは不足
- `Path`, `Service`, `Client Impact` の 3 分割が必要
- uplink が複数ある前提の比較表示を持つべき

### 修正方針

1. `Network Health` を `Path Health` と `Client Reachability` に分離
2. `Service Health` を独立拡大
3. `Client Impact` カードを新設

## 6. Round 4: 初心者 / Temporary 観点レビュー

### 否定的レビュー

`Temporary Operator Support AI`:
- `Temporary Triage` のボタンは有用だが、結果的に operator 密度の画面に埋もれている
- 初心者に必要なのは「次に何を聞くか」「何を伝えるか」「何を触るな」の 3 要素であり、今は散らばっている

`Human Factors AI`:
- 色と情報量の観点で、Temporary はまだ Professional 画面の縮退版に見える
- 役割別 UI としては不十分

### 協議結果

- Temporary は同一画面内切替のままでも、最上段に `Temporary Mission Card` を出す必要がある
- 危険操作は非表示だけでなく、視線に入らない位置まで後退させるべき

### 修正方針

1. `Temporary Mission Card` 追加
2. Temporary 中は `Current Mission`, `Ask the user`, `Tell the user`, `Do not do` を最上段表示
3. `Gateway Controls` は画面下段に退避

## 7. Round 5: M.I.O. 支援導線レビュー

### 否定的レビュー

`Incident Commander AI`:
- M.I.O. は補助線として正しいが、現状は「右にある別パネル」で終わりやすい
- Operator が判断盤面から M.I.O. に質問し、また盤面へ戻るまでの 1 サイクルが弱い

`Frontend Architect AI`:
- `Ask M.I.O.` と `M.I.O. Assist` はあるが、各ボードとの対応関係が明示されていない

### 協議結果

- M.I.O. は単独パネルではなく `contextual assist` へ寄せるべき
- 各ボードから `Ask about this` を設けるべき

### 修正方針

1. `Situation`, `Action`, `Evidence` 各ボードに contextual ask を追加
2. M.I.O. パネルを `global status + last answer + next handoff` に限定
3. 詳細対話は `/ops-comm` に逃がす

## 8. Round 6: 最終レビュー

### 否定的レビュー

`Security Architect AI`:
- 画面を増やしすぎると認知負荷が上がる
- ブロックを増やすだけでは逆効果になり得る

`Human Factors AI`:
- 再設計案が正しくても、要素が増えればまた読みにくくなる

`Incident Commander AI`:
- 最優先は「何が起きているか」ではなく「今この端末の前の担当者は何をすべきか」だ

### 協議結果

- 再設計は「カード追加」ではなく「責務の再配置」として行う
- 最上段は `Mission -> Threat/NOC split -> Action -> Evidence -> Assist` の順で固定
- main dashboard は最終的に「作戦盤」として使う

## 9. 裁定

### 9.1 人間工学

現行 dashboard は「読める」が、「一目で迷わない」段階には達していない。

裁定:
- 現状は `部分合格`
- main dashboard はもう一段の再設計が必要

### 9.2 SOC 機能

現行 dashboard は SOC の生データと explanation は持っているが、SOC operator の判断盤面としては evidence の前面化が不足している。

裁定:
- 現状は `最低限の SOC support`
- `Threat Evidence Summary` と `stronger action rejection` を前面化しない限り、完成とは言えない

### 9.3 NOC 機能

現行 dashboard は NOC としては比較的成立しているが、path/service/client impact の分離が弱い。

裁定:
- 現状は `実用可能な NOC dashboard`
- ただし multi-uplink / multi-segment を見せ切る追加再編が必要

## 10. 最終再設計案

### 10.1 目標構造

1. `Mission Row`
- 今の最優先任務
- operator が今見るべき理由
- stale / live 判定

2. `SOC / NOC Split Board`
- 左: SOC Threat Evidence Summary
- 右: NOC Path / Services / Client Impact

3. `Action Board`
- chosen action
- why chosen
- why not stronger
- do next
- do not do

4. `Temporary Mission Layer`
- Temporary 時だけ最上段へ繰り上げ

5. `Evidence Timeline`
- 現在 trigger
- 変更履歴
- operator interaction
- background

6. `M.I.O. Assist`
- last answer
- rationale
- handoff
- contextual ask links

### 10.2 優先実装順

#### Phase A: Human Factors Fix
- `Current Mission` 追加
- `Action Board` の最優先カード化
- `Evidence` の沈下
- 状態: 実装済み

#### Phase B: SOC Focus
- `Threat Evidence Summary`
- `Rejected Stronger Actions`
- `ATT&CK / D3FEND / Sigma / YARA / TI` の要約化
- 状態: 実装済み

#### Phase C: NOC Focus
- `Path Health`
- `Service Health`
- `Client Impact`
- `multi-uplink comparison`
- 状態: 実装済み

#### Phase D: Temporary Mode
- `Temporary Mission Card`
- `Ask / Tell / Do not do` の再配置
- danger controls を視界外へ退避
- 状態: 実装済み

#### Phase E: M.I.O. Contextual Assist
- 各ボードに `Ask about this`
- M.I.O. パネルを status / rationale / handoff に限定
- 状態: 実装済み

## 11. 実装前提

1. 現行 API を壊さず、表示レイヤを中心に再構成する
2. 追加が必要な API は最小限にとどめる
3. Dashboard と `ops-comm` は役割分担を明確にする
4. main dashboard は「盤面」、`ops-comm` は「対話」と割り切る

## 12. 結論

現行 dashboard は破綻していない。
しかし、

- 人間工学的にはまだ詰め切れていない
- SOC としては evidence 前面化が不足
- NOC としては path/service/client impact の分離が不足

という明確な欠点がある。

したがって、次の main dashboard 作業は見た目の小修正ではなく、

- `Mission Row`
- `SOC / NOC split`
- `Action clarity`
- `Temporary mission layer`
- `contextual M.I.O.`

を軸に再設計として進めるのが正しい。
