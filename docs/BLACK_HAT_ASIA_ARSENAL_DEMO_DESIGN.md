# Black Hat Asia Arsenal 向け Azazel-Edge デモ設計

最終更新: 2026-03-16
対象: Black Hat Asia Arsenal ブース展示
前提: 展示説明は Azazel-Pi の公開アブストと整合しつつ、実機は Azazel-Edge を使用する

## 1. 結論

展示では Azazel-Edge の全機能を見せない。
`Arsenal Compatibility Demo` として、以下の一本線だけを見せる。

1. 攻撃トラフィックを入れる
2. Suricata が検知する
3. deterministic な `Mock-LLM Scorer` が 0-100 を付ける
4. スコア帯域に応じて自動ポリシーが変わる
5. `tc` / `nftables` / decoy redirect が発動する
6. Web UI と e-paper が状態を同時表示する

この構成なら、アブストと矛盾せず、30-60 秒で理解でき、Azazel-Edge の将来拡張も邪魔しない。

## 2. デモの基本方針

Azazel-Edge は本来、

- Tactical Engine
- Evidence Plane
- NOC evaluator
- SOC evaluator
- Action Arbiter
- Decision Explanation
- AI assist

を持つ。

ただし Arsenal では、これをそのまま出すと説明過多になる。

そのため展示では、

- 見せる名称はアブスト互換
- 内部実装は Azazel-Edge のまま
- 高度機能は裏方に退避

とする。

展示上の見せ方は次の通り。

| 展示ラベル | 実体 |
|---|---|
| Suricata Detection | `suricata_eve`, `evidence_plane/suricata.py` |
| Mock-LLM Scorer | `tactics_engine/scorer.py` を deterministic scorer として使用 |
| Policy Band Controller | `arbiter/action.py` と制御アダプタ群 |
| Traffic Shaping | `tc` による遅延/帯域制御 |
| Micro Policy | `nftables` / 必要時 `iptables` |
| Decoy Redirect | `opencanary_redirect.py` + OpenCanary |
| Status Display | Web UI + EPD |

## 3. 機能分類

### CATEGORY A: Black Hat Asia で必ず見せるべき機能

1. Suricata によるイベント検知
   理由: アブスト直結、見てすぐ分かる、トリガとして最も分かりやすい。

2. deterministic `Mock-LLM Scorer` による 0-100 のスコア表示
   理由: アブスト中心。来場者は「AI風だが再現可能」という点をすぐ理解できる。

3. スコア帯域ごとの自動ポリシー制御
   理由: 展示の肝。検知だけでなく制御まで繋がることを見せる必要がある。

4. `tc` による遅延/帯域制御
   理由: 「軽い制御」を見せる最も分かりやすい実演要素。

5. `nftables` / `iptables` によるマイクロポリシー
   理由: スコア上昇で通信条件が変わることを短時間で見せやすい。

6. OpenCanary などのデコイへの選択的 NAT 誘導
   理由: Arsenal 的に映える。防御の次の段階として強い印象を残せる。

7. オフライン動作
   理由: Black Hat の会場環境でも再現しやすく、説明価値も高い。

8. e-paper による状態表示
   理由: ブースの視認性が高い。Web UI だけより強い。

### CATEGORY B: 内部では使うが展示では強調しない機能

1. Tactical Engine
   理由: 内部の first-pass として有用だが、展示では `Mock-LLM Scorer` の一語に畳んだほうが伝わる。

2. Evidence Plane
   理由: 実装基盤として重要だが、展示で説明すると抽象度が高い。

3. SOC evaluator / NOC evaluator
   理由: Azazel-Edge らしさではあるが、Arsenal アブストの中心ではない。

4. Action Arbiter
   理由: 自動制御判断の実体として必要。ただし前面に出すより `policy band` の裏側に置く。

5. Decision Explanation
   理由: 質問対応には効くが、30 秒デモの主役ではない。

6. audit / state persistence
   理由: 安定運用のためには必要。ただし見せても理解に寄与しにくい。

7. internal SoT / client identity / NOC inventory
   理由: Azazel-Edge の運用面では重要だが、今回のアブスト中心軸からは外れる。

### CATEGORY C: 展示では見せない機能

1. AI assist / Ollama / LLM fallback
   理由: アブストの主役ではない。ここを出すと `Mock-LLM Scorer` の deterministic 性がぼやける。

2. M.I.O. / ops-comm / Mattermost
   理由: 説明コストが高く、ブースでの 30-60 秒デモから外れる。

3. 高度な NOC 可視化
   理由: 面白いが、展示軸が「検知 → スコア → 制御」からぶれる。

4. 詳細な decision trace / rejected alternatives
   理由: 深掘り質問用。通常の展示導線には不要。

5. Beginner onboarding / progress checklist / handoff pack
   理由: 運用 UI としては有用だが、Arsenal デモではノイズになる。

6. 将来構想としての enterprise SIEM/SOC/NOC 拡張
   理由: 今回の展示スコープを超える。

## 4. なぜこの切り分けが必要か

### 批判 1: Azazel-Edge の強みを隠しすぎではないか

反論:
強みを全部出すと展示の主題が崩れる。
Arsenal で必要なのは「広さ」ではなく「一本で伝わること」。

### 批判 2: NOC 機能や AI assist を見せないのは損ではないか

反論:
損ではあるが、主デモの可読性を優先すべき。
質問されたら「これは Azazel-Edge では裏で保持しているが、今回の展示は Azazel-Pi アブスト互換に絞っている」と答える。

### 批判 3: `Mock-LLM Scorer` は実体が LLM でなくてもよいのか

反論:
よい。むしろ deterministic であることが Black Hat の live demo には向いている。
重要なのは名称ではなく、アブストが説明する「LLM風のスコア層」を再現し、しかも再現性が高いこと。

### 批判 4: Azazel-Edge の UI は情報量が多すぎないか

反論:
その通り。展示では通常 UI をそのまま見せず、`Arsenal Compatibility Demo` 表示に絞るべき。

### 批判 5: すべて live 連動で見せる必要があるか

反論:
必要なのは「live に見える一貫した挙動」であり、全てが外部依存の live である必要はない。
オフライン deterministic demo がむしろ正しい。

## 5. 展示用機能セット

展示で前面に出す構成は以下で固定する。

### 5.1 必須表示面

1. Attack Generator
2. Suricata Alert
3. Risk Score Meter
4. Policy Band
5. Active Control
6. Decoy Redirect Status
7. EPD Status

### 5.2 表示ルール

- 上から下へ読むだけで意味が分かる
- 数値は 0-100 のスコアを主役にする
- 説明文は短くする
- NOC/SOC/AI などの内部用語は主画面に出しすぎない
- 来場者が立った位置からでも `NORMAL / THROTTLE / REDIRECT` が読めるようにする

### 5.3 推奨スコア帯域

| スコア帯域 | 展示ラベル | 自動制御 | 説明 |
|---|---|---|---|
| 0-29 | NORMAL | 制御なし | 通常状態 |
| 30-59 | WATCH | ログ強化 / 監視継続 | 検知はあるが通信は維持 |
| 60-79 | THROTTLE | `tc` で遅延/帯域制御 | 可逆な軽制御 |
| 80-89 | MICRO-POLICY | `nftables` / `iptables` で限定制御 | 影響範囲を絞る |
| 90-100 | DECOY REDIRECT | OpenCanary へ選択的 NAT 誘導 | 高リスク時の強い可逆制御 |

補足:
`isolate` は内部には残してよいが、展示では基本的に見せない。
理由は強すぎる制御であり、Black Hat ブースの 30 秒デモには過剰だから。

## 6. デモ構成図

```text
 [Attacker Laptop]
        |
        | demo traffic
        v
 [Azazel-Edge ingress]
        |
        +--> Suricata detect
        |        |
        |        v
        |   Mock-LLM Scorer (0-100, deterministic)
        |        |
        |        v
        |   Policy Band Controller
        |      |        |          |
        |      |        |          +--> OpenCanary redirect
        |      |        +-------------> nftables / iptables micro-policy
        |      +----------------------> tc delay / bandwidth shaping
        |
        +--> Web UI status
        |
        +--> e-paper status
```

## 7. 30-60 秒デモシナリオ

### 7.1 標準シナリオ

0-10 秒:

- 画面は `NORMAL`
- EPD も `NORMAL`
- Web UI は `Score 12` 程度

10-20 秒:

- 攻撃トラフィックを送る
- Suricata が alert を出す
- UI の `Suricata Detection` が点灯

20-30 秒:

- Scorer が `72` を出す
- `Policy Band` が `THROTTLE` に変わる
- `tc` 制御が入る
- EPD が `WATCH` または `THROTTLE` を表示

30-45 秒:

- より強い攻撃パターンを送る
- Scorer が `91` に上がる
- `Policy Band` が `DECOY REDIRECT`
- OpenCanary への redirect が有効化される

45-60 秒:

- 来場者に「検知から制御までがオフラインで自律完結する」と説明
- 画面で `Suricata -> Score -> Policy -> Decoy -> EPD` を再確認

### 7.2 最短 30 秒版

1. 平常表示
2. 攻撃送信
3. スコア上昇
4. `tc` で遅延
5. `DECOY REDIRECT`
6. EPD 更新

## 8. Azazel-Edge 内部構成との対応表

| 展示要素 | Azazel-Edge 内部モジュール | 扱い |
|---|---|---|
| Suricata detection | `py/azazel_edge/evidence_plane/suricata.py` | そのまま使う |
| Mock-LLM Scorer | `py/azazel_edge/tactics_engine/scorer.py` | 表示名だけ展示用に変更 |
| Policy band controller | `py/azazel_edge/arbiter/action.py` | 展示向けの帯域制御プロファイルを定義 |
| Decoy redirect | `py/azazel_edge/opencanary_redirect.py` | そのまま使う |
| Deterministic replay/demo | `py/azazel_edge/demo/scenarios.py` | 展示シナリオ用に追加・調整 |
| EPD | `py/azazel_edge_epd.py`, `py/azazel_edge_epd_mode_refresh.py` | 表示文言を展示向けに簡素化 |
| Web UI | `azazel_edge_web/*` | Arsenal 互換表示を追加 |
| NOC/SOC evaluators | `py/azazel_edge/evaluators/*` | 内部使用、主画面では前面に出さない |
| AI assist | `py/azazel_edge_ai/agent.py` | 今回の展示では非主役、基本非表示 |

## 9. 展示時に説明すべきメッセージ

### 9.1 15 秒版

```text
Azazel-Edge detects traffic with Suricata, assigns a deterministic 0-100 risk score, and automatically shifts into reversible policy control, including shaping, micro-policy, and decoy redirect, all offline.
```

### 9.2 30 秒版

```text
This demo is intentionally minimal and matches the Arsenal abstract.
Suricata detects the event, a deterministic Mock-LLM Scorer assigns a risk score, the score band selects a policy, tc and firewall policy apply bounded control, and high-risk traffic can be redirected into a decoy. The web UI and e-paper show the same state, and the whole flow works offline.
```

### 9.3 質問された時だけ話す内容

- Azazel-Edge には本来 NOC/SOC 分離評価や AI assist がある
- ただし今回の展示は Azazel-Pi アブストと矛盾しない最小構成に絞っている
- つまり「中身は Azazel-Edge、見せ方は Arsenal 互換モード」である

## 10. 実装計画

### Phase 1: 展示互換レイヤ作成

1. `Arsenal Compatibility Demo` という表示プロファイルを追加
2. UI ラベルを展示用に整理
3. `Mock-LLM Scorer` の説明文を固定

受け入れ条件:

- UI を初見で見た人が `Suricata -> Score -> Policy -> EPD` を追える
- NOC/SOC/M.I.O. などの用語が主画面で主役にならない

### Phase 2: スコア帯域と制御の一本化

1. 0-100 スコア帯域を固定
2. 帯域ごとの制御を `WATCH / THROTTLE / MICRO-POLICY / DECOY REDIRECT` に対応づけ
3. `isolate` は展示経路から外す

受け入れ条件:

- スコア上昇に対して制御が一貫して変わる
- 説明なしでも「高スコアほど強い制御」が分かる

### Phase 3: デモシナリオ固定

1. `arsenal_low_watch`
   - `Ping Sweep`
   - WATCH 帯域
2. `arsenal_throttle`
   - `SSH Brute Force`
   - ambiguity band -> local Ollama review -> THROTTLE
3. `arsenal_decoy_redirect`
   - `Exploit Probe / RCE Beacon`
   - DECOY REDIRECT 帯域

の 3 本を用意する。

受け入れ条件:

- どのシナリオも 30-60 秒で終わる
- 会場ネットワーク非依存で再現できる

実行コマンド:

```bash
bin/azazel-edge-arsenal-demo list
bin/azazel-edge-arsenal-demo run arsenal_throttle
bin/azazel-edge-arsenal-demo flow --keep-final
bin/azazel-edge-arsenal-demo clear
bin/azazel-edge-arsenal-demo menu
```

補足:

- `run` と `flow` はデフォルトで overlay を書く
- 機械可読 JSON が必要な場合は `--format json`
- 外部スクリプト連携には `--state-out /path/to/state.json`
- ブースでの手動操作には `menu` を使うと
  - 個別攻撃の選択
  - 連続実行
  - 全クリア
  をその場で選べる

### Phase 4: EPD と Web UI の整合

1. Web UI の状態語と EPD の状態語を統一
2. `NORMAL / WATCH / THROTTLE / REDIRECT`
   を優先表示にする
3. 読みすぎない短文にする

受け入れ条件:

- EPD と Web UI を見比べたときに状態解釈がぶれない

### Phase 5: ブース運用手順

1. 平常状態に戻すリセット手順
2. シナリオ再実行手順
3. オフライン時の起動確認手順
4. デコイ/制御の解除確認

受け入れ条件:

- 誰がブースに立っても同じ 1 分デモを再現できる

## 11. 最終判断

本件で採るべき設計は、

- Azazel-Edge の全機能を見せる設計ではない
- Azazel-Pi アブストを Azazel-Edge 上で再現する設計である
- そのために `Arsenal Compatibility Demo` を前面に置く

である。

これにより、

1. アブストと一致する
2. 30-60 秒で理解できる
3. Azazel-Edge の将来拡張と矛盾しない

の 3 条件を同時に満たせる。
