# Azazel-Edge デモガイド

最終更新: 2026-03-12

## 目的

Azazel-Edge には、live runtime state を汚さずに判断経路を示すための deterministic demo pack が含まれています。

live 運用では判断経路を段階化しています。

1. Tactical Engine が first-minute triage を行う
2. Evidence Plane と deterministic evaluator が second-pass の文脈を付与する
3. AI は説明と operator 補助に限定する

デモ replay では次の流れを示します。

1. Evidence を共通モデルへ正規化する
2. NOC と SOC を分離して評価する
3. Action Arbiter が明示的に action を選ぶ
4. Decision Explanation が採用理由を記録する
5. Dashboard、`ops-comm`、TUI、EPD が一時的な demo overlay で結果を表示する

この demo pack は replay 経路です。live telemetry injection ではありません。
また、live の Tactical first-pass を置き換えるものでもありません。制御された形で deterministic な NOC/SOC/arbiter 経路を見せるための replay です。

## このデモで示せること

- 一次判断は AI に依存していない
- action selection の前に NOC と SOC を分離評価している
- action は明示的で、review と audit が可能である
- live control state を汚さずに判断経路を見せられる

## 利用可能な Scenario

- `mixed_correlation_demo`
  - メイン展示向け
  - cross-source evidence、correlation、explanation、action selection を一通り示せる
- `noc_degraded_demo`
  - 運用寄りの audience 向け
  - path health と device state の悪化を示す
- `soc_redirect_demo`
  - セキュリティ寄りの audience 向け
  - 高信頼 SOC path と reversible control の議論向け

## 推奨の見せ順

1. `mixed_correlation_demo`
2. `noc_degraded_demo`
3. `soc_redirect_demo`

1 本だけ見せるなら `mixed_correlation_demo` を使ってください。

## 事前確認

開始前に以下を確認します。

- `bin/azazel-edge-demo list` が成功する
- `bin/azazel-edge-demo run mixed_correlation_demo` が成功する
- Web UI の `/health` が `status=ok` を返す
- Dashboard から `/api/demo/scenarios` を取得できる
- M.I.O. も見せるなら `ops-comm` へ到達できる

## クイックスタート

### CLI

scenario 一覧:

```bash
bin/azazel-edge-demo list
bin/azazel-edge-arsenal-demo list
```

scenario 実行:

```bash
bin/azazel-edge-demo run mixed_correlation_demo
bin/azazel-edge-arsenal-demo run arsenal_low_watch
bin/azazel-edge-arsenal-demo run arsenal_throttle
bin/azazel-edge-arsenal-demo run arsenal_decoy_redirect
bin/azazel-edge-arsenal-demo flow --keep-final
bin/azazel-edge-arsenal-demo menu
```

Dashboard を使わず外部スクリプトから連携する場合:

```bash
bin/azazel-edge-arsenal-demo run arsenal_decoy_redirect --state-out /tmp/arsenal-demo-state.json
bin/azazel-edge-arsenal-demo flow --hold-sec 0 --keep-final --state-out /tmp/arsenal-demo-state.json
```

展示で使う攻撃シナリオ:

- `arsenal_low_watch`
  - `Ping Sweep`
- `arsenal_throttle`
  - `SSH Brute Force`
  - `Mock-LLM` の一次判定が ambiguity band に入るため、`Ollama Review` が可視化される
- `arsenal_decoy_redirect`
  - `Exploit Probe / RCE Beacon`

ブースでの手動操作:

```bash
bin/azazel-edge-arsenal-demo menu
```

選べる内容:

- 個別攻撃の実行
- 3 シナリオの連続実行
- 全クリア

### Web UI

開く URL:

- Dashboard: `https://172.16.0.254/`
- Ops workspace: `https://172.16.0.254/ops-comm`
- Arsenal 展示ページ: `https://172.16.0.254/arsenal-demo`

展示で推奨する表示面:

- Azazel-Pi 互換の見せ方にしたい場合は `/arsenal-demo` を使う
- Azazel-Edge の運用語彙を避けたい場合は通常の Dashboard を前面に出さない

展示で推奨する見せ順:

1. `Ping Sweep`
2. `SSH Brute Force`
3. `Exploit Probe / RCE Beacon`

Dashboard では次の順で操作します。

1. `Scenario Replay` を開く
2. scenario を選ぶ
3. `Run Demo` を押す
4. overlay 結果カードを確認する
5. 終わったら `Clear Demo Overlay` を押す

## デモ中に何が変わるか

デモ実行中は、presentation surfaces に一時 overlay が適用されます。

変化する面:

- Dashboard
- `ops-comm`
- TUI
- EPD

これは表示用 overlay であり、live control plane を真実のソースとして置き換えるものではありません。

## 画面上で見るべき場所

最初に見るべき場所は以下です。

1. `Current Mission`
2. `SOC / NOC Split Board`
3. `Immediate Action`
4. `Threat Evidence Summary`
5. `NOC Focus`
6. `Operator Wording`
7. `Next Checks`
8. `Chosen Evidence`
9. `Rejected Alternatives`

raw JSON から始めず、まず summary card を見せてください。

## 説明用の短い話し方

### 短い説明

```text
Azazel-Edge は NOC と SOC を分離して評価し、明示的な action を選び、その理由を記録したうえで、live runtime state を汚さずにその経路を replay できます。
```

### AI について聞かれた場合

```text
このデモでも AI は補助です。live 運用では Tactical Engine が first-minute の一次判断を行い、この replay では deterministic な second-pass 評価経路を示しています。
```

### live かと聞かれた場合

```text
いいえ。これは再現性を優先した deterministic replay です。live operator surface は別にあります。
```

## M.I.O. の見せ方

scenario 実行後は、次のいずれかで続けます。

### Dashboard

- `Ask about this` を使う
- M.I.O. が現在の action と次の確認事項をどう説明するか見せる

### `ops-comm`

- `Triage Navigator` または direct ask を使う
- 次のような質問をする
  - 現在の最優先懸念は何か
  - なぜこの action が選ばれたか
  - 次に何を確認すべきか

### Mattermost

例:

```text
/mio この demo で throttle が選ばれた理由と、次に確認すべき事項を示せ
```

## Web API

scenario 一覧:

```bash
curl -sS -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/scenarios | jq
```

scenario 実行:

```bash
curl -sS -X POST -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/run/mixed_correlation_demo | jq
```

overlay clear:

```bash
curl -sS -X POST -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/overlay/clear | jq
```

overlay state 取得:

```bash
curl -sS -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/overlay | jq
```

## トラブル時の確認

### `Scenario Replay` が空

次を確認します。

- `/api/demo/scenarios`
- Web UI を repository root から起動しているか

### Web UI で scenario replay が失敗する

同じ scenario を CLI で実行します。

```bash
bin/azazel-edge-demo run mixed_correlation_demo
```

CLI が動くなら replay path 自体は正常で、問題は web layer 側です。

### demo overlay が消えない

次を実行します。

```bash
curl -sS -X POST -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/overlay/clear | jq
```

その後、dashboard を再読み込みします。

### CLI-only demo に切り替える必要がある

問題ありません。replay runner は同じ deterministic scenario pack を使います。

## 関連文書

- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)
- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [Black Hat Asia Arsenal demo design](docs/BLACK_HAT_ASIA_ARSENAL_DEMO_DESIGN.md)
