# AGENTS.md — Azazel-Edge AI Agent Working Charter

最終更新: 2026-05-12
対象: このリポジトリで作業するすべての AI エージェント（Claude Code, GitHub Copilot, Cursor, その他）

---

## 0. このファイルの位置づけ

AGENTS.md は、複数メンバーが複数の AI エージェントを使って作業するときに、
思想・ルール・判断基準が一致するための **共通契約** である。

AI エージェントはこのファイルを作業開始時に必ず読み、内容に従って動く。
このファイルの内容と他のドキュメントが矛盾する場合、このファイルを優先する。
ただし `docs/P0_RUNTIME_ARCHITECTURE.md` のアーキテクチャ事実とは矛盾しないこと。

---

## 1. プロジェクトの本質的な目的

Azazel-Edge は **緊急時の簡易 SOC/NOC ゲートウェイ** である。

- 人が少ない、専門家がいない、時間がない状況での初動対応を支援する
- Raspberry Pi 上で動く。リソースは常に有限である
- オンプレミス AI（Ollama）を補助として使う。AI は主役ではない
- 決定論エンジンが判断する。AI はその説明と補助を担う

この本質を損なう変更、たとえば「AI に一次判断させる」「クラウド依存を増やす」
「Raspberry Pi では動かない重い処理を入れる」は、たとえ技術的に正しくても採用しない。

---

## 2. 設計の絶対原則（変えてはいけないもの）

### 2.1 Deterministic First

判断パイプラインの順序は固定である。AI エージェントはこの順序を変えない。

```
Tactical Engine (first-minute triage)
  ↓
Evidence Plane (正規化・スキーマ化)
  ↓
NOC Evaluator / SOC Evaluator (決定論評価)
  ↓
Action Arbiter (アクション決定)
  ↓
Decision Explanation (説明生成)
  ↓
Notification / AI Assist (通知・AI補助) ← AI はここから
  ↓
Audit Logger (監査ログ)
```

AI が判断パイプラインの上流（Evidence Plane より前）に入り込むコードは書かない。

### 2.2 AI は補助であり統治される

AI assist path に関するコードを変更・追加するとき、以下を守る。

- `py/azazel_edge/ai_governance.py` の guardrail を経由しない AI 呼び出しを追加しない
- AI の出力は `advice / summary / candidate` の 3 種に限定する
- AI が出した結果を、人間またはシステムのレビューなしにそのまま実行しない
- `adopt / fallback` の監査ログ記録を省略しない

### 2.3 Fail-Closed

セキュリティ判断において、デフォルトは「拒否・閉じる」である。

- 新しい認証エンドポイントを追加するとき、デフォルトは `AZAZEL_AUTH_FAIL_OPEN=0`
- トークンファイルが存在しない場合は保護エンドポイントをオープンにしない
- 新しいアクションタイプを追加するとき、`AZAZEL_DEFENSE_ENFORCE=false` のうちは
  必ず dry-run（ログのみ）として実装し、enforce=true に切り替える前に別途確認する

### 2.4 Raspberry Pi 制約を尊重する

- Python の新しい依存パッケージを追加するとき、`aarch64` で動作することを確認する
- メモリを多く消費する処理は `AZAZEL_OPS_MIN_MEM_AVAILABLE_MB` 相当のガードを設ける
- Ollama モデルは `4b` 以上を通常パスに入れない（同居運用では `2b` 以下が原則）
- Docker コンテナを増やすときはメモリ影響を必ず見積もりコメントに書く

---

## 3. コードを変更するときのルール

### 3.1 変更前に確認するファイル

| 変更対象 | 確認先ドキュメント |
|----------|-------------------|
| 評価器・アービター | `docs/P0_RUNTIME_ARCHITECTURE.md` §3 |
| AI 補助パス | `docs/AI_OPERATION_GUIDE.md` §1〜4 |
| M.I.O. の応答・文体 | `docs/MIO_PERSONA_PROFILE.md` |
| デモ・展示系 | `docs/POST_DEMO_MAIN_INTEGRATION_104.md` |
| ソケット権限 | `docs/POST_DEMO_SOCKET_PERMISSION_MODEL_105.md` |
| Runbook | `docs/AI_OPERATION_GUIDE.md` §11 |

変更する前に、関連ドキュメントを読んでいない場合は読む。
読まずに変更した場合、その変更は不完全とみなす。

### 3.2 テストの義務

コードを変更したら、関連するテストが通ることを確認する。

```bash
PYTHONPATH=. .venv/bin/pytest -q
```

- 新しい機能を追加したら、対応するテストを同じ PR に含める
- 既存のテストを削除・無効化する場合は、理由をコミットメッセージに書く
- `PYTHONPATH=py:. pytest -q` で 220 passed（+ subtests）が基準ライン。これを下回る変更はマージしない

Rust を変更した場合:

```bash
cd rust/azazel-edge-core && cargo test
```

### 3.3 コミットメッセージの形式

```
<type>(<scope>): <短い要約>

[本文: 任意。なぜこの変更をしたか、何を変えたか]
[Closes #<issue番号>: 関連 issue があれば]
```

type の候補:
- `feat`: 新機能
- `fix`: バグ修正
- `refactor`: 動作を変えないリファクタ
- `test`: テストのみの変更
- `docs`: ドキュメントのみの変更
- `chore`: ビルド・CI・設定の変更
- `security`: セキュリティ修正

scope の候補: `arbiter`, `evaluator`, `evidence`, `ai`, `web`, `rust`, `runbook`,
`installer`, `notify`, `audit`, `demo`, `mio`

### 3.4 やってはいけないこと

以下は AI エージェントが自律的に行ってはいけない。
必ず人間のレビューと明示的な承認を求める。

- `installer/` 配下のスクリプトの実行・変更
- `security/` 配下の Docker Compose の変更
- `systemd/` ユニットファイルの変更
- `/etc/azazel-edge/` に書き込むコードの追加
- `AZAZEL_AUTH_FAIL_OPEN` を `1` にするコードの追加
- `AZAZEL_DEFENSE_ENFORCE` を `true` にするコードの追加（dry-run 検証前）
- `controlled_exec` を無条件で有効にするコードの追加
- Runbook の `requires_approval` を `false` に変更すること

---

## 4. レイヤー別の作業ガイド

### 4.1 Evidence Plane を変更するとき

`py/azazel_edge/evidence_plane/` は入力正規化の層である。

- `schema.py` のフィールドを削除・リネームするとき、downstream の evaluator への影響を確認する
- 新しいデータソース（collector）を追加するとき、`bus.py` の型契約に合わせる
- `trace_id` は必ずすべてのイベントに付与する。省略しない

### 4.2 Evaluator / Arbiter を変更するとき

- NOC と SOC は分離して実装する。一方が他方に依存するコードを書かない
- Arbiter が返す `action` は `observe / notify / throttle / redirect / isolate` の 5 種のみ
  新しいアクション種別を追加するときは Issue を立てて議論する
- `why_chosen / why_not_others / evidence_ids / operator_wording` は必須フィールド。
  省略した Decision Explanation は不完全とみなす

### 4.3 AI Governance を変更するとき

`py/azazel_edge/ai_governance.py` はすべての AI 呼び出しの入口である。

- このファイルをバイパスする AI 呼び出しを他のモジュールに追加しない
- guardrail の条件を緩める変更は、セキュリティ影響を Issue に記載してからマージする
- `sanitized payload` の内容（何を AI に渡すか）を変えるときは audit log の schema も合わせる

### 4.4 Web / API を変更するとき

- 新しい API エンドポイントはデフォルトで token 保護する
  例外（`/health` 相当）を作るときはコメントに理由を書く
- Flask route に直接ビジネスロジックを書かない。evaluator / arbiter / governance 層を通す
- `/demo` 系のルートと本番ルートは混在させない（`POST_DEMO_MAIN_INTEGRATION_104.md` 参照）

### 4.5 Runbook を追加・変更するとき

`runbooks/` 配下の YAML は以下の構造を守る。

必須フィールド:
- `id`: `rb.<namespace>.<name>` 形式
- `title`
- `audience`: `operator` / `beginner` / `both`
- `type`: `read_only` / `operator_guidance` / `controlled_exec`
- `requires_approval`: bool
- `steps`: 1 件以上

`controlled_exec` タイプを追加するときは `requires_approval: true` を必ず設定する。
`read_only` タイプは dry-run が可能なものに限定する。

### 4.6 M.I.O. の応答に関わるコードを変更するとき

`docs/MIO_PERSONA_PROFILE.md` を読んでから変更する。

守るべき文体ルール:
- 冷静・明瞭・簡潔
- 根拠のない安心断定をしない（「大丈夫です」「問題ありません」は使わない）
- `beginner` 向けは 1 回答 3 手順まで、1 手順 1 行動
- `operator` 向けは `answer + rationale + runbook + review` の構造を持たせる
- M.I.O. は evaluator / arbiter の判断を上書きする文を生成しない

---

## 5. Issue・PR の作り方

### 5.1 Issue を立てるとき

タイトルは `[layer] 要約` 形式で書く。
例: `[arbiter] redirect アクション実装`, `[ai] Ops Guard のメモリ閾値を設定可能にする`

layer の候補: `arbiter`, `evaluator`, `evidence`, `ai`, `web`, `rust`, `runbook`,
`installer`, `notify`, `audit`, `demo`, `mio`, `security`, `docs`, `infra`

本文に含めるもの:
- なぜこの変更が必要か（動機）
- 変更によって何が変わるか（影響範囲）
- `Deterministic First` 原則への影響の有無

### 5.2 PR を作るとき

- 1 PR = 1 つの目的。複数の目的を 1 PR に混ぜない
- PR タイトルは `<type>(<scope>): <要約>` 形式（コミットメッセージと同じ）
- チェックリストに含めるもの:
  - [ ] `PYTHONPATH=. pytest -q` が通ることを確認した
  - [ ] 関連ドキュメントを読んだ（変更した場合は更新した）
  - [ ] `Deterministic First` 原則を損なっていない
  - [ ] Raspberry Pi 制約に影響しない（または影響を説明した）
  - [ ] セキュリティ関連の変更であればレビュアーを明示した

### 5.3 マージしてはいけない状態

- テストが 1 件でも落ちている
- `PYTHONPATH=.` なしでは動かない import を追加している
- AI エージェントが自律的に `installer/` `systemd/` `security/` を変更している
- Decision Explanation の必須フィールドが欠けている
- `AZAZEL_AUTH_FAIL_OPEN=1` をデフォルト化するコードが含まれている

---

## 6. ファイル・ディレクトリの扱い方

### 6.1 各ディレクトリの役割

```
py/azazel_edge/          Evidence Plane, evaluators, arbiter, audit, SoT, triage, demo
py/azazel_edge_control/  Control daemon とアクションハンドラ
py/azazel_edge_ai/       AI エージェント統合と M.I.O. 補助パス
azazel_edge_web/         Flask backend, dashboard, ops-comm UI
rust/azazel-edge-core/   Rust 防御コア（イベント取り込み・転送）
runbooks/                Runbook レジストリ（YAML）
systemd/                 systemd ユニットとタイマー
security/                Docker Compose スタック（Ollama, Mattermost, OpenCanary）
installer/               統合インストーラ（変更は慎重に）
docs/                    アーキテクチャ・運用・ペルソナドキュメント
tests/                   ユニット・回帰テスト（47 モジュール）
```

### 6.2 新しいファイルを追加するとき

- Python モジュールは適切な層のディレクトリに置く。`azazel_edge_web/` にビジネスロジックを置かない
- テストは `tests/test_<module>_v<N>.py` の命名規則に従う
- ドキュメントは `docs/` に置き、README や AGENTS.md から参照する
- 展示・デモ専用のファイルは `POST_DEMO_MAIN_INTEGRATION_104.md` の分類に従う

### 6.3 削除してはいけないファイル

以下は runtime に直結しているため、削除前に影響範囲を必ず確認する。

- `py/azazel_edge/ai_governance.py`
- `py/azazel_edge/audit/logger.py`
- `py/azazel_edge/arbiter/action.py`
- `azazel_edge_web/app.py`
- `installer/internal/verify_runtime_sync.sh`
- `systemd/` 配下のすべてのユニットファイル

---

## 7. 重要な環境変数リファレンス

AI エージェントがコードを読んだり書いたりするとき、以下の変数の意味を把握する。

| 変数名 | 意味 | デフォルト | 変更時の注意 |
|--------|------|-----------|-------------|
| `AZAZEL_AUTH_FAIL_OPEN` | 認証失敗時にオープンにするか | `0` (fail-closed) | `1` にする変更は人間レビュー必須 |
| `AZAZEL_DEFENSE_ENFORCE` | Rust コアの実行系を有効にするか | `false` | dry-run 検証後にのみ `true` |
| `AZAZEL_LLM_AMBIG_MIN/MAX` | LLM を呼ぶリスクスコア帯 | `60`〜`79` | 範囲を広げると LLM 負荷が増える |
| `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC` | controlled_exec Runbook の実行許可 | 未設定=無効 | 有効化は運用ポリシーの変更を伴う |
| `AZAZEL_OPS_MIN_MEM_AVAILABLE_MB` | Ops Coach 実行の最低空きメモリ | `1400` | 下げすぎると Raspberry Pi が不安定になる |
| `AZAZEL_CORR_WINDOW_SEC` | 相関検出の時間窓 | `300` | 長くするとメモリ使用量が増える |

---

## 8. AI エージェントへの具体的な指示

### 8.1 作業開始時にやること

1. このファイル（AGENTS.md）を読む ← 今やっている
2. 変更対象レイヤーの関連ドキュメントを読む（§3.1 の表を参照）
3. 現在の open issues を確認し、重複や衝突がないか確認する
4. `PYTHONPATH=. pytest -q` を実行し、ベースラインが通ることを確認する

### 8.2 不明なことがあったときの判断基準

以下の優先順で判断する。

1. AGENTS.md に明記されていればそれに従う
2. `docs/P0_RUNTIME_ARCHITECTURE.md` の事実と矛盾しないか確認する
3. 既存のテストコードから動作仕様を読み取る
4. それでも不明な場合は **作業を止めて人間に確認を求める**
   推測で「たぶんこうだろう」と実装を進めない

### 8.3 「Azazel らしさ」の判断軸

何かを追加・変更するとき、以下の問いに答えられるか確認する。

- この変更は「決定論エンジンが主、AI が補助」を守っているか？
- この変更は緊急時にオペレータの判断を **支援** しているか、それとも **代替** しているか？
- この変更は Raspberry Pi で動くか？
- この変更はオフラインでも（インターネット接続なしで）機能するか？
- この変更によって audit trail が失われないか？

すべてに「はい」と答えられない変更は、実装前に Issue で議論する。

### 8.4 禁止されているパターン

以下のコードパターンを書いたら、それは間違っている。

```python
# NG: AI が直接アクションを決定する
action = ai_agent.decide_action(event)  # evaluator / arbiter を通していない

# NG: AI governance をバイパスする
response = ollama.chat(model=..., messages=...)  # ai_governance.py 経由でない

# NG: audit なしの実行
run_command(action.command)  # audit logger を呼んでいない

# NG: 認証チェックのない API エンドポイント
@app.route("/api/sensitive", methods=["POST"])
def sensitive():  # @require_token デコレータがない
    ...

# NG: Decision Explanation の省略
return ActionDecision(action="isolate")  # why_chosen 等がない
```

---

## 9. 既知の未完成箇所（作業時に注意）

以下は現時点で未完成・既知の問題である。AI エージェントが意図せず触れないよう明示する。

| 箇所 | 状態 | 対応方針 |
|------|------|---------|
| `rust/azazel-edge-core/src/main.rs` の enforce path | dry-run 中心実装まで完了 | 実適用（enforced mode）の実機検証と運用ガードを継続 |
| `py/azazel_edge_epd.py --help` | 修正済み | 回帰テスト `tests/test_epd_cli_help_v1.py` で継続検証 |
| `.github/workflows/` | 追加済み | CI（python-tests / rust-tests）の安定運用を継続 |
| `LICENSE` | 追加済み（MIT） | README 記載との整合を維持 |

これらの箇所を「偶然直した」場合は、単独の PR として分離してコミットする。
他の変更と混ぜない。

---

## 10. ドキュメントの更新ルール

コードを変更したとき、以下の場合はドキュメントも同時に更新する。

| 変更内容 | 更新が必要なドキュメント |
|----------|-------------------------|
| 判断パイプラインの構造変更 | `docs/P0_RUNTIME_ARCHITECTURE.md` |
| AI しきい値・モデル設定の変更 | `docs/AI_OPERATION_GUIDE.md` §4 |
| M.I.O. 応答仕様の変更 | `docs/MIO_PERSONA_PROFILE.md` |
| 新しい環境変数の追加 | `docs/AI_OPERATION_GUIDE.md` + README.md |
| デモ/展示系資産の分類変更 | `docs/POST_DEMO_MAIN_INTEGRATION_104.md` |
| Runbook の追加・廃止 | 対象 YAML のコメント + `docs/AI_OPERATION_GUIDE.md` §11 |

「コードは変えたがドキュメントは後で」は認めない。
同じ PR にドキュメント更新を含める。

---

## Appendix A: 用語統一表

このリポジトリで使う用語を統一する。AI エージェントは以下の canonical term を使う。

| Canonical term | 説明 | 使ってはいけない言い換え |
|----------------|------|-------------------------|
| `Evidence Plane` | イベント正規化・バス層 | イベントパイプライン、ログ収集層 |
| `NOC Evaluator` | ネットワーク状態の決定論評価器 | NOC 監視、ネットワーク判定 |
| `SOC Evaluator` | セキュリティ状態の決定論評価器 | SOC 分析、セキュリティ判定 |
| `Action Arbiter` | アクション決定器 | 意思決定エンジン、AI 判断器 |
| `Decision Explanation` | 判断理由生成 | 説明可能 AI、XAI |
| `AI Assist Governance` | AI 補助の統治層 | AI フィルター、AI ガード |
| `M.I.O.` | Mission Intelligence Operator（運用人格） | AI キャラ、チャットボット、アシスタント |
| `deterministic path` | 決定論的判断経路 | ルールベース、ハードコードロジック |
| `controlled execution` | 承認付き実行 | 自動実行、AI 実行 |
| `Source of Truth (SoT)` | デバイス・ネットワーク・サービスの正解データ | マスターデータ、設定ファイル |
| `trace_id` | イベント追跡 ID | request_id, log_id |

---

*このファイルは `docs/` ではなくリポジトリルートに置く。*
*AI エージェントが自動的に読み込めるよう、ルートに配置することが慣例である。*
