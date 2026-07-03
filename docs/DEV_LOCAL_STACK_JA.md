# ローカル開発スタック起動ツール（JA）

## 目的
`bin/azazel-edge-devstack` は、macOS（Apple Silicon）の開発機上で Azazel-Edge のランタイム全体を一括起動するためのワンショット・ランチャーです。これまで `bin/azazel-edge-dev` はビルド／テスト用途（`bootstrap`、`test`、`rust-test`、`python`）のみをカバーしており、実際に動作中のサービス（control-daemon、ai-agent、Rust コア、Web ダッシュボード）をローカル LLM とローカル Mattermost に接続した状態で起動する手段がありませんでした。`azazel-edge-devstack` はそのギャップを埋め、依存関係の順序に従ってパイプライン全体をセーフモードで一括起動します。

このスタックは以下に接続します。
- **ollama** — ローカル LLM ランタイム。macOS の GUI アプリとして動作し、`qwen3.5:2b` を `http://127.0.0.1:11434` で提供します。
- **Mattermost** — OrbStack 上で `docker compose` により動作し、`http://localhost:8065` で到達可能です。

このランチャーは `bin/azazel-edge-dev` を置き換えるものではありません。ビルド／テストには `azazel-edge-dev` を、実行には `azazel-edge-devstack` を使用してください。

## 前提条件
- Apple Silicon 搭載の macOS。
- [OrbStack](https://orbstack.dev/)（または Docker Desktop 互換の他のエンジン）がインストールされ、起動していること（Mattermost 用）。
- Rust ツールチェーン（`cargo`）がインストールされていること（`rust/azazel-edge-core` のビルド用）。
- Python 3 がインストールされていること。
- [Ollama](https://ollama.com/) GUI アプリがインストールされ起動しており、`qwen3.5:2b` モデルが取得済みであること。
  ```bash
  ollama pull qwen3.5:2b
  ```

## クイックスタート
```bash
bin/azazel-edge-devstack up
```

依存関係のプリフライトチェック（必要に応じて Python venv の作成、Rust コアのビルド）を行った後、control-daemon → ai-agent → Rust コア → Web ダッシュボードの順に起動します。成功すると、以下を含むサマリーが表示されます。
- ダッシュボード URL と認証トークン
- Mattermost の URL
- ollama の状態（到達可否・モデル有無）

サマリーに表示されたダッシュボード URL をブラウザで開くと、稼働中のシステムを確認できます。Mattermost は `http://localhost:8065` で開けます。

パイプラインにライブデータを流してダッシュボードで確認したい場合は、`dummy-eve` テストイベント注入ツールを同時に起動します。
```bash
bin/azazel-edge-devstack up --inject
```

## コマンドリファレンス

| コマンド | フラグ | 説明 |
|---|---|---|
| `up`（デフォルト） | `--inject` | `dummy-eve` テストイベント注入ツールも起動し、パイプラインにライブデータを流す。 |
| | `--all` | 外部依存関係（OrbStack 経由の Mattermost）も（再）起動する。 |
| `down` | `--all` | azazel のプロセスを停止する。デフォルトでは Mattermost と ollama は起動したままにする。`--all` を指定すると Mattermost コンテナも停止する。`down` は ollama には一切手を加えない。 |
| `status` | — | 各コンポーネントの状態（起動中／停止中と PID）、および ollama／Mattermost の到達可否を表示する。 |
| `restart` | `--inject` | `down` の後に `up` を実行するのと同等。 |
| `logs [component]` | — | 指定したコンポーネントのログを tail する。コンポーネント未指定時は利用可能なログの一覧を表示する。 |

`up` は冪等です。すでに起動しているコンポーネントは再起動せずスキップされます。

## コンポーネントと起動順序
`up` は以下の順序でコンポーネントを起動します。

1. **control-daemon** — ランタイム状態とローカル制御ソケットを調整する。
2. **ai-agent** — ollama と接続し、LLM 支援によるトリアージ／アドバイザリ出力を行う。
3. **Rust コア**（`rust/azazel-edge-core`） — イベント正規化と決定論的な判断ループ。
4. **Web ダッシュボード** — オペレーター向け UI・API。

`--inject` を指定すると、`dummy-eve` テストイベント注入ツールも起動し、合成イベントをパイプラインに流してダッシュボードにライブな動きを表示します。

`--all` を指定すると、外部依存関係（現時点では `security/docker-compose.mattermost.yml` による OrbStack 上の Mattermost）が azazel コンポーネントより先に（再）起動されます。

ランタイムは**セーフモード**で動作します。防御機能はドライラン／アドバイザリのみで、`tools/macdev/env.sh` の `AZAZEL_DEFENSE_DRY_RUN=true` / `AZAZEL_DEFENSE_ENFORCE_LEVEL=advisory` に対応します。

## インジェクター — テスト／デモ操作パネル
`bin/azazel-edge-injector` は、テストイベント生成ツール `dummy-eve` の**自己完結型**フロントエンドです。開発環境（`tools/macdev/env.sh`）を自身で読み込むため、**devstack を起動していなくても単体で動作**し、Rust コアが監視する開発用 `eve.json` に模擬 Suricata EVE アラートを書き込みます。

2 つのモードがあります:

```bash
bin/azazel-edge-injector                              # 対話メニュー（デモ画面）
bin/azazel-edge-injector emit --scenario port_scan --count 5   # パススルー CLI
bin/azazel-edge-injector list                         # パススルー CLI
```

対話メニューは、ライブ状態（eve.json のイベント数、バックグラウンドストリームの稼働状態、パイプライン／ダッシュボードの起動有無）を表示し、次の操作ができます: シナリオ一覧、単発シナリオの発火、段階的な攻撃フローの実行、連続ストリームの開始／停止、直近イベントの表示、`eve.json` のリセット。

**デモの流れ:** まず `bin/azazel-edge-devstack up` を実行し、その後インジェクターのメニューから攻撃を発火して、実ダッシュボードが反応する様子を見せます。これがモック画面ではなく**ライブパイプライン注入でデモを駆動する**という意図された方法です。利用可能なシナリオ: `recon_probe`、`port_scan`、`arp_spoof`、`dns_exfil`、`cred_harvest`、`c2_beacon`、`phishing`、`benign`。（`up --inject` は連続ストリームを自動起動します。インジェクターのメニューは、シナリオ単位で手動操作したい場合に使います。）

## 環境設定
このランチャーは `tools/macdev/env.sh` を読み込み、（アプライアンスの Linux パスの代わりに）`~/.azazel-edge-dev` 配下に macOS 向けのランタイムパス、`PYTHONPATH`、ollama のエンドポイントを設定します。さらに `azazel-edge-devstack` は、ローカル開発向けにスタックの Mattermost 接続先を `127.0.0.1:8065` に向けます（アプライアンスのデフォルトは `172.16.0.254`）。

状態は `~/.azazel-edge-dev/` 配下に保持されます。
- PID ファイル: `~/.azazel-edge-dev/run/devstack/`
- ログ: `~/.azazel-edge-dev/log/devstack/`

## トラブルシューティング

**ollama に到達できない**
Ollama アプリを開きます: `open -a Ollama`。その後 `bin/azazel-edge-devstack status` で再確認してください。

**モデル `qwen3.5:2b` が見つからない**
```bash
ollama pull qwen3.5:2b
```
プリフライトチェックはモデル未取得を警告するのみで起動をブロックしません。ただし、モデルが存在しない間は AI エージェントが有用な出力を生成できません。

**Mattermost に到達できない**
OrbStack が起動しており、コンテナが立ち上がっているか確認します。
```bash
docker compose -f security/docker-compose.mattermost.yml ps
```
`bin/azazel-edge-devstack up --all` で、他のコンポーネントと合わせて Mattermost を（再）起動できます。

**ポートが既に使用されている**
ダッシュボード、制御ソケット、Mattermost の `8065` など、スタックが必要とするポートを別プロセスが使用している可能性があります。`bin/azazel-edge-devstack status` でランチャーが認識している起動状況を確認し、`lsof -i :<port>` で競合しているプロセスを特定してください。

**初回実行時に Rust のビルドが遅い**
既存のビルドが存在しない場合、初回の `up` は `rust/azazel-edge-core` をリリースモードでビルドします（`cargo build --release`）。これには数分かかることがあります。2 回目以降は既存のビルドを再利用し、即座に起動します。

**ログの場所**
```bash
bin/azazel-edge-devstack logs            # 利用可能なログの一覧
bin/azazel-edge-devstack logs ai-agent   # 特定コンポーネントのログを tail
```
ログの実体は `~/.azazel-edge-dev/log/devstack/` 配下にあります。

## 関連ドキュメント
- macOS 開発環境変数: `tools/macdev/env.sh`
- ビルド／テスト用ヘルパー: `bin/azazel-edge-dev`
- Mattermost の compose 定義: `security/docker-compose.mattermost.yml`
