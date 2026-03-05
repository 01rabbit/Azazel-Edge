# Azazel-Edge

内部ネットワーク向けインストーラです。`wlan0` をアクセスポイントとして起動し、`br0` 上で DHCP 配布を行います。

## 構成内容
- `NetworkManager` で内部ブリッジを永続化
- `br0` に `172.16.0.254/24` を設定
- `eth0` を `br0` の slave として接続
- `wlan0` を AP モード (`master=br0`) で起動
- `dnsmasq` で DHCP 配布
  - 配布レンジ: `172.16.0.101-172.16.0.200`
  - Gateway/DNS: `172.16.0.254`
- 既存の `eth0` 自動接続プロファイル競合を無効化（`eth0` の bridge 参加を固定）
- `avahi-daemon` 有効化（`.local` 維持）
- `sshd` は既定で `ListenAddress 172.16.0.254`（内部専用）
- `nftables` で `br0 -> WAN` の NAT/forward を設定（既定: デフォルトルートのIF）

外部WAN (`eth1`/`wlan1`) の uplink は自動検出（必要なら `WAN_IF` で上書き）します。OpenCanary・policy routing は対象外です。

## 実行
```bash
cd /home/azazel/Azazel-Edge
sudo AP_SSID='Azazel-Internal' AP_PSK='yourStrongPass123' ./installer/internal/install_internal_network.sh
```

`AP_SSID` と `AP_PSK` を省略するとデフォルト値が使われます。

## ワンショット統合インストーラ
内部ネットワーク + アプリスタック + （任意）開発用リモート許可を1回で実行:

```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_DEV_REMOTE_ACCESS=1 DEV_REMOTE_MODE=open ./installer/internal/install_all.sh
```

主な切替変数:
- `ENABLE_INTERNAL_NETWORK=1|0`（既定: 1）
- `ENABLE_APP_STACK=1|0`（既定: 1）
- `ENABLE_DEV_REMOTE_ACCESS=1|0`（既定: 0）
- `DEV_REMOTE_MODE=open|close`（既定: open）

Rust防御コアは既定で導入されます（完全移行モード）。明示的に再導入する場合:
```bash
cd /home/azazel/Azazel-Edge
sudo ENABLE_RUST_CORE=1 ./installer/internal/install_migrated_tools.sh
```

関連サービス:
- `azazel-edge-core.service`（Rustイベントエンジン）
- `azazel-edge-ai-agent.service`（Python AI支援）

設計資料:
- `docs/ARCHITECTURE_REDESIGN.md`

## 反映後チェック
```bash
nmcli -t -f DEVICE,STATE,CONNECTION dev
ip addr show br0
systemctl status dnsmasq --no-pager
systemctl status avahi-daemon --no-pager
```

DHCP確認（接続端末側）:
- APに接続して `172.16.0.101-200` が払い出されること
- `eth0` 接続端末でも同レンジが払い出されること

内部端末からの管理SSH確認:
```bash
ssh azazel@Azazel-Edge.local
```

## 開発期間: 外部/内部から同時アクセスを許可
開発期間中に、外部ネットワークと内部ネットワークの両方からアクセスできる設定へ切り替えるには:

```bash
cd /home/azazel/Azazel-Edge
sudo MODE=open DEVICE_HOSTNAME=Azazel-Edge ./installer/internal/set_dev_remote_access.sh
```

この設定で以下を実施します:
- SSH を全インターフェースで待受（VSCode Remote-SSH 利用可）
- Avahi を `br0` + WAN IF で有効化し、`.local` を広報
- UFW 有効時は `22/tcp` を許可

開発終了後に戻す:
```bash
cd /home/azazel/Azazel-Edge
sudo MODE=close DEVICE_HOSTNAME=Azazel-Edge ./installer/internal/set_dev_remote_access.sh
```

注意:
- `.local` は mDNS 依存のため、外部クライアント環境によっては名前解決できません。
- その場合は外部クライアント側の hosts に `WAN_IP Azazel-Edge.local` を追加してください。

## Azazel-Gadget からの移植（ネットワーク非影響）
- `bin/azazel-edge-path-schema`
  - パススキーマ状態確認/移行ツール
  - `status` は参照のみ
  - `migrate --dry-run` は変更なしで計画表示
- `py/azazel_edge/path_schema.py`
  - パス候補解決とスキーマ移行ロジック
- `py/azazel_edge/tactics_engine/config_hash.py`
  - 設定の SHA256 計算/検証ユーティリティ
- `py/azazel_edge/tactics_engine/decision_logger.py`
  - 意思決定レコードを JSONL に追記するロガー
- `py/azazel_edge/tactics_engine/eve_parser.py`
  - EVE JSON を破損耐性つきで解析するパーサ

インストール（移植した順）:
```bash
cd /home/azazel/Azazel-Edge
sudo ./installer/internal/install_migrated_tools.sh
```

使用例:
```bash
cd /home/azazel/Azazel-Edge
/usr/local/bin/azazel-edge-path-schema status
PYTHONPATH=/opt/azazel-edge/py python3 -c "from azazel_edge.tactics_engine.config_hash import ConfigHash; print(ConfigHash.compute(config_dict={'mode':'shield'}))"
PYTHONPATH=/opt/azazel-edge/py python3 -c "from azazel_edge.tactics_engine import EVEParser; p=EVEParser(); print(p.parse_line('{\"alert\":{\"sid\":1}}'))"
```

## WebUI / TUI / EPD 移植
以下を `Azazel-Edge` 名で移植・インストール済みです。
- WebUI: `azazel_edge_web/` + `azazel-edge-web.service`（`gunicorn` 本番WSGI）
- TUI: `py/azazel_edge/cli_unified.py` + `azazel-edge-tui`
- EPD: `py/azazel_edge_epd.py` / `py/azazel_edge_epd_mode_refresh.py` + `azazel-edge-epd-refresh.timer`
- Control API: `py/azazel_edge_control/daemon.py` + `azazel-edge-control-daemon.service`

実装済み機能:
- `azazel-edge-control-daemon` の Unix socket (`/run/azazel-edge/control.sock`) 経由で action API を処理
- `/api/mode`（mode状態取得・切替）
- `/api/action/*`（refresh/reprobe/contain/stage_open/disconnect/details/shutdown/reboot）
- `/api/wifi/scan`, `/api/wifi/connect`
- TUI/EPD は `azazel_edge` の snapshot/control API を使用

再インストール:
```bash
cd /home/azazel/Azazel-Edge
sudo ./installer/internal/install_migrated_tools.sh
```

他環境への構築:
1. このリポジトリを配置
2. `sudo ./installer/internal/install_migrated_tools.sh` を実行
3. 自動で以下を構成
   - `/opt/azazel-edge` 配下にコード/資産配置
   - `venv` 作成と `requirements/runtime.txt` から依存導入
   - `azazel-edge-control-daemon.service`
   - `azazel-edge-web.service`（gunicorn）
   - `azazel-edge-epd-refresh.timer`
   - `/usr/local/bin/azazel-edge-*` ランチャー配置

起動/確認:
```bash
systemctl status azazel-edge-control-daemon.service --no-pager
systemctl status azazel-edge-web.service --no-pager
systemctl status azazel-edge-epd-refresh.timer --no-pager
curl http://127.0.0.1:8084/health
curl http://127.0.0.1:8084/api/mode
curl -X POST http://127.0.0.1:8084/api/action/refresh
/usr/local/bin/azazel-edge-tui --help
/usr/local/bin/azazel-edge-epd --state normal --ssid "Azazel-Edge" --mode-label SHIELD --risk-status SAFE --signal -55 --dry-run
```
