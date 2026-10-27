# 実機初回検証チェックリスト（Raspberry Pi 5）

最終更新: 2026-10-27

Azazel-Edge を Raspberry Pi 5 実機に初めて導入し、確かめるための手順書です。
確認項目ごとに ID・コマンド・期待する結果・合否欄・関係する PR／issue を
載せています。英語版（正）:
[HARDWARE_FIRST_RUN_CHECKLIST.md](HARDWARE_FIRST_RUN_CHECKLIST.md)。

Refs #408（R0）、#372（Pi クラスの HIL）、#471（権限の分離）、#477（硬化）。

## 0. この手順書の前提

- `main` に **#479〜#488 と #490** が入っていること（すべてマージ済み。
  #490: control.sock の権限不足で TUI が `PermissionError`、HIL の
  `FileNotFoundError`）。それらを含む `main` から導入します（2.3）。
  チェックアウトに入っていない PR が付いた行は対象外です。合否欄には
  `N/A（PR 未マージ）` と書き、`pass` にはしません。
- **#489**（ホストの入力フィルタ、WAN 既定拒否）は draft で、**既定で無効**
  です。[3.13](#313-ホストファイアウォールの試行489draft任意) で、#489 の
  ブランチを使って別に試し、最後に元に戻します。#489 がマージされた後は
  `main` のチェックアウトに含まれる（`installer/internal/azazel-host-firewall`
  がある）ので、3.13 は `main` で行います（3.13 の冒頭を参照）。
- これらの PR に書かれた結果は、すべてコンテナか VM のものです。**どれも実機の
  証拠ではありません**。今回が最初の実機の確認です。コンテナの結果をこの表に
  `pass` として写さないでください。
- 以下のコマンド・パス・アカウント名・ポートは、上の PR のブランチのコードと
  1 つずつ照合しました。そうして確かめられなかったものは **（要確認）** と
  書いてあり、今回の実機で確かめる対象です。

置き換える値: `<pi-user>` は SD カードを書くときに作ったログインアカウント、
`<CC>` は 1.3 で決めた Wi-Fi の国コード、`<WAN_IF>` は上流の IF（USB Ethernet か USB Wi-Fi）、`<WAN-ADDR>` は上流で
得たアドレス（`ip -4 -br addr show <WAN_IF>`）、`<hostname>` は機器のホスト名。
LAN のアドレス `172.16.0.254` と LAN `172.16.0.0/24` は
`installer/internal/install_internal_network.sh` で固定です。

## 1. 準備

### 1.1 ハードウェア

| 物 | 注意 |
| --- | --- |
| Raspberry Pi 5 | 8 GB を推奨（Ollama のモデル、任意の Mattermost をエミュレーションで動かすため）。RAM の容量を記録する。 |
| 電源 | USB-C 5 V / 5 A（[PHYSICAL_SETUP_GUIDE.md](PHYSICAL_SETUP_GUIDE.md) §2 のラベルは 5V/5A MIN）。R0 の電力（3.12）用に USB-C のインライン電力計。 |
| 起動媒体 | 産業用 SD カードか USB/NVMe の SSD。Ollama のモデルと Docker イメージで数 GB 使う。容量と導入後の空きを記録する。 |
| EPD | Waveshare 2.13" e-Paper (B) V4（コードは `epd2in13b_V4` を使う）。40 ピンヘッダ（SPI）に接続。 |
| Touch Display 2 | Raspberry Pi Touch Display 2（1280x720）。デスクトップ版のイメージが要る（1.2）。 |
| 上流用アダプタ | **必須。** 内蔵の `eth0` と `wlan0` は内部 LAN（`br0`）になるため、上流には USB Ethernet か USB Wi-Fi のアダプタが要る（[PHYSICAL_SETUP_GUIDE.md](PHYSICAL_SETUP_GUIDE.md) §1.1）。Wi-Fi の確認（3.4）には USB Wi-Fi がさらに要る。初回は「上流は USB Ethernet、Wi-Fi の確認用に USB Wi-Fi」が最も簡単。 |
| LAN 側のクライアント | 内部 AP（WPA2）に参加するノート PC と、できれば `eth0` の先のスイッチにつなぐ有線のクライアント。HIL bridge（3.11）を動かす Mac も LAN 側に置く（導入後、SSH は `172.16.0.254` だけで待ち受ける）。 |
| 上流側の試験機 | 上流ネットワーク（`<WAN_IF>` と同じセグメント）にもう 1 台。`curl`・`nc`・`dig` を使う。WAN 露出の確認（3.7）用。 |
| 試験用の AP | 3.4 用に、WPA2-PSK の AP、WPA3-SAE のみの AP、WPA2/WPA3 移行モードの AP、802.1X（WPA2-Enterprise）の AP。本番のネットワークではなく試験用の AP を使う。 |
| コンソール | Pi に直接つないだキーボードとディスプレイ（micro-HDMI）か、動作を確認済みのシリアルコンソール。installer はコンソールか `tmux` の中で実行する（1.4）。 |

### 1.2 OS

- **Raspberry Pi OS（64-bit）、Debian 13 "trixie" ベース。** PR はどれも
  trixie arm64 でだけ確かめています。bookworm のイメージは対象外です（例:
  `install_ntfy.sh` は `ntfy` を Debian のアーカイブから入れますが、bookworm
  にはありません）。
- Touch Display 2 のキオスク（3.9）にはデスクトップ版のイメージが要ります。
  使わないなら Lite で足ります。
- 使ったイメージ（`/etc/rpi-issue`）、`/etc/os-release`、カーネル（`uname -r`）、
  ページサイズ（`getconf PAGESIZE`。Pi 5 の既定のカーネルは 16K ページで、
  3.8 の Mattermost に関係する）を記録します。どのイメージのリリースを使うかは
  今回の記録の一部です **（要確認: まだどのリリースでも試していない）**。
- カードを書くときに、ユーザー・ホスト名・ロケール・SSH を設定します。内蔵
  Wi-Fi にクライアントとしての Wi-Fi 接続を設定しないでください。`wlan0` は
  内部 AP になり、installer がそのクライアント用プロファイルを落とします。

### 1.3 導入前に決める値

| 値 | どこで使う | 決めること |
| --- | --- | --- |
| `WIFI_COUNTRY` | `install_internal_network.sh` | ISO 3166-1 の 2 文字（例 `JP`）。既に設定済み（`sudo raspi-config nonint get_wifi_country` が `00` 以外の国コードを出す）でなければ、Raspberry Pi OS では必須。どちらも無いと installer は何も変えずに止まる。 |
| `AP_SSID` | `install_internal_network.sh` | 内部 AP の SSID（1〜32 文字、既定 `Azazel-Edge-Internal`）。**再実行のたびに同じ値を渡す**（渡さないと既定値に戻る）。下のコマンドは二重引用符の `script -c` の中で単一引用符で囲むので、`'`・`"`・`$`・バックスラッシュを含む SSID は別の引用が要る（または簡単な SSID にする）。 |
| `AP_PSK` | `install_internal_network.sh` | 指定しない。ランダムなパスフレーズが作られ、root だけが読める（0600）`/etc/azazel-edge/internal-ap.psk` に保存される。`ChangeMe1234` は拒否される。 |
| `WAN_IF` | `install_internal_network.sh` | USB の上流 IF。既定経路が既にそこを通っていれば省略できる。既定経路が `eth0`・`wlan0`・`br0` なら installer は止まる。 |
| `SKIP_LUKS` | `install_all.sh` と security stack | `0`（既定）: 暗号化した秘密の保管領域（`/var/lib/azazel-secrets.img`、mapper `azazel-secrets`）を作り、パスフレーズを端末で入力する。`1`: 暗号化領域を作らない。実行前に決める。パスフレーズは installer が保存しない。**パスフレーズを失うと領域は二度と開けず、中身は失われる**（回復用の鍵は無い）。現地の運用手順どおり、機器とは別に保管する。 |
| `ENABLE_MATTERMOST` | `install_ai_runtime.sh` | 初回の `install_all.sh` では指定しない。aarch64（Pi 5）では既定が `0` なので Mattermost は入らない。試すときは後で単独に `ENABLE_MATTERMOST=1` を明示して入れる（2.8）。amd64 だけのイメージが Pi 5 で動くかは分かっておらず、そこで失敗すると `install_all.sh` が selftest の前に止まるため。（x86_64 の既定は `1` のまま。） |
| `AZAZEL_UP_IF` | `/etc/default/azazel-edge-security` | 切断操作で使う上流 IF。既定は `wlan0` で、これは内部 AP なので拒否される。3.4（WIFI-09）で設定する。 |
| `ALLOW_EXTERNAL_SSH` | `install_internal_network.sh` | `false` のまま。sshd は `172.16.0.254` だけで待ち受ける。 |

### 1.4 コンソールか tmux で

installer はすべてローカルのコンソールか `tmux` の中で実行し、素の SSH の
セッションからは実行しません（[PHYSICAL_SETUP_GUIDE.md](PHYSICAL_SETUP_GUIDE.md)
§1.2）。`eth0` や内蔵 Wi-Fi 経由の SSH は `br0` を作る時点で切れ、sshd の
再起動の後は上流側からの新しい SSH はつながりません。`tmux` の中なら installer
は動き続けます。LAN 側から入り直して（`ssh <pi-user>@172.16.0.254`）
`tmux attach` してください。

### 1.5 結果の記録用紙

結果は手元のファイルに残します（3 章の表を写して合否欄を埋める）。issue に
書いてよいものは 4 章のとおりです。

## 2. 導入

### 2.1 初回起動と版の記録

```bash
sudo apt update && sudo apt full-upgrade -y
sudo reboot
# after the reboot: record these
cat /etc/rpi-issue /etc/os-release
uname -r
getconf PAGESIZE
tr -d '\0' < /proc/device-tree/model; echo
free -h
df -h /
```

期待: `/etc/os-release` が trixie、機種の文字列が Raspberry Pi 5、
`getconf PAGESIZE` が 16384（既定のカーネル）か 4096。

### 2.2 上流

先に USB の上流アダプタをつないでから:

```bash
ip -br link
iw dev
ip route show default
```

期待: USB の IF（`eth1`、`wlan1`、または `enx…` のような名前）が見え、既定
経路がそこを通っている（`eth0`・`wlan0` ではない）。USB Wi-Fi を上流にする
場合は、パスフレーズをコマンド行に書かずに接続します:
`sudo nmcli --ask dev wifi connect '<SSID>' ifname <WAN_IF>`（nmcli が尋ねる）。

止まったら: 既定経路が無い → 上流で DHCP が取れていない（`nmcli dev`、
ケーブル、上流の DHCP）。既定経路が `eth0`/`wlan0` → installer が拒否するので、
上流を USB アダプタに移すか `WAN_IF=<WAN_IF>` を渡す。

### 2.3 チェックアウト

```bash
sudo apt install -y git tmux
git clone https://github.com/01rabbit/Azazel-Edge ~/Azazel-Edge
cd ~/Azazel-Edge
git log --oneline -n 40
```

期待: #479〜#488 と #490 のマージコミットがログにある（件名の末尾が
`(#NNN)`）。HIL bridge（3.11）はこのチェックアウトが `~/Azazel-Edge` にあり、
変更の無い `main` であることを前提にします。中のファイルを編集しないでください。

### 2.4 事前確認（何も変えない）

```bash
sudo raspi-config nonint get_wifi_country
rfkill list
ls -l /dev/spidev0.0
```

期待: 国コードが出る、または 1.3 で `WIFI_COUNTRY` を決めてある。Wi-Fi は
まだソフトブロックでもよい（installer が解除する）。SPI を有効にして再起動
するまで（2.6）`/dev/spidev0.0` は無くてもよい。

### 2.5 installer の実行

コンソールで、`tmux` の中で実行します。`script` はログを残し、LUKS の
パスフレーズのための端末を installer に渡します（標準入力をパイプにしない）:

```bash
tmux new -s install
cd ~/Azazel-Edge
script -c "sudo WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' WAN_IF=<WAN_IF> installer/internal/install_all.sh" ~/install-first-run.log
```

`SKIP_LUKS=1` は 1.3 でそう決めたときだけ付けます。開始と終了の時刻を記録
します（導入時間、R0-04）。

期待する出力（順番どおり。段階の行はスクリプトが出す）:

| 段階 | 期待する行 | 止まったとき |
| --- | --- | --- |
| 開始 | `[all/1] Azazel-Edge unified installer` と `ENABLE_*` の値 | `ENABLE_RUST_CORE must be 0 or 1`: 打ち間違い。`ERROR: the encrypted secrets volume … needs a passphrase typed on a terminal`: 標準入力が端末でない。上の `script -c` の形で実行する。 |
| 内部ネットワーク | `[all/2] Apply internal network baseline`、続いて（この順に）`WIFI_COUNTRY` を渡さないときは `Wi-Fi country: … (already configured)`、`Uplink (WAN) interface: <WAN_IF>`、パッケージの導入、`WIFI_COUNTRY` を渡したときは `Wi-Fi country: <CC>`、`===== verify =====` とその一覧、`Internal AP + DHCP baseline applied.`、`AP SSID: …`、`AP passphrase: a new random one, saved root-only in /etc/azazel-edge/internal-ap.psk …`、`SSH listen scope: 172.16.0.254 only.`、`From internal host, verify: …`。その後 `[avahi] allow-interfaces=br0 in /etc/avahi/avahi-daemon.conf (…)`（新規導入では `changed`） | `ERROR: no Wi-Fi country is configured, …` → `WIFI_COUNTRY` を渡す。`ERROR: the uplink is <IF>, which becomes part of the internal LAN …` か `ERROR: WAN interface not found …` → 2.2。`ERROR: the internal AP (lan-wlan0-ap on wlan0) did not come up` → `rfkill list`、`nmcli radio`、`journalctl -u NetworkManager`。`ERROR: sshd rejects the new configuration` → `sudo sshd -t`（元の設定のまま）。 |
| アプリ | `[all/3] Install Azazel-Edge app stack`、`[1/16] Install OS dependencies`、`[1/16] Enable SPI for the EPD (Raspberry Pi OS)`（`NOTICE: SPI is enabled … reboot before the EPD can draw.` が出ることがある）、`[2/16] Create base directories` … `[8/16] Build Python runtime (venv + pip)` … `[11.8/16] Build and install the Rust defense core …`（最も長い）、`[12/16] Enable services` と、制御デーモン・AI エージェント・Web UI・core の順の `… is active`、`[13/16] Install local CA and TLS cert (optional)`、`[14/16] Install HTTPS reverse proxy (optional)`（最後に `[https] nginx TLS reverse proxy enabled on :443 (this device and … only)`）、`[15/16] Install ntfy (optional)`（最後に `[ntfy] Service healthy on http://127.0.0.1:8081 (loopback only, anonymous access denied)`）、`[16/16] Install security stack (OpenCanary + Suricata, optional)`（`SKIP_LUKS=1` でなければここで LUKS のパスフレーズを入力）、`[17/17] Verify runtime sync`、`Installed Azazel-Edge stack …` | `ERROR: <unit> did not stay active …` → `journalctl -u <unit> -b`。終了コード 78 → `/opt/azazel-edge/config` の SOC policy／ATT&CK の YAML が不正。`cargo build` の失敗はここで止まる（fail-closed）。ntfy の `ERROR:` 行は失敗した確認（健全性、匿名アクセス、トークン）を示す。 |
| AI runtime | `[all/4] Install AI runtime stack`、`[ai/4] Start Ollama and provision models`（モデルのダウンロード）、`[ai/5] Skip Mattermost (off by default on aarch64; ENABLE_MATTERMOST=1 installs it, untested on a 16K-page kernel)`、`[DONE] AI runtime stack installed.` | `docker exec … ollama pull` の失敗 → 上流／DNS。同じ値で `install_all.sh` を再実行する。 |
| 任意の部分 | 既定では `[all/5]` … `[all/7]` が `Skip …` | – |
| selftest | `[all/8] Run selftest`、続いて `[all/9] Install the periodic selftest timer` と `[selftest 1/4] Install selftest binary` … `[selftest] timer started`（aarch64 だけ。selftest が失敗しても入れる）、最後に `Unified installation completed.` | `ERROR: the selftest found a critical failure …` → `/var/log/azazel-edge/selftest_latest.json` と 3.10。 |

同じ値での再実行は安全です（スクリプトは冪等）。`AP_SSID` は毎回同じ値を
渡します。

### 2.6 再起動

```bash
sudo reboot
```

導入中に SPI を有効にした場合、`/dev/spidev0.0` のために再起動が要ります。
これは起動経路の最初の確認でもあります（SSH と AP が戻るか。3.6 と 3.3）。
LUKS を使う場合、`crypttab` は `nofail` と 90 秒の待ち時間なので、パスフレーズ
なしでも起動は進み、秘密の保管領域は開けるまで閉じたままです。コンソールに
パスフレーズの入力が出たかを記録します。

### 2.7 ダッシュボード

LAN 側のクライアントで、`http://172.16.0.254/.well-known/azazel-edge-local-ca.crt`
からローカル CA を取得して信頼済みの CA として入れ、`https://172.16.0.254/`
を開きます。初回は `?token=` を付け、トークンは機器で
`sudo cat /etc/azazel-edge/web_token.txt` で読みます（メモや issue に写さない）。
手順は [OPERATOR_GUIDE_JA.md](OPERATOR_GUIDE_JA.md) のとおりです。アドレスに入れたトークンは
nginx と gunicorn のアクセスログ、ブラウザの履歴に残ります。信頼できる LAN 側の
クライアントで 1 回だけ行い、`/touch` では決して使わず
（[TOUCH_CONSOLE_KIOSK.md](TOUCH_CONSOLE_KIOSK.md)）、アドレスを人に渡した場合は
トークンを替えてください。

### 2.8 Mattermost（任意。初回の確認が通った後）

aarch64 では Mattermost は既定で入らない。`ENABLE_MATTERMOST=1` を明示して入れる。

```bash
cd ~/Azazel-Edge
sudo ENABLE_OLLAMA=0 ENABLE_MATTERMOST=1 installer/internal/install_ai_runtime.sh
```

期待:
`NOTICE: Mattermost's image is amd64 only; on this aarch64 host it runs under qemu-user emulation,`（ページサイズ付き。MM-01 に記録する）、
`[ai/5] Start Mattermost stack`、
`[ai/6] Provision Mattermost workspace`、
`[ai/7] Provision Mattermost slash command`、
`[DONE] AI runtime stack installed.`。
終了コード 1 で手順が表示された: LAN 向けの中継を作れなかった
（表示を読む）。終了コード 3 で `[ACTION REQUIRED]`: 管理者パスワードが以前の
既定値（新規導入では起きないはず）。Mattermost のコンテナが起動しなければ、
3.8 の MM-01/MM-02 を集めてそこで止めます。オーナー判断の事項です（5 章）。

## 3. 確認項目

合否欄（`Result`）には `pass`、`fail`（理由を一言）、`N/A（理由）` のどれかを
書きます。

### 3.1 サービスと実行ユーザー（#471 段階 1・2）

```bash
# SVC-02: the account each unit's main process runs as
for u in azazel-edge-control-daemon azazel-edge-core azazel-edge-web azazel-edge-ai-agent; do
  printf '%s ' "$u"; ps -o user= -p "$(systemctl show -p MainPID --value "$u")"
done
# SVC-05
systemctl show -p NRestarts azazel-edge-control-daemon azazel-edge-core azazel-edge-web azazel-edge-ai-agent
```

SVC-09 は 2 段階です。段階 1 は読むだけです:

```bash
# SVC-09 step 1: enforcement stays off (the unit's defaults; the environment file must not change them)
systemctl show -p Environment azazel-edge-core
sudo grep -E '^AZAZEL_DEFENSE_' /etc/default/azazel-edge-security
sudo wc -l /var/log/azazel-edge/ai/core-decision-audit.jsonl /var/log/azazel-edge/ai/p0-alert-queue.jsonl
date -Is
```

段階 2 は、段階 1 で unit に `AZAZEL_DEFENSE_ENFORCE=false` と
`AZAZEL_DEFENSE_DRY_RUN=true` があり、`grep` が何も出さない**ときだけ**実行
します。そうでなければ注入せず、SVC-09 を理由付きで `N/A` にします。試験用の
alert は消せない形で残ります: 追記専用の core の判定の監査チェーン、P0 キュー、
`normalized-events.jsonl`（チェーンを壊さずに消すことはできない）。P0 になると、
キューの先の表示や音声の通知が出ることがあります。後で区別できるよう、前後の
時刻を記録します。

```bash
# SVC-09 step 2: test alerts into the eve.json the core reads
sudo azazel-edge-dummy-eve emit --scenario ssh_bruteforce --count 20
# a few seconds later
sudo wc -l /var/log/azazel-edge/ai/core-decision-audit.jsonl /var/log/azazel-edge/ai/p0-alert-queue.jsonl
date -Is
```

`ssh_bruteforce` と `port_scan` の後でも P0 の行が増えなければ、SVC-09 を
`N/A（試験用の alert で P0 の判定にならない）` とし、シナリオと行数を記録します。

```bash
# SVC-10: terminal 1, the Web UI's ntfy bridge (the token goes on stdin)
sudo sed 's/^/X-Auth-Token: /' /etc/azazel-edge/web_token.txt | curl -skN -H @- --max-time 30 https://127.0.0.1/api/events/stream
# SVC-10: terminal 2, publish a test message with the Edge ntfy token
sudo sed 's/^/Authorization: Bearer /' /etc/azazel-edge/ntfy.token | curl -s -o /dev/null -w '%{http_code}\n' -H @- -d 'first-run test' http://127.0.0.1:8081/azg-info-status
# SVC-11: monitoring state as the Web UI reports it
sudo sed 's/^/X-Auth-Token: /' /etc/azazel-edge/web_token.txt | curl -sk -H @- https://127.0.0.1/api/state | python3 -c 'import json, sys; print(json.load(sys.stdin)["monitoring"])'
```

SVC-12 は任意で、機器を変えます: `install_sensors.sh` は
`/etc/default/azazel-edge-sensors` を上書きし（`SNMP_TARGETS` が無いと
SNMP の対象は書かない。`ENABLE_SNMP=0` なので SNMP 自体は動かない。
`ENABLE_SNMP=1` で `SNMP_TARGETS` に実際の対象が無いと、何も変えずに
止まる）、NetFlow の unit を有効のまま残します。終わったら
`sudo systemctl disable --now azazel-edge-netflow-receiver` で戻します。

SNMP の対象を設定するときの注意が 2 つあります。

- `sudo SNMP_TARGETS=… installer/internal/install_sensors.sh` のように
  渡すと、community が導入者のコマンドライン（実行中はほかのローカル
  ユーザーから見える）とシェル履歴に残ります。先に非エコーで読み
  （`read -rs SNMP_TARGETS && export SNMP_TARGETS`）、
  `sudo --preserve-env=SNMP_TARGETS`（または `sudo -E`）で渡してください。
- `SNMP_TARGETS` を与えずに `install_sensors.sh` を再実行すると、
  `/etc/default/azazel-edge-sensors` は対象なしで書き直され、手で書いた
  対象は消えます。同じ `SNMP_TARGETS` をもう一度与えてください。

```bash
# SVC-12 (optional): the NetFlow sensor unit
cd ~/Azazel-Edge && sudo ENABLE_NETFLOW=1 ENABLE_SERVICES=1 installer/internal/install_sensors.sh
systemctl show -p ActiveState -p Result -p User azazel-edge-netflow-receiver
```

SVC-13 は読むだけです。agent は core の判定 1 件ごとに v2 の判定の説明を
1 件書きます（#477）。SVC-09 の段階 2 のテストアラートで書かれます。段階 2 を
していなければ SVC-13 は `N/A (no test alerts)` にします。

```bash
# SVC-13 (after SVC-09 step 2): the agent's v2 explanation of the core's decision
sudo stat -c '%a %U:%G' /var/log/azazel-edge/ai/decision-explanations.jsonl
sudo azazel-edge-audit-review --compact --audit-path /var/log/azazel-edge/ai/core-decision-audit.jsonl
sudo sed 's/^/X-Auth-Token: /' /etc/azazel-edge/web_token.txt | curl -sk -H @- https://127.0.0.1/api/booth-focus | python3 -c 'import json, sys; d = json.load(sys.stdin); print(d["available"], d["mode"]["kind"], d["decision"]["action"], d["audit"]["policy_profile"])'
sudo tail -n 1 /var/log/azazel-edge/ai/decision-explanations.jsonl | python3 -c 'import json, sys; print(json.load(sys.stdin).get("trust_capsule", {}).get("signature_state"))'
```

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| SVC-01 | unit が動いている | `systemctl is-active azazel-edge-control-daemon azazel-edge-core azazel-edge-web azazel-edge-ai-agent azazel-edge-suricata azazel-edge-opencanary nginx ntfy` | どれも `active` | | #483 |
| SVC-02 | 主プロセスの実行ユーザー | 上のスクリプト | control-daemon `root`、core `root`、web `azazel-web`、ai-agent `azazel-agent` | | #475, #476 |
| SVC-03 | 失敗した unit が無い | `systemctl --failed` | `0 loaded units listed` | | #483, #486 |
| SVC-04 | サンドボックスの評価 | `systemd-analyze security azazel-edge-web azazel-edge-ai-agent` | 値を記録する（コンテナのオフライン評価は 3.1 OK。実機の値は初めて） | | #475, #476 |
| SVC-05 | 再起動を繰り返していない | 上のコマンド | どれも `NRestarts=0` | | #483 |
| SVC-06 | アカウント | `getent passwd azazel-web azazel-agent azazel-sensor` と `id azazel-web` | `azazel-web` と `azazel-agent` が nologin のシェルで存在、`azazel-web` は `azazel-control` に所属、`azazel-sensor` は SNMP/NetFlow を有効にしたときだけ | | #475, #476, #480 |
| SVC-07 | 権限の無いユーザーの TUI | `<pi-user>`（`azazel-control` に入っていない）で `azazel-edge-tui --curses` | トレースバックが出ない。View に `(control.sock: permission denied)`、evidence に `azazel-control` グループの案内が出て、終了すると終了コード 0。`sudo azazel-edge-tui --curses` では実際の状態が出る | | #490, #479 |
| SVC-08 | `azazel-web` で動く Web UI | ダッシュボード（2.7）: 状態、Wi-Fi のスキャン、SoT の編集、M.I.O. への質問（`/api/ai/ask`） | それぞれ応答する。失敗は失敗として表示され、成功に見えない | | #475, #476, #479 |
| SVC-09 | 実際の core からの P0 リレー | 上の段階 1 と 2（段階 2 は段階 1 が通ったときだけ） | 段階 1: unit に `AZAZEL_DEFENSE_ENFORCE=false` と `AZAZEL_DEFENSE_DRY_RUN=true`、環境ファイルからは何も出ない。段階 2: `core-decision-audit.jsonl` が増え、`p0-alert-queue.jsonl` に P0 の行が足される。機器でどのシナリオが P0（enforcement を伴う、または SOC critical）の判定になるかは **（要確認）**。ならなければ上のとおり `N/A` | | #476 |
| SVC-10 | トークンファイルを使った ntfy の SSE | 上のコマンド | 端末 2 が `200`。端末 1 に `first-run test` を含むイベントが出る | | #475, #485 |
| SVC-11 | OpenCanary/Suricata の表示 | 上のコマンド | `opencanary`・`suricata`・`ntfy` が `ON`、`container_check` が `not_checked`（Web UI は Docker に問い合わせない） | | #475 |
| SVC-12 | SNMP/NetFlow（任意） | 上のコマンド（既定では入らない: `ENABLE_SNMP`/`ENABLE_NETFLOW` は `0`、`install_sensors.sh` は `ENABLE_SERVICES=1` のときだけ unit を有効にする） | `User=azazel-sensor`。`ActiveState=inactive`、`Result=success`: モジュールにエントリポイントが無くすぐに終了コード 0 で終わるので、**センサーは動いていない**（5 章） | | #480, #483 |
| SVC-13 | agent が書く判定の説明 | 上のコマンド（SVC-09 の段階 2 の後） | ファイルが `640 azazel-agent:azazel-web`。監査レビューが `schema:OK`、`capsule:signed`、`chain:OK(…)` を最新の判定の action と一緒に出し、isolate・redirect・throttle なら `release=NOT APPLIED - planned only (dry_run)`（SVC-09 の段階 1 のとおり enforcement は無効。lease の時刻は出ない）と `hash_basis=enforcement_settings` も出す。Booth Focus の行が `True live_test_input <ACTION> azazel-edge-core/rust_event_engine_v1`。最後の行が `signed`（trust capsule が機器の鍵で署名されている。`unsigned` なら `/etc/azazel-edge/trust-capsule.env` が無い。SOCK-06 を見る。`None` は #477 より前の記録） | | #477 |

### 3.2 ソケット・ディレクトリ・秘密の権限（#471 段階 1・2）

```bash
sudo stat -c '%a %U:%G %n' /run/azazel-edge /run/azazel-edge/control.sock \
  /run/azazel-edge-ai /run/azazel-edge-ai/ai-bridge.sock \
  /run/azazel-edge-agent /run/azazel-edge-agent-query /run/azazel-edge-agent-query/agent-query.sock \
  /var/log/azazel-edge/ai /var/lib/azazel-edge-agent \
  /run/azazel-edge-web /var/lib/azazel-edge-web /var/log/azazel-edge-web /etc/azazel-edge
sudo stat -c '%a %U:%G %n' /etc/azazel-edge/web_token.txt /etc/azazel-edge/ntfy.token
sudo stat -c '%a %U:%G %n' /etc/azazel-edge/internal-ap.psk /etc/azazel-edge/trust-capsule.env
```

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| SOCK-01 | 制御ソケット | 上の 1 つめの `stat` | `/run/azazel-edge` が `750 root:azazel-control`、`control.sock` が `660 root:azazel-control` | | #475 |
| SOCK-02 | エージェントのソケット | 上の 1 つめの `stat` | `/run/azazel-edge-ai` が `700 azazel-agent:azazel-agent`、`ai-bridge.sock` が `600 azazel-agent:azazel-agent`、`/run/azazel-edge-agent-query` が `2750 azazel-agent:azazel-web`、`agent-query.sock` が `660 azazel-agent:azazel-web` | | #476 |
| SOCK-03 | エージェントと Web UI のディレクトリ | 上の 1 つめの `stat` | `/run/azazel-edge-agent` と `/var/log/azazel-edge/ai` が `2750 azazel-agent:azazel-web`、`/var/lib/azazel-edge-agent` が `750 azazel-agent:azazel-agent`、`azazel-edge-web` の 3 つが `750 azazel-web:azazel-web`、新規導入では `/etc/azazel-edge` が `750 root:azazel-web` | | #475, #476 |
| SOCK-04 | 他のユーザーは制御ソケットに届かない | `<pi-user>` で `ls /run/azazel-edge/` | `Permission denied` | | #475 |
| SOCK-05 | トークン | 上の 2 つめの `stat` | `640 root:azazel-web`（Mattermost を入れた後は `/etc/azazel-edge/mattermost-command-token` も同じ） | | #475, #485 |
| SOCK-06 | root だけの秘密 | 上の 3 つめの `stat`（内部 AP のパスフレーズと trust capsule の鍵）。2.8 の後は `/etc/azazel-edge/mattermost-db.env` と `/etc/azazel-edge/mattermost-credentials.env` も | `600 root:root` | | #485, #486, #477 |
| SOCK-07 | ntfy が匿名の読み取りを断る | `curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8081/azg-alert-critical/json?poll=1'` | `401` か `403` | | #485 |

### 3.3 内部 AP

```bash
# AP-05: the keyfile of the AP profile
nmcli -t -f NAME,FILENAME con show
sudo nmcli -g 802-11-wireless-security.psk-flags con show lan-wlan0-ap
# AP-06: the passphrase is in neither the install log nor this boot's journal
sudo python3 - ~/install-first-run.log <<'EOF'
import subprocess, sys
psk = open("/etc/azazel-edge/internal-ap.psk", "rb").read().strip()
log = open(sys.argv[1], "rb").read()
journal = subprocess.run(["journalctl", "-b", "-o", "cat"], capture_output=True).stdout
print("in install log:", psk in log, "| in journal:", psk in journal)
EOF
```

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| AP-01 | 無線がブロックされていない | `rfkill list` | Wireless LAN が `Soft blocked: no`、`Hard blocked: no` | | #486 |
| AP-02 | 国設定 | `sudo raspi-config nonint get_wifi_country` | 1.3 で決めたコード | | #486 |
| AP-03 | AP が上がる（再起動後も） | `nmcli -t -f NAME,DEVICE con show --active` | `lan-wlan0-ap:wlan0` と `lan-br0:br0`。再起動後 `systemctl show -p Result azazel-internal-apply` が `Result=success`（oneshot の unit なので、実行後に `inactive` なのは正常） | | #486 |
| AP-04 | PSK のファイル | 3.2 の 3 つめの `stat` | `600 root:root`。生成した場合は 20 文字（表示しない。`sudo wc -c` は改行込みで 21） | | #486 |
| AP-05 | keyfile | 上のコマンド | `lan-wlan0-ap` の行のファイルが `600 root:root`（`sudo stat`）、`psk-flags` が `0` で始まる（system-owned） | | #486 |
| AP-06 | PSK が表示されていない | 上のスクリプト | `in install log: False` と `in journal: False` | | #486 |
| AP-07 | クライアントが参加できる | LAN 側のノート PC で `AP_SSID` に参加する。パスフレーズはコンソールで `sudo cat /etc/azazel-edge/internal-ap.psk` で読む | WPA2 で接続、DHCP で `172.16.0.101`〜`172.16.0.200` のアドレス、`https://172.16.0.254/` に届く | | #486 |
| AP-08 | 以前の既定値を拒否 | `sudo AP_PSK=ChangeMe1234 WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' installer/internal/install_internal_network.sh` | 何も変える前に `ERROR: the AP passphrase is the old built-in default; …` で止まる（AP は上がったまま） | | #486 |

### 3.4 上流の Wi-Fi（USB Wi-Fi アダプタ）

接続はダッシュボードの Wi-Fi の画面か `/touch` の「ネットワーク」タブから
行います（どちらも `POST /api/wifi/connect`、operator のトークン）。パス
フレーズをコマンド行に書かないでください。接続のたびに、その前に別の
コンソールで次の監視を起動します。パスフレーズを（表示せずに）尋ね、60 秒間、
全プロセスのコマンド行にそれが現れないかを調べます:

```bash
sudo python3 - <<'EOF'
import getpass, glob, time
secret = getpass.getpass("passphrase to look for: ").encode()
hits, end = set(), time.time() + 60
while time.time() < end:
    for path in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            if secret in open(path, "rb").read():
                hits.add(path)
        except OSError:
            pass
    time.sleep(0.05)
print("found in:", sorted(hits) if hits else "none")
EOF
```

接続のたびに:

```bash
nmcli -t -f DEVICE,TYPE,STATE,CONNECTION dev
nmcli -t -f NAME,DEVICE con show --active
nmcli -t -f NAME,UUID con show
```

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| WIFI-01 | WPA2-PSK、新規 | パスフレーズを入れて接続 | USB Wi-Fi の IF で接続。`lan-wlan0-ap` は `wlan0` で動いたまま。監視は `found in: none` | | #478, #486 |
| WIFI-02 | WPA3-SAE のみ、新規 | WIFI-01 と同じ | WIFI-01 と同じ | | #478 |
| WIFI-03 | WPA2/WPA3 移行モード、新規 | WIFI-01 と同じ | WIFI-01 と同じ | | #478 |
| WIFI-04 | 保存済み、パスフレーズなし | 切断してから、3 つそれぞれに保存済みとして接続 | パスフレーズなしで再接続。AP は落ちない | | #478 |
| WIFI-05 | 保存済み、新しいパスフレーズ | 1 つの AP のパスフレーズを変え、新しい値で接続 | 接続できる。`nmcli … con show` に `azazel-wifi-pending-…` が残らない。監視は `none` | | #478 |
| WIFI-06 | 保存済み、誤ったパスフレーズ | 誤った値で接続 | 失敗する。その後、保存済みのプロファイルで正しい値のまま接続できる。pending のプロファイルが残らない | | #478 |
| WIFI-07 | 802.1X を拒否 | 802.1X の SSID に接続 | `802.1X (WPA-Enterprise) networks are not supported here; set the profile up with NetworkManager directly` で拒否。プロファイルは増えない | | #478 |
| WIFI-08 | USB Wi-Fi が無い | USB Wi-Fi を外してスキャン | `No wireless interface for the uplink: …`。AP は落ちない。制御デーモンが `wifi sensor: not scanning: …` を 1 回ログに出す | | #486 |
| WIFI-09 | 切断で AP を落とさない | `AZAZEL_UP_IF` 未設定で、`sudo sed 's/^/X-Auth-Token: /' /etc/azazel-edge/web_token.txt` の出力を `curl -sk -H @- -w '\n%{http_code}\n' -X POST https://127.0.0.1/api/action/disconnect` に渡す | 本文に `uplink_interface_serves_internal_lan:wlan0`、続いて `500`。AP は落ちない。続けて（任意。上流が切れるので LAN 側かコンソールから）`/etc/default/azazel-edge-security` に `AZAZEL_UP_IF=<WAN_IF>` を書き、`sudo systemctl restart azazel-edge-control-daemon` の後に繰り返す: `<WAN_IF>` が落ちる。`sudo ip link set <WAN_IF> up` で戻す | | #475, #486 |
| WIFI-10 | 日本語のロケール（任意） | システムのロケールを `ja_JP.UTF-8` にして WIFI-01 を繰り返す | WIFI-01 と同じ | | #480 |

トークンは curl の標準入力（`-H @-`）で渡し、コマンド行には載せません。
`sed` の出力はパイプで渡します（`sudo sed … | curl …`）。

### 3.5 EPD

```bash
# EPD-02
sudo /opt/azazel-edge/venv/bin/python -c 'import spidev, gpiozero, lgpio, gpiozero.pins.lgpio; print("ok")'
# EPD-03 (gpiozero internal API; record the error if it has none)
sudo /opt/azazel-edge/venv/bin/python -c 'from gpiozero import Device; f = Device._default_pin_factory(); print(type(f).__name__); f.close()'
# EPD-04: force one draw (the refresh draws only when the frame changed)
sudo rm -f /run/azazel-edge/epd_last_render.json
sudo systemctl start azazel-edge-epd-refresh.service
systemctl show -p Result azazel-edge-epd-refresh.service
journalctl -u azazel-edge-epd-refresh -b --no-pager -n 20
systemctl list-timers azazel-edge-epd-refresh.timer
```

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| EPD-01 | SPI のデバイス | `ls -l /dev/spidev0.0` | ある（2.6 の再起動の後） | | #486 |
| EPD-02 | venv から GPIO のモジュールが見える | 上のコマンド | `ok` | | #486 |
| EPD-03 | ピンファクトリ | 上のコマンド | クラス名を記録する。期待は `LGPIOFactory`（Pi 5 の RP1 は lgpio で動かす）。ほかのファクトリやエラーは発見事項。gpiozero の内部関数を使うので、確かめ方として正しいかは **（要確認）** | | #486 |
| EPD-04 | 描画 | 上のコマンド | パネルが描き直される。`Result=success`。タイマーに次回の実行がある | | #486 |
| EPD-05 | 失敗が見え、タイマーは続く | 電源を切って EPD を外し、起動して EPD-04 を繰り返す | `Result=exit-code`。描画が失敗したときも、45 秒で打ち切ったときも refresh は 1 で終わり、journal にどちらかが出る（`azazel-edge-epd-refresh: ERROR: EPD renderer exited with status …` か `… timed out after 45 s …`）。`Result=timeout` なら unit 自体の 60 秒の上限に達した（発見事項）。`systemctl list-timers` に次回の実行が残る。パネルが無いときにどちらになるかは **（要確認）**。終わったら電源を切って付け直す | | #486 |
| EPD-06 | Waveshare の機種判定 | `grep -c Raspberry /proc/cpuinfo` | `1` 以上（Waveshare の `epdconfig` は `/proc/cpuinfo` で Pi を判定する） | | #486 |

### 3.6 SSH

```bash
systemctl is-enabled ssh.service ssh.socket
systemctl show -p Restart -p RestartUSec ssh.service
sudo sshd -T | grep -i listenaddress
sudo ss -Hltnp 'sport = :22'
# SSH-04, after a reboot
journalctl -b -u ssh --no-pager
systemctl show -p ActiveEnterTimestampMonotonic ssh.service
```

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| SSH-01 | socket と service | `systemctl is-enabled ssh.service ssh.socket` | `enabled` / `disabled`。導入前の初期イメージでどうだったかも記録する（2.1） | | #486 |
| SSH-02 | drop-in | `systemctl cat ssh.service` と上の `systemctl show` | drop-in `azazel-edge-listen.conf` が出る。`Restart=on-failure`、`RestartUSec=5s` | | #486 |
| SSH-03 | 待ち受け先 | 上の `sshd -T` と `ss` | `listenaddress 172.16.0.254:22` だけ。sshd は `172.16.0.254:22` だけで待ち受ける | | #486 |
| SSH-04 | 起動時に `br0` のアドレスが遅れる | 再起動して上の journal を見る | `br0` のアドレスより先に sshd が起動した場合、`Cannot bind any address` の 5 秒後に再起動して `active` になる。LAN からの SSH が数秒〜十数秒で使える。かかった時間を記録する | | #486 |
| SSH-05 | 導入中も既存のセッションは切れない | installer の再実行中に使っている LAN 側の SSH | 切れない | | #486 |

### 3.7 WAN 露出（#485、#488。#489 は無効）

まず機器で、待ち受けをすべて一覧にします:

```bash
sudo ss -Hltunp
```

期待する待ち受け: `0.0.0.0:80` と `0.0.0.0:443`（nginx）、`0.0.0.0:8065`
（nginx。2.8 の後だけ）、`127.0.0.1:8081`（ntfy）、`127.0.0.1:8084`（Web UI）、
`127.0.0.1:18065`（Mattermost。2.8 の後）、`127.0.0.1:11434`（Ollama）、
`127.0.0.1:18080` と `127.0.0.1:12222`（OpenCanary）、`172.16.0.254:22`
（sshd）、`br0` の dnsmasq（53、67）、5353/udp とランダムな高い番号の UDP（ユニキャストの問い合わせ用）の avahi。ほかに `0.0.0.0`・
`*`・`[::]` で待ち受けているものがあれば発見事項です。ポートとプロセスを
記録します（アドレスは書かない）。

**上流側の試験機**から（`<WAN-ADDR>` を置き換える）:

```bash
curl -s  -o /dev/null -w '%{http_code}\n' --max-time 5 http://<WAN-ADDR>/health
curl -sk -o /dev/null -w '%{http_code}\n' --max-time 5 https://<WAN-ADDR>/health
curl -s  -o /dev/null -w '%{http_code}\n' --max-time 5 http://<WAN-ADDR>:8065/
for p in 8081 22 8084 11434 18065; do nc -vz -w 3 <WAN-ADDR> "$p"; done
dig +time=2 +tries=1 -p 5353 @<WAN-ADDR> <hostname>.local
```

**LAN 側のクライアント**から（有線か内部 AP）:

```bash
curl -s  -o /dev/null -w '%{http_code}\n' --max-time 5 http://172.16.0.254/health
curl -sk -o /dev/null -w '%{http_code}\n' --max-time 5 https://172.16.0.254/health
curl -s  -o /dev/null -w '%{http_code}\n' --max-time 5 http://172.16.0.254:8065/
nc -vz -w 3 172.16.0.254 22
dig +time=2 +tries=1 -p 5353 @172.16.0.254 <hostname>.local
```

| ID | 項目 | どこから | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| WAN-01 | 80/tcp | 上流 | `403`（nginx が拒否） | | #488 |
| WAN-02 | 443/tcp | 上流 | `403` | | #488 |
| WAN-03 | 8065/tcp（Mattermost） | 上流 | 2.8 の後は `403`。Mattermost なしでは接続拒否 | | #485 |
| WAN-04 | 8081、8084、11434、18065/tcp | 上流 | 接続拒否（loopback だけ） | | #480, #485 |
| WAN-05 | 22/tcp | 上流 | 接続拒否かタイムアウト | | #486 |
| WAN-06 | 5353/udp | 上流 | 応答なし（タイムアウト） | | #488 |
| WAN-07 | 2055/udp（NetFlow） | 機器: `sudo ss -Hlunp 'sport = :2055'` | 待ち受けなし（受信側にエントリポイントが無い。5 章）。NetFlow を有効にした場合だけ `172.16.0.254:2055` | | #488 |
| WAN-08 | LAN では使える | LAN 側のクライアント | `/health` が http で `301`、https で `200`。2.8 の後は 8065 が `200`。22 に接続できる。5353 が応答する | | #485, #488 |
| WAN-09 | 弱いホストモデル（参考） | `172.16.0.0/24 via <WAN-ADDR>` の経路を足した上流の試験機 | #489 が無効の間は `172.16.0.254` の 22/tcp に届く（既知。nginx は 403 のまま）。記録する。これを塞ぐのは #489 の層 | | #488, #489 |
| WAN-10 | 証明書の SAN | 機器: `sudo openssl x509 -in /etc/azazel-edge/tls/webui.crt -noout -ext subjectAltName` | `172.16.0.254`、ホスト名、`Azazel-Edge.local`（ホスト名に `.local` を付けたもの）、`localhost`、`127.0.0.1` を含み、WAN のアドレスを含まない（出力は貼らない）。この変更より前に導入した機器は、証明書を発行し直すまで古い証明書のまま。installer を再実行するか、`sudo /opt/azazel-edge/install_local_ca.sh` の後に `sudo systemctl reload nginx`（CA はそのまま） | | #488, #477 |

### 3.8 Mattermost（使う場合だけ。2.8 の後）

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| MM-01 | 16K ページでの amd64 エミュレーション | `getconf PAGESIZE`、`ls /proc/sys/fs/binfmt_misc/` | ページサイズを記録する。`qemu-x86_64` がある | | #485 |
| MM-02 | コンテナが動く | `sudo docker ps --filter name=azazel-edge-mattermost`、`sudo docker logs --tail 50 azazel-edge-mattermost` | `Up` で、再起動を繰り返していない。終了してしまう場合はログの末尾を記録して（秘密は含まれないはずだが確かめる）ここで止める。aarch64 で既定を有効に戻すかはオーナー判断 | | #485 |
| MM-03 | loopback の API | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18065/api/v4/system/ping` | `200` | | #485 |
| MM-04 | nginx 経由で LAN から | LAN 側のブラウザで `http://172.16.0.254:8065` | ログイン画面。`azazelops` で、機器の `/etc/azazel-edge/mattermost-credentials.env` にあるパスワードでログインできる | | #485 |
| MM-05 | slash command | `soc-noc` チャンネルで `/mio <質問>`（別名 `/azops`） | M.I.O. から応答がある。`403` にならない（戻りは `172.31.250.0/24` から来て、nginx が許可する） | | #485, #488 |
| MM-06 | Docker のネットワーク | `sudo docker network inspect security_mattermost` | サブネットが `172.31.250.0/24`（compose のプロジェクト `security` のネットワーク `mattermost`） | | #488 |

### 3.9 Touch Display 2（`/touch`）

[TOUCH_CONSOLE_KIOSK.md](TOUCH_CONSOLE_KIOSK.md) のとおりに設定します（デスク
トップのユーザーのセッションでキオスク、`http://127.0.0.1:8084/touch?lang=ja`、
トークンは設定タブで入力。`/touch` に `?token=` を付けない）。

```bash
# TCH-05: Web UI CPU time over 5 minutes, panel untouched, then while touching
systemctl show -p CPUUsageNSec azazel-edge-web
# ... wait 300 s ...
systemctl show -p CPUUsageNSec azazel-edge-web
# open state streams to the Web UI
sudo ss -Htn state established '( sport = :8084 )'
```

`CPUUsageNSec` が `[not set]`（CPU の計測が無効）なら、代わりに `top -b -n 1`
で `gunicorn` のプロセスを見て、その方法を記録します。

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| TCH-01 | キオスクの起動 | autostart を設定して再起動 | Chromium が全画面で `/touch` を開く。1280x720 でスクロールなしに収まる | | #484 |
| TCH-02 | タッチ | 各タブを押す、Wi-Fi をスキャン | タッチ（pointer events）に応答する。日本語が表示される（`fonts-noto-cjk`） | | #484 |
| TCH-03 | 長押し | Wi-Fi の接続／Runbook の実行 | タップでは何も起きない。1.2 秒の長押しで実行。途中で離すと取り消し | | #484 |
| TCH-04 | 消灯からの復帰 | 画面を消灯させ（`swayidle`/`wlopm`）、タッチ | 画面が点く。そのタッチでは操作が始まらない | | #484 |
| TCH-05 | SSE の負荷 | 上のコマンド | 5 分触らないとストリームの接続が無くなる。CPU % = 差分 ns / 3e11 × 100 を、触らないときと使っているときで記録する | | #484 |
| TCH-06 | 古い状態の表示 | 制御デーモンを少し止める（`sudo systemctl stop azazel-edge-control-daemon`、その後 start） | 「古い」「未確認」の印で、緑にならない。start の後に戻る | | #484, #479 |
| TCH-07 | nginx（HTTPS）経由の `/touch` | ローカル CA を信頼した LAN 側のブラウザで `https://172.16.0.254/touch` を開き、2 分を超えて触り続ける | nginx の 120 秒の読み取りタイムアウトを過ぎても毎秒更新が続く（ストリームは毎秒データを送り、アプリは `X-Accel-Buffering: no` を付ける）。使っている間、上部の表示が定期更新に落ちない | | #484 |

### 3.10 selftest、Suricata、ウォッチドッグ

installer は selftest を 1 回実行し（`[all/8]`）、
`/usr/local/bin/azazel-edge-selftest` として timer 付きで入れます（`[all/9]`、
aarch64 だけ）。起動のたびに 5 分後と、四半期ごとに実行されます。

```bash
sudo azazel-edge-selftest; echo "exit=$?"
sudo cat /var/log/azazel-edge/selftest_latest.json
# ST-06: the timer and its service
systemctl list-timers azazel-edge-selftest.timer
systemctl show -p Result azazel-edge-selftest.service
journalctl -u azazel-edge-selftest -b --no-pager -n 20
sudo suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/azazel-lite.rules -l "$(mktemp -d)"; echo "exit=$?"
# ST-05
ls -l /dev/watchdog*
sudo dmesg | grep -i -E 'bcm2835-wdt|watchdog'
systemctl show -p RuntimeWatchdogUSec
```

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| ST-01 | selftest の終了コード | 1 つめのコマンド | `exit=0`。表示された一覧に失敗が無い | | #487 |
| ST-02 | 既知の警告 | JSON | `"failures": []`。現状で出る警告は `config_checksums_missing`（`/etc/azazel-edge/.config_checksums` を作るものが無い。5 章）と `python_smoke_tests_missing` | | #487 |
| ST-03 | SD の書き込み試験 | JSON | ext4 のルートで `sd_write_test_skipped:not_on_sd:…` が出ない。`sd_write_speed_low:…` は媒体が遅いときだけ（値を記録する） | | #478, #487 |
| ST-04 | Suricata のルールが読める | 最後のコマンド | `exit=0`。有効なルールは 13 本（sid 9901211 は無効。Suricata 7 は ARP を照合できない） | | #481 |
| ST-05 | ハードウェアウォッチドッグ（任意の設定） | 上のコマンド | `/dev/watchdog` があり、カーネルのログに `bcm2835-wdt` が出る（文言は **（要確認）**）。`RuntimeWatchdogUSec=0`（Azazel-Edge は有効にしない）。有効にするのは任意で、[PHYSICAL_SETUP_GUIDE.md](PHYSICAL_SETUP_GUIDE.md) §4 のとおり | | #486 |
| ST-06 | selftest の timer | ST-06 のコマンド。再起動の後（timer が起動 5 分後に実行する） | timer に次回の実行がある。実行後は `Result=success`（critical があると oneshot の unit が `failed` になり、`systemctl --failed` に出る） | | #487 |

### 3.11 HIL bridge（LAN 側の Mac から）

前提: Mac が LAN 側にあり、その checkout が `main`。Pi のホスト鍵を確かめて
ある（コンソールで `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` を表示
し、最初の `ssh <pi-user>@172.16.0.254` の表示と比べる）。`<pi-user>` で
`sudo -n true` が通る（`nft list ruleset` に要る。通らないと nft の観測が
`unobserved` になり、終了コードは 3）。詳しくは
[R0_PI_HIL_BRIDGE.md](R0_PI_HIL_BRIDGE.md)。

```bash
tools/hil/azazel-hil --target 172.16.0.254 --user <pi-user> prepare --no-update-repo
tools/hil/azazel-hil --target 172.16.0.254 --user <pi-user> full; echo "exit=$?"
```

`full` の終了コード: `0` 完了、`1` 失敗したテストがある、`2` 途中の段階で
停止（準備の gate など）、`3` 証拠が足りない（`unobserved` の観測、必須テストの
欠落や skip — **モデルが無いと 3** — 、イベントが 0 件）、`255` SSH/SCP の失敗。

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| HIL-01 | 準備の確認 | `prepare --no-update-repo` | 終了コード 0。拒否されるときは実際の理由（`main` でない、未コミットの変更）が出る | | #482, #490 |
| HIL-02 | full | `full` | 終了コード `0`。`[ai/4]` のモデルを入れたのに `3` なら発見事項 | | #482, #372, #408 |
| HIL-03 | インタプリタ | 報告 | `/opt/azazel-edge/venv/bin/python` が理由付きで選ばれている | | #482 |
| HIL-04 | Ollama | 報告 | `127.0.0.1:11434` 経由で版と 2 つのモデル（`qwen3.5:0.8b`、`qwen3.5:2b`）を計測 | | #482 |
| HIL-05 | 読み取りだけの観測 | 報告 | `tc` と `nft` が観測できている（`unobserved` でない）。コマンドが無い場合は `failed` ではなく `unobserved` | | #482, #490 |
| HIL-06 | 再起動（任意。保守時間に） | `tools/hil/azazel-hil --target 172.16.0.254 --user <pi-user> --session <id> run --allow-service-restart --service azazel-edge-core`（`<id>` は `full` が表示した session。`<pi-user>` は `systemctl restart` を対話なしの sudo で実行できること） | 再起動が記録され、15 秒以内に `active` | | #482 |

### 3.12 R0 の計測（#408、#372）

```bash
systemd-analyze
systemd-analyze critical-chain azazel-edge-web.service
systemctl show -p ActiveEnterTimestampMonotonic azazel-edge-web azazel-edge-control-daemon azazel-edge-core
vcgencmd measure_temp
vcgencmd get_throttled
vcgencmd pmic_read_adc
free -m
df -h /
sudo du -sh /var/log/azazel-edge /var/lib/docker
```

| ID | 計測 | 方法 | 記録するもの | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| R0-01 | 起動時間 | 電源を入れ直した後の `systemd-analyze` | 全体と userspace の時間 | | #408 |
| R0-02 | サービスが使えるまでの時間 | `ActiveEnterTimestampMonotonic`（起動からの µs） | Web UI、制御デーモン、core | | #408 |
| R0-03 | 電力 | USB-C のインライン電力計で、起動後 5 分の待機時と、HIL の `full`（推論）中。補助に `vcgencmd pmic_read_adc`（ボードの電源系だけで USB 機器を含まない。読み方は **（要確認）**） | 待機 W／最大 W。[POWER_PLAYBOOK.md](POWER_PLAYBOOK.md) §1 と比べる | | #408, #372 |
| R0-04 | 導入時間 | 2.5 の開始と終了の時刻 | 分。`[11.8/16]` にかかった時間も | | #408 |
| R0-05 | 温度とスロットリング | HIL の実行中と後に `vcgencmd measure_temp`、`vcgencmd get_throttled` | 最高温度。`throttled=0x0`（それ以外なら値を記録） | | #372 |
| R0-06 | メモリとディスク | 上の `free -m`、`df -h /`、`du` | 使用量／空き、swap。導入後と HIL の後のディスク使用量 | | #372 |
| R0-07 | HIL のプロファイル | HIL の報告 | 推論の遅延、前後のメモリ、observer の時間（報告のとおり） | | #372, #408 |

### 3.13 ホストファイアウォールの試行（#489、draft、任意）

**前提: #489 のブランチに現在の `main` が含まれていること。** #489 は
`main`（#490 の後）の上に rebase 済みです。その後に `main` が進むと（この
手順書自体も後から #491 として入りました）、ブランチに `main` が含まれなく
なることがあります。FW の行の前に機器で確かめます。含まれていなければ #489 の
再 rebase を依頼し、それまで FW の行はすべて `N/A（#489 未 rebase）` です。

**#489 がマージ済みの場合**（2.3 の `main` のチェックアウトに
`installer/internal/azazel-host-firewall` がある）: この前提、下の fetch、
`git switch try-489` は不要です。その `main` のチェックアウトのまま各段階を
行います（`--enable-host-firewall` を付けるまでホストファイアウォールは無効のまま）。

```bash
cd ~/Azazel-Edge
git fetch origin main pull/489/head:try-489
git merge-base --is-ancestor origin/main try-489 && echo rebased || echo "not rebased: FW rows are N/A"
```

行はこの順に行います: FW-01（有効にして確定）→ 規則が**有効**な状態で
FW-02〜FW-05 と FW-07〜FW-12 → 最後に FW-06（自動の巻き戻し）→ 下の
「元に戻す」。各段階の前に `sudo azazel-host-firewall status` が
`state=enabled` と `loaded=yes` を出すことを確かめます。出なければ、その段階の
行は `N/A` とし、status の行を理由に書きます。

**段階 1（FW-01）: 有効にして確定。** 3.1〜3.12 の後に、**コンソール**
（端末があり、上流側からの SSH セッションが無い状態）で実行します:

```bash
git switch try-489
sudo WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' WAN_IF=<WAN_IF> installer/internal/install_internal_network.sh --enable-host-firewall
# the installer loads the rules on trial and asks:
#   Host firewall on trial. Type 'yes' within 100 s to keep it (anything else, or nothing, takes it off):
# type: yes   (the WAN checks of FW-02 come after this, without a time limit)
sudo azazel-host-firewall status
```

installer が尋ねるのは、標準入力が端末で、上流側から入った SSH セッションが
無いときだけです。`yes` 以外の入力か、100 秒以内に答えが無いと `disable`
を実行します（状態を消し、`Host firewall not kept.` と出す）。端末が無いときは
NOTICE を出し、**新しい**接続（コンソールか新しい LAN 側の SSH。開いている
セッションは確立済みの接続として残る）から `sudo azazel-host-firewall confirm`
を実行しない限り、helper のタイマーが 120 秒後に規則を外します。

**段階 2（FW-02〜FW-05、FW-07〜FW-12）: 規則が有効な状態で。**

```bash
sudo azazel-host-firewall status   # state=enabled, loaded=yes (again after the FW-05 reboot)
# FW-04: on the device, after half the DHCP lease time
journalctl -u NetworkManager -b --no-pager | grep -i -E 'dhcp4|dhcp6'
ip -6 addr show dev <WAN_IF>
# FW-09: docker networks and the FORWARD policy docker set
sudo docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $(sudo docker network ls -q)
sudo iptables -S FORWARD | head -n 1
# FW-11 (only if nftables.service is enabled; from the console, see the row)
systemctl is-enabled nftables
sudo systemctl reload nftables
sudo nft list tables
sudo systemctl start azazel-internal-apply   # only if "ip azazel_internal" is missing
```

**段階 3（FW-06）: 自動の巻き戻し（最後）。** installer が尋ねないよう、標準
入力を端末以外にします:

```bash
sudo azazel-host-firewall disable
sudo WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' WAN_IF=<WAN_IF> installer/internal/install_internal_network.sh --enable-host-firewall </dev/null
sudo azazel-host-firewall status   # state=pending while the timer runs
# wait 120 s, then
sudo azazel-host-firewall status
```

| ID | 項目 | コマンド | 期待する結果 | Result | PR / issue |
| --- | --- | --- | --- | --- | --- |
| FW-01 | installer の問いで確定 | 段階 1（`yes`） | `status` が `state=enabled`、`loaded=yes`、`remote_access=off` | | #489 |
| FW-02 | WAN が閉じる | 段階 2: 上流の試験機から 3.7 を繰り返す | 80/443/8065/8081/22 に届かない（タイムアウト）。5353 は応答なし。WAN-09 も届かない | | #489 |
| FW-03 | LAN は変わらない | 段階 2: WAN-08、AP-07、MM-05 を繰り返す（有線 LAN と内部 AP から、Web UI・SSH・DHCP/DNS・mDNS） | 前と同じ | | #489 |
| FW-04 | 上流の DHCP と IPv6 | 段階 2 のコマンド。IPv6 は上流にある場合だけ | DHCPv4 のリースが更新される。RA/SLAAC（上流が使っていれば DHCPv6 も）のアドレスが残る | | #489 |
| FW-05 | 起動の順番 | 段階 2: 再起動して `systemctl show -p ActiveEnterTimestampMonotonic azazel-host-firewall NetworkManager`、`systemctl --failed`、もう一度 `status` | `azazel-host-firewall` の時刻の方が小さい（NetworkManager より先に active）。失敗した unit が無い。`state=enabled` のまま | | #489 |
| FW-07 | PMTU | 段階 2: LAN 側のクライアントから（NAT 経由で）と機器自身で、100 MB 以上のファイルを HTTPS でダウンロード | 止まらずに完了する | | #489 |
| FW-08 | コンテナ | 段階 2: `sudo docker exec azazel-edge-ollama ollama pull qwen3.5:0.8b`（外向き）、MM-05（コンテナからホスト） | どちらも動く | | #489 |
| FW-09 | Docker のネットワークと FORWARD | 段階 2 のコマンド | Docker のネットワークがすべて 172.17.0.0/16〜172.31.0.0/16 にある。FORWARD の方針の行を記録する（Docker は通常 `-P FORWARD DROP` にする） | | #489 |
| FW-10 | リモートアクセスの対の規則 | 段階 2: installer を `ALLOW_EXTERNAL_SSH=true`（とほかの値）で再実行し、次に付けずに再実行。`sudo DEVICE_HOSTNAME=<hostname> MODE=open installer/internal/set_dev_remote_access.sh`、次に `MODE=close` | `ALLOW_EXTERNAL_SSH=true` か `MODE=open` のとき、上流の試験機から 22/tcp と 5353/udp に届き、8081 は届かないまま。付けない／`MODE=close` で再び閉じる。`set_dev_remote_access.sh` の副作用: ホスト名を `DEVICE_HOSTNAME`（既定 `Azazel-Edge`）にする。`/etc/ssh/sshd_config` を書き換え（`sshd_config.bak.<時刻>` を残す。`open` は `ListenAddress` をすべて消し、`close` は `ListenAddress 172.16.0.254` を戻す）、ssh を再起動する。上流のアドレスを表示する（出力は貼らない）。コンソールから実行する | | #489 |
| FW-11 | `nftables.service` の reload | 段階 2 のコマンド。`systemctl is-enabled nftables` が `enabled` のときだけ、**コンソール**から | `inet azazel_host` が再び出る。reload でも `flush ruleset` が走り、`ip azazel_internal`（LAN の NAT）が消えるので、戻るまで LAN のクライアントは上流に出られない。`nft list tables` に無ければ `sudo systemctl start azazel-internal-apply` で戻し、もう一度確かめて発見事項として記録する。nftables が無効なら `N/A`（起動しない。同じ flush が起きる。#489 の既知事項） | | #489 |
| FW-12 | enforcement の表 | 段階 2: `sudo nft list tables` | オーナーが `table inet azazel_edge` を作って enforcement を有効にしていない限り `N/A`（5 章）。有効なら core の isolate/redirect の規則と `inet azazel_host` の両方が残る | | #489, #480 |
| FW-06 | 自動の巻き戻し（最後） | 段階 3（`</dev/null`、または pty の無い SSH で実行） | installer は尋ねずに NOTICE を出す。120 秒後に `status` が `state=rolled-back`、`loaded=no`。WAN の結果が 3.7 のとおりに戻る | | #489 |

元に戻す（最後に必ず）:

```bash
sudo azazel-host-firewall disable
sudo azazel-host-firewall status   # state=off, loaded=no
git switch main
sudo WIFI_COUNTRY=<CC> AP_SSID='<your SSID>' WAN_IF=<WAN_IF> installer/internal/install_internal_network.sh
sudo nft list tables               # no "inet azazel_host"; "ip azazel_internal" present
```

元に戻した後も helper と unit は残りますが、状態が off なので起動時に何も
読み込みません。FW-10 を開いたままにしていたら `MODE=close` で閉じます。

## 4. 結果の記録と、失敗時に集めるもの

issue（#408、#372、#471、#477、または新しい issue）に書いてよいもの:

- 3 章の表（ID、結果、短い注記）、OS のイメージ名、カーネルの版、ページ
  サイズ、RAM の容量、R0 の数値。
- **書かないもの**: パスフレーズ、トークン、パスワード、`/etc/azazel-edge` の
  下のファイルの中身（モードと所有者は可）、秘密鍵、固定の LAN 以外の IP
  アドレス、MAC アドレス、シリアル番号、ホスト名、実在のネットワークの SSID、
  boot ID、HIL の session ID、イメージの digest やその他のハッシュ・識別子。
  貼る前に伏せてください。HIL の報告は秘密を伏字にしますが、アドレスは伏せ
  ません。
- コンテナや VM で見たことは、そう明記します。実機の結果ではありません。

確認が失敗したら、機器で次を集めて手元に残します（共有する前に見直して
伏せる）:

```bash
systemctl --failed
systemctl status <unit> --no-pager
journalctl -b -u <unit> --no-pager -n 200
sudo cat /var/log/azazel-edge/selftest_latest.json
nmcli dev; nmcli -t -f NAME,DEVICE con show --active; rfkill list
ip -br addr; ip route
sudo ss -Hltunp
vcgencmd get_throttled
sudo dmesg | tail -n 100
```

加えて、導入のログ（`~/install-first-run.log`）と、HIL bridge の場合は Mac の
`artifacts/hil/` の下の session のディレクトリ。

## 5. 未決事項（オーナー判断）

コードでは決めていない事項です。どれもオーナーの判断が要ります。今回の実機で
判断の材料が得られるものもあります。

| 事項 | 現状 | 関係 |
| --- | --- | --- |
| `table inet azazel_edge` の作成 | 作る installer が無い。enforcement を有効にしても `nft insert` が失敗し、何も適用されない。作る（hook と priority を選ぶ）と enforcement の挙動が変わる。 | #480, #477 |
| `redirect_policy` と OpenCanary のポート | OpenCanary の SSH は 12222 で待ち受けるが、core のおとりの既定は 2222。相対パスの `config/redirect_policy.yaml` は機器では読まれない。 | #479, privilege-inventory §12 |
| NetFlow/SNMP のエントリポイント | `azazel_edge.sensors.netflow_receiver` と `snmp_poller` に `__main__` が無く、unit はすぐに終了コード 0 で終わる。 | #483, #488 |
| ARP 偽装の検知方式 | Suricata 7 は ARP を照合できない。sid 9901211 は無効で、代わりの検知器も無い。 | #481 |
| aarch64 での Mattermost の既定 | aarch64 では既定で入れない（`ENABLE_MATTERMOST=0`。x86_64 は `1` のまま）。イメージは amd64 だけで、16K ページのカーネル上のエミュレーションは未確認。既定を有効に戻すかは実機の 3.8 の結果で決める。 | #485, #477 |
| ホスト INPUT フィルタの既定 | #489 は既定で無効（選択肢 B）。既定で有効にするかは FW-01〜FW-12 の後に別に判断する。 | #489 |
| selftest の `.config_checksums` | `/etc/azazel-edge/.config_checksums` を作るものが無く、selftest は常に `config_checksums_missing` を警告する。 | #487 |
