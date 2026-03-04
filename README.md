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
- `sshd` を `ListenAddress 172.16.0.254` に固定
- `nftables` で `br0 -> WAN` の NAT/forward を設定（既定: デフォルトルートのIF）

外部WAN (`eth1`/`wlan1`) の uplink は自動検出（必要なら `WAN_IF` で上書き）します。OpenCanary・policy routing は対象外です。

## 実行
```bash
cd /home/azazel/Azazel-Edge
sudo AP_SSID='Azazel-Internal' AP_PSK='yourStrongPass123' ./installer/internal/install_internal_network.sh
```

`AP_SSID` と `AP_PSK` を省略するとデフォルト値が使われます。

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
