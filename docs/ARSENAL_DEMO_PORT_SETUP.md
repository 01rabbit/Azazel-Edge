# Arsenal-Demo Port Configuration Guide

Arsenal-Demo を別ポートで実行するための設定方法を説明します。

## 永続化設定（本番環境）

### 1. systemd サービス設定

`/etc/default/azazel-edge-web` を作成・編集：

```bash
sudo cp systemd/azazel-edge-web.defaults.template /etc/default/azazel-edge-web
sudo vi /etc/default/azazel-edge-web
```

以下の行を設定：

```
AZAZEL_WEB_PORT=8084
AZAZEL_ARSENAL_DEMO_PORT=8885
```

その後、サービスを再起動：

```bash
sudo systemctl restart azazel-edge-web
```

### 2. 設定の確認

```bash
# 設定ファイルの内容確認
cat /etc/default/azazel-edge-web

# サービス状態確認
sudo systemctl status azazel-edge-web

# ポート使用状況確認
netstat -tlnp | grep :8885
```

## 開発時設定

### 環境変数で直接指定

```bash
# Arsenal-Demo を 8885 ポートで直起動
AZAZEL_ARSENAL_DEMO_PORT=8885 AZAZEL_ARSENAL_DEMO_MODE=1 python3 azazel_edge_web/app.py
```

注意:
- `python3 azazel_edge_web/app.py` の直起動では Flask 開発サーバーが単一ポートでしか待ち受けできないため、`AZAZEL_ARSENAL_DEMO_MODE=1` を付けると Web UI 全体が `8885` に切り替わります
- `8084` と `8885` の両方を同時に待ち受けたい場合は、上記の systemd サービス設定を使ってください

### .env ファイルで設定

`.env.demo.template` をコピーして `.env` を作成：

```bash
cp .env.demo.template .env
```

`.env` を編集：

```
AZAZEL_WEB_PORT=8084
AZAZEL_ARSENAL_DEMO_PORT=8885
AZAZEL_ARSENAL_DEMO_MODE=1
```

## ポート設定の優先順位

1. **systemd / Gunicorn 起動:**
   - `AZAZEL_WEB_PORT` で待ち受け
   - `AZAZEL_ARSENAL_DEMO_PORT` が別値なら、そのポートも追加で待ち受け

2. **`python3 azazel_edge_web/app.py` 直起動 + `AZAZEL_ARSENAL_DEMO_MODE=1`:**
   - `AZAZEL_ARSENAL_DEMO_PORT` を使用（単一ポート）

3. **通常モード:**
   - `AZAZEL_WEB_PORT` を使用（デフォルト: 8084）

## 確認方法

```bash
# 標準Web UI (ポート8084)
curl http://127.0.0.1:8084/

# Arsenal-Demo (ポート8885)
curl http://127.0.0.1:8885/arsenal-demo
```

## 注意事項

- systemd サービス起動では `AZAZEL_ARSENAL_DEMO_MODE` は不要です
- `AZAZEL_ARSENAL_DEMO_MODE=1` が必要なのは `python3 azazel_edge_web/app.py` を直起動する場合だけです
- ファイアウォールでポートが開かれていることを確認してください
- Webアプリケーションの再起動が必要です
- 永続化設定はsystemdサービス再起動後も維持されます
