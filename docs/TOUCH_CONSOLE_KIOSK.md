# Touch Console (`/touch`) and Kiosk Setup

Last updated: 2026-10-27

`/touch` is a full-screen console for a touch display attached to the Edge
device. The primary target is the Raspberry Pi Touch Display 2 (7 inch,
1280x720 landscape); the layout also holds at 720x1280 portrait and at 800x480.

It is a front end only. It reads and operates through the **existing** Web UI
API with the **existing** token and roles. It adds no endpoint, no role, no
approval flag and no environment switch, and it cannot do anything the API
does not already allow for the token entered on it.

## What it shows

| Tab | Content | Source (existing API) |
| --- | --- | --- |
| Status | Defensive State (the arbiter's selected action), SOC and NOC state, P0 / SOC critical count, M.I.O. (AI) availability, decision record (trace id, policy profile), uplink, snapshot age and source, M.I.O. advisory text | `GET /api/dashboard/bundle`, `GET /api/state/stream` |
| Alerts | P0 / NOW / WATCH / BACKLOG counts and the NOW + WATCH alert rows, paged | `GET /api/dashboard/bundle` (`evidence.alert_queues`) |
| Network | Uplink facts; Wi-Fi scan and connect | bundle state, `GET /api/wifi/scan`, `POST /api/wifi/connect` |
| Operate | Suggested runbook (preview / execute), results of this screen's operations | `GET /api/runbooks/<id>`, `POST /api/runbooks/act` |
| Settings | Language (ja/en), dark/light display, access token | none |

Every state is shown as a word and an icon as well as a colour. Missing data is
`—` / unknown, never green. A stale snapshot (older than 30 s), a lost
connection, or a snapshot that did not come through the control daemon
(file fallback, daemon not answering) is marked STALE or UNVERIFIED and is not
shown green either. AI output is labelled "M.I.O. advisory — AI IS NOT
DECISION AUTHORITY"; the Defensive State shown is the deterministic arbiter's
selected action, never an AI output.

The page polls `GET /api/dashboard/bundle` (the dashboard's own poll, at the
dashboard's cadence, at least every 4 s) and, while someone is using the
panel, keeps one `GET /api/state/stream` connection open. The stream is read
with `fetch()` so that the token goes in the `X-Auth-Token` header and never in
the URL.

Load on the Edge: each open state stream makes the Web UI run its monitoring
checks (several `systemctl is-active` calls) and a `mode_status` query once a
second. So that a panel that is always on does not add that load all day:

- the stream is closed after 5 minutes without a touch, and reopened by the
  next touch (the header then shows "Periodic update": the bundle poll keeps
  the screen current);
- when the page is hidden (`visibilitychange`), both the stream and the bundle
  poll stop, and resume when it is shown again;
- after a `stream_error` event it waits at least the server's `retry` (15 s),
  and after three in a row it stays on the bundle poll for 5 minutes; other
  failures back off from 2 s to 1 minute.

Blanking the screen with `wlopm` does not necessarily hide the page, so the
idle rule above is what keeps a blanked panel off the stream. The server side
is unchanged.

## Operations and how each is confirmed

| Operation | API and role (unchanged) | Confirmation |
| --- | --- | --- |
| Wi-Fi scan | `GET /api/wifi/scan` (no token, as today) | none (read only) |
| Wi-Fi connect, protected network | `POST /api/wifi/connect` (operator) | passphrase on the on-screen keyboard, then press and hold "Hold to connect" |
| Wi-Fi connect, saved or open network | `POST /api/wifi/connect` (operator) | confirmation sheet (SSID, security, note), then press and hold |
| Runbook preview | `POST /api/runbooks/act` `action: preview` (operator) | none (dry run) |
| Runbook execute | `POST /api/runbooks/act` `action: execute` (operator, runbook review and approval rules as today) | confirmation sheet, then press and hold. Offered only for `read_only` / `controlled_exec` runbooks without required arguments; others say to use Ops Comm |

"Press and hold" is 1.2 s of continuous press; lifting early cancels. A single
tap — including the touch that wakes a blanked screen — cannot start an
operation.

The result is shown as reported, never upgraded: success only when the API
answered `ok: true`; otherwise "Failed", "Refused by review or approval rule",
"Not allowed (token or role)", "Not implemented on this device"
(`not_implemented`), "Not delivered" (`undelivered`, daemon not reachable), or
"No answer — it may have run" (`delivery_unknown`, a daemon timeout, an empty reply or
a reset after sending, or no HTTP answer). "Refused by the control daemon" is
shown for `busy`, `forbidden` and a rate limit (nothing was run).
`status_api_error` is a failure. Any other 5xx answer to an operation
(including the generic "Server error") is shown as "No answer — it may have
run", because it does not say that nothing ran.

Not offered on this screen: disconnect, shutdown / reboot, client trust,
M.I.O. questions, and the
legacy concept mode (Portal / Shield / Scapegoat): it is neither shown nor
offered, following #340 ("do not resurrect legacy mode UI"); the Defensive
State is the outward state (see [decision-loop.md](architecture/decision-loop.md)).
Use the main dashboard or Ops Comm for the others. contain / release /
stage-open and the portal viewer are not offered anywhere (removed in
Edge#477: nothing on an Edge provided them).

## Secrets

- The access token is typed on the Settings tab and kept in page memory only.
  It is not written to localStorage, sessionStorage or a cookie, and it is not
  put in a URL. Reloading the page forgets it. A `?token=` in the address is
  removed from the address bar and not used — but by then the request carrying
  it has already reached the server, so it can be in the nginx / gunicorn
  access log, in the browser history and in the kiosk command line. Never open
  `/touch` (or any dashboard page) with `?token=`; if it happened, rotate that
  token.
- If the same browser profile already holds the token the existing dashboard
  pages store (`localStorage` key `azazel_token`, written when a dashboard page
  is opened with `?token=`), `/touch` reads it. It never writes it. Use a
  dedicated, incognito kiosk profile (below) to avoid that.
- The Wi-Fi passphrase is typed on the on-screen keyboard (no `<input>`, so the
  browser cannot autofill or offer to save it), shown masked unless "Show" is
  pressed, sent once, and cleared from the page right after it is sent. The
  Web UI does not log it (existing behaviour).
- Use the least role that covers what the panel needs: a `viewer` token for a
  display-only panel, `operator` for Wi-Fi and runbooks. No operation on this
  screen needs `admin`. Tokens and roles are the
  existing `auth_tokens.json` entries; nothing new is configured.

## Kiosk on Raspberry Pi OS (user session)

These steps run in the desktop user's session. They add no root service and no
systemd unit.

1. Fonts for Japanese, if the panel will show Japanese:
   `sudo apt install fonts-noto-cjk` (a package, not a service).
2. Choose the address.
   - Browser on the Edge device itself: `http://127.0.0.1:8084/touch` (the Web
     UI listens on loopback; no certificate is needed). If
     `AZAZEL_AUTH_MTLS_REQUIRED` is on, operator and admin operations need the
     client-certificate header that only the TLS proxy adds, so use the HTTPS
     address below instead.
   - Browser on another machine: `https://<edge-address>/touch`, after trusting
     the local CA (step 3).
   - Add `?lang=ja` or `?lang=en` to fix the start language. Never add the token.
3. Trust the local CA (HTTPS only). Download it from
   `https://<edge-address>/api/certs/azazel-webui-local-ca.crt`, compare its
   SHA-256 with `/api/certs/azazel-webui-local-ca/meta` as shown on the device
   itself, then add it to the user's NSS database (used by Chromium on Linux):

   ```bash
   sudo apt install libnss3-tools
   mkdir -p "$HOME/.pki/nssdb"
   certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n "Azazel-Edge local CA" -i azazel-webui-local-ca.crt
   ```
4. Start Chromium full screen from the session's autostart. On the labwc
   desktop (Raspberry Pi OS Bookworm default) add this line to
   `~/.config/labwc/autostart`; on Wayfire put it under `[autostart]` in
   `~/.config/wayfire.ini` as `touch = <command>`:

   ```bash
   chromium-browser --kiosk --incognito --noerrdialogs --disable-infobars \
     --disable-pinch --overscroll-history-navigation=0 \
     --disable-features=TranslateUI --password-store=basic \
     "http://127.0.0.1:8084/touch?lang=ja" &
   ```

   (`chromium` instead of `chromium-browser` on newer images.) `--incognito`
   keeps nothing between sessions; the display theme then resets to dark at
   each start.
5. Screen blanking. Keep the panel on during operations, or let it blank after
   inactivity: Raspberry Pi Configuration → Display → Screen Blanking, or in the
   labwc autostart for example
   `swayidle -w timeout 600 'wlopm --off \*' resume 'wlopm --on \*' &`.
   A touch wakes the screen; because every operation needs a press-and-hold,
   that touch cannot start one.
6. Rotation: set it in Screen Configuration; the console switches to the
   portrait layout (tabs at the bottom) by itself.
7. After each start, open Settings and enter the token on the on-screen
   keyboard.

To leave kiosk mode, close Chromium from a keyboard (Alt+F4) or over SSH.

## Japanese summary (日本語の要約)

- `/touch` はタッチパネル用の画面です。既存の API・トークン・権限だけを使い、
  新しい操作や権限は増やしません。
- 影響のある操作（Wi-Fi 接続、Runbook 実行）は、確認画面のあと「長押し（1.2 秒）」で
  実行します。旧コンセプトモード（Portal/Shield/Scapegoat）は #340 に従い表示も操作も
  しません。
- SSE（`/api/state/stream`）は触っている間だけつなぎ、5 分触らないと切ります。
  ページが非表示のときはポーリングも止めます。結果は API の応答どおりに表示し、未実装・
  未配送・応答なし（実行された可能性あり）を成功に見せません。
- `?token=` 付きで開くと、画面側で消してもサーバのアクセスログ・履歴に残ります。付けないでください（付けたらトークンを替える）。
- トークンとパスフレーズはページのメモリにだけ置き、保存・URL・ログに残しません。
  再読み込みでトークンは消えます。キオスクでは `--incognito` を推奨します。
- キオスクはユーザーセッションの autostart で Chromium を `--kiosk` 起動します
  （root のサービスや unit は追加しません）。同じ機器なら
  `http://127.0.0.1:8084/touch`、別の機器からなら CA を信頼して HTTPS で開きます。
