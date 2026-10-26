# Changelog

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Settings and behaviour that disagreed (Edge#477):
  - `control.sock` `contain`, `disconnect` and `stage_open` answer
    `{"ok": false, "error": "not_implemented"}` instead of appending a line
    to `/run/azazel-edge/action_requests.log` (read by nothing) and answering
    success; their scripts are removed. Nothing new is enforced. The CLI
    returns any answer of the daemon as it is (a refusal or an unusable
    reply stays a failure). A request sent without a reply (timeout, closed
    before a reply) is `delivery_unknown: true`: it may have run, so it is
    not handed on and the CLI says to check the state before running it
    again. Only when the daemon was never reached (no socket, connect
    failed) does it write the legacy `ui_command.json`, which nothing here
    reads, so the result is `ok: false, undelivered: true` instead of
    `ok: true`. The CLI labels
    Stage-Open and Contain as not implemented.
  - The Web UI's `/api/state/stream` sends a `stream_error` event (with
    `retry: 15000`) with the reason
    (`busy`, `stream_closed`, `socket_missing`, …) when the daemon's watch
    stream ends, instead of ending silently.
  - The port 8082 status API call uses `curl --fail`: an HTTP error reply,
    an empty reply where one is required or a non-JSON reply is the status
    API's refusal and a failure, not "Containment activated"; `disconnect`
    falls back to `uplink_disconnect` only when nothing answers (refused,
    timeout). No server for 8082 ships here.
  - The Web UI reads the portal viewer's status under the unit the control
    daemon starts (`azazel-edge-portal-viewer.service`, was
    `azazel-portal-viewer.service`); a missing unit is reported as not
    installed. The unit itself is still not shipped.

### Security

- External exposure found by the audit before the device run (Edge#477):
  - **Action required on a device installed by an earlier version:** if the
    Mattermost admin account still has the former fixed password,
    `provision_mattermost_workspace.sh` ends with `[ACTION REQUIRED]` and
    exit code 3 instead of success (the password is not changed for you).
    Log in at `http://172.16.0.254:8065` as `azazelops`, change it (Profile >
    Security > Password), put the new one in `MATTERMOST_PASSWORD=` in
    `/etc/azazel-edge/mattermost-credentials.env` (0600 root; edit it with
    `sudoedit`, not on a command line), and run
    `sudo ENABLE_OLLAMA=0 installer/internal/install_ai_runtime.sh` again from
    the Azazel-Edge checkout used for the install (it also registers the
    slash command and restarts the Web UI and the AI agent; the copy in
    `/opt/azazel-edge` cannot find the repository and is not the entry). If
    the device was installed with `install_all.sh`, its later stages (dev
    remote access, Vector, sensors) did not run either: run the enabled
    ones as `install_all.sh` would.
  - `provision_mattermost_workspace.sh` also fails (exit 1, with what to do)
    when Mattermost would not be reachable from the LAN: nginx is not
    installed, or an earlier container still publishes 8065 on every
    interface; the fix is the same re-run of `install_ai_runtime.sh`.
  - ntfy listens on `127.0.0.1:8081` only (was every interface, so the WAN
    too) with `auth-default-access: deny-all` (was `read-write`); the
    anonymous read-write grants on the alert and info topics are removed,
    also from an existing auth database. The Edge account reads and writes
    them with its token (0640 root:azazel-web, as before), which the Web UI
    bridge already sends. The installer stops when an anonymous read is not
    refused or the token is. The ntfy web app is off. The Web UI and CLI
    health probes try loopback first.
  - Mattermost publishes on `127.0.0.1:18065` only (was `8065` on every
    interface, which Docker opens past the host firewall). LAN clients keep
    `http://172.16.0.254:8065` through an nginx site that
    `provision_mattermost_workspace.sh` writes, admitting `172.16.0.0/24` and
    loopback only.
  - The Mattermost database password is no longer a fixed value in the
    compose file: `mattermost_db_secret.sh` makes a random one in
    `/etc/azazel-edge/mattermost-db.env` (0600 root) before the stack starts
    and changes an existing database's password to it first. The admin
    password is no longer a fixed default: it is random on first run, kept
    in `mattermost-credentials.env` (0600 root) and never printed (see the
    action required above for a device still using the former default).
  - The Mattermost image is pinned to `12.0.1` (was `latest`). It exists for
    `linux/amd64` only; on a Pi it runs under qemu-user emulation, which may
    not work on a 16K-page kernel (not shown on the device).

- Four hardening fixes from Edge#477 (found by the #471 privilege inventory):
  - Wi-Fi connect (control daemon, `wifi_connect.py`): the passphrase is no
    longer on nmcli's argv (readable from `/proc/<pid>/cmdline`). A new
    profile is added without its secret (`nmcli con add …
    connection.autoconnect no wifi-sec.key-mgmt <as NetworkManager would
    complete it from the AP>`); a saved one given a new PSK is copied
    (`nmcli con clone` as `azazel-wifi-pending-<UUID>`, autoconnect off,
    its stored PSK dropped with `wifi-sec.psk-flags 2`, then `0`); both are
    brought up with `nmcli con up … passwd-file <file>`. The saved profile
    is not changed until the copy is up: then it is deleted by UUID and the
    copy takes its name; on any failure the copy is deleted and the saved
    profile keeps its old PSK. A copy left by a crash is deleted by UUID on
    the next connect when its original still exists and it is not active
    (otherwise kept and reported). Profiles are addressed by the UUID of
    the SSID match throughout, never by name (a name may be shared by a
    profile of another SSID). One connect runs at a time: an exclusive
    `flock` on `/run/azazel-edge-wifi-connect.lock` (0600, `O_NOFOLLOW`,
    must be a private regular file) covers the sweep and the connect; a
    second connect waits up to 30 s, then gets a "busy" error. The file is 0600 (`O_EXCL`,
    `O_NOFOLLOW`) in a fresh 0700 directory under `/run`, holds the secret
    octal-escaped, and is removed on success, failure and exception.
    NetworkManager stores the secret in the profile as before. key-mgmt
    for a new profile is chosen across every AP of the SSID (any PSK AP →
    `wpa-psk`, all SAE-only → `sae`); an SSID with an 802.1X AP, or an
    existing 802.1X profile given a passphrase, is refused instead of being
    turned into a PSK profile; a new profile whose activation fails is
    deleted by its UUID (as `nmcli dev wifi connect` left nothing behind).
  - `provision_mattermost_workspace.sh`: `mattermost-credentials.env` is
    written 0600 from creation (mktemp beside it, `mv -T` over it), not with
    the default umask followed by `chmod`; a symlink there is replaced, not
    followed.
  - `azazel-edge-selftest` (root): the SD write-speed test writes to a new
    `mktemp` name in `/tmp` (`dd conv=nocreat`) instead of the fixed
    `/tmp/azazel_sdtest`, and removes it on every exit.
  - `migrate_audit_path.migrate_chain`: an `os.link` that fails with EXDEV
    (old and new log directories on different filesystems) no longer ends
    in a traceback: it stops before that file (state `cross_filesystem`,
    exit 2; nothing copied, unlinked or carried), and
    `setup_agent_account.sh` prints a NOTICE with the manual steps. Other
    link errors still stop with the error.
- More hardening from Edge#477:
  - Sensors: the netflow and snmp units run as the dedicated system account
    `azazel-sensor` instead of `azazel` (which no installer created and which
    is the login account on many devices). `install_sensors.sh` creates it
    (`setup_sensor_account.sh`: system user and group, `nologin`, no home; an
    existing `azazel-sensor` that is not such an account stops the script).
    The account `azazel` is not created, changed or checked.
  - Rust core: the apply path starts `nft`/`tc` by absolute path from
    `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin` with the environment cleared
    (`LC_ALL=C`, `LANG=C`, a fixed `PATH`), as the release path does. The
    commands applied are unchanged; any other `argv[0]` is refused.
  - Ollama: `docker-compose.ollama.yml` publishes 11434 on `127.0.0.1` only
    (every client is on the host).
  - Installer: `azazel_edge_web/auth.py`, `io_helpers.py`,
    `py/azazel_edge/_util.py` and the other modules the installed code
    imports (`aggregator`, `audit_review`, `deception_*`, `decision_layers`,
    `fabric_view`, `i18n`, `policy`, `snapshot_model`, all of `sensors/`),
    and every Web UI template and static file, are installed and compared by
    `verify_runtime_sync.sh`. A test checks the installer against the
    package's modules.
  - `wifi_connect.py` run by hand: `--passphrase` is refused; the
    passphrase is read from stdin with `--passphrase-stdin`. Every nmcli
    call runs under `LC_ALL=C.UTF-8`, so the UUID read from nmcli's message
    does not depend on the device's locale.
  - `provision_mattermost_workspace.sh`: `upsert_env` (the bot token, the
    webhook URL) writes `/etc/default/azazel-edge-web` 0600 from creation
    through `write_private_file`, instead of `touch` and `sed -i`/`>>`.

### Changed

- AI agent runs as the non-root account `azazel-agent` (Edge#471 stage 2;
  details, upgrade and rollback in `docs/architecture/privilege-inventory.md`
  §11.7):
  - `azazel-edge-ai-agent.service`: `User=`/`Group=azazel-agent`, no
    capabilities, `NoNewPrivileges`, `ProtectSystem=strict`,
    `ProtectHome=yes`, `PrivateTmp=yes`,
    `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`,
    `RuntimeDirectory=azazel-edge-ai` (0700), `StateDirectory=azazel-edge-agent`,
    `UMask=0027`; `WorkingDirectory=` unchanged. New tmpfiles.d
    `azazel-edge-agent.conf`: `/run/azazel-edge-agent`,
    `/run/azazel-edge-agent-query`, `/var/log/azazel-edge/ai`, 2750
    azazel-agent:azazel-web.
  - the agent writes only in its own directories (advisory, metrics, policy
    and its snapshot fields in `/run/azazel-edge-agent`; logs, the
    core-decision audit chain and the P0 queue in `/var/log/azazel-edge/ai`;
    the decision log in `/var/lib/azazel-edge-agent/decisions`), never
    chmods the shared `/run/azazel-edge`, refuses an unsafe directory, and
    stops instead of falling back to `/tmp` for its audit log.
  - the control daemon is the single writer of `ui_snapshot.json` and merges
    a fixed list of the agent's fields from the agent's own file; the daemon,
    the Web UI (advisory, metrics, AI logs, status view) and the AI log
    runbook read the new paths.
  - installer: `setup_agent_account.sh` creates the account, moves the chain
    and the P0 queue together and carries the relay's reconcile cursor
    (`azazel_edge.notify.migrate_audit_path`, no replay), copies the decision
    log and runtime files, rewrites only old-default variables, adds
    `/var/lib/azazel-edge-agent` to the Wazuh FIM paths, restarts control
    daemon → agent → Web UI.
  - the runbook loader logs and skips a runbook directory it cannot search.

- Web UI runs as the non-root account `azazel-web` (Edge#471 stage 1; details,
  upgrade and rollback in `docs/architecture/privilege-inventory.md` §10.9):
  - `azazel-edge-web.service`: `User=`/`Group=azazel-web`,
    `SupplementaryGroups=azazel-control`, no capabilities, `NoNewPrivileges`,
    `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
    `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` and the
    other §10.6 settings; `RuntimeDirectory=`/`StateDirectory=`/
    `LogsDirectory=azazel-edge-web`, where the Web UI's state and logs now
    live by default.
  - control daemon: `control.sock` checks the peer uid (`SO_PEERCRED`)
    against a fixed table (root: all; `azazel-web`: the actions the Web UI
    uses; anyone else: refused and counted; `migrate_path_schema` root
    only). Connection limits keep headroom for root (non-root ≤ 24 of
    32, ≤ 16 `watch_snapshot` streams); a dead idle watch stream frees its
    slot. New fixed actions, relocated from the Web UI by owner decision:
    `uplink_disconnect` (no parameters; the daemon's own `AZAZEL_UP_IF`),
    `sot_devices_replace` / `sot_devices_patch` (validated with `SoTConfig`,
    atomic write; the daemon is the only SoT writer). Requests up to 1 MiB.
  - AI agent (still root): a `manual_query`-only socket for the Web UI,
    `/run/azazel-edge-agent-query/agent-query.sock` (0750 directory and 0660
    socket, group `azazel-web`, peers root and `azazel-web`); once it
    listens, `ai-bridge.sock` refuses `manual_query`. The Web UI's
    `AZAZEL_AI_SOCKET` default is that socket.
  - Web UI: no `ip link` and no `docker ps` any more; triage sessions and
    the triage audit chain never fall back to `/tmp` (503 with the reason);
    a trend store write failure no longer makes `/api/dashboard/*` answer
    500; unreadable/missing token files are logged and reported; authz audit
    failures are counted in `/health`; a controlled-exec runbook that fails
    as non-root says so.
  - installer: creates `azazel-web` / `azazel-control` idempotently, moves
    only old-default lines in `/etc/default/azazel-edge-security` and
    `/etc/default/azazel-edge-web`, copies the Web UI's existing state into
    its new directories (keeping the originals), makes the Web UI's token
    files, `sot.yaml` and `first_minute.yaml` `0640 root:azazel-web`, never
    widens `/etc/azazel-edge` (no script resets its mode any more; a 0750
    root:root one gets group `azazel-web`), makes the local CA and server
    keys 0600 explicitly, adds the Web UI's directories to the Wazuh FIM
    paths, and restarts the control daemon, the agent and the Web UI in that
    order.

### Added

- `docs/architecture/privilege-inventory.md` (Edge#471 stage 0, documentation
  only, no behaviour change): what `azazel-edge-web`, `azazel-edge-ai-agent`,
  `azazel-edge-control-daemon`, `azazel-edge-core` and the other units read,
  write, connect to and execute, and which of those need root, a capability
  or a group; a non-root container observation of the Web UI and the agent
  (labelled as a container, not hardware evidence); the stage 1 (Web UI as
  `azazel-web`, plus a dedicated agent query socket for `manual_query`) and
  stage 2 (agent as `azazel-agent`) plans; the owner decisions taken so far;
  open questions.
- Focus screens informed by commercial SIEM/SOC/NOC dashboard patterns
  (design notes in `docs/architecture/socnoc-workspace-design.md`):
  - **Simple+**: the Simple landing view gains a Splunk-style KPI strip
    (Risk / Now queue / Direct critical / Impacted clients / Uplink /
    Services, with ~1-min trend arrows), a band-colored 60-min activity
    strip, and a deterministic pipeline funnel
    (`events → signals → now/watch → action`).
  - **SOC Focus panel** (SOC workspace): NOW/WATCH/BACKLOG + critical +
    visibility + oldest-unhandled-NOW KPIs, a real triage **table** over the
    deterministic queue bands (band chips + keyword filter), a Decision card
    (arbiter's pick, why, why-not-stronger, confidence/evidence/AI role),
    and a 6-hour alerts-over-time strip.
  - **NOC Focus panel** (NOC workspace): uplink/internet/capacity/clients/
    impacted/services KPIs, a five-hop **path health strip**
    (clients → edge → uplink → gateway → internet; the edge-local answer to
    a geo map), a top-talkers table joined with the client identity view,
    runtime meters, and service chips.
  - **BHUSA 2026 decision rationale per jurisdiction**: the booth-focus
    payload now exposes `domains.noc` / `domains.soc` (per-domain evaluator
    `reasons` from the same v2 explanation record), and the bundle carries
    the whole projection as `decision_focus`. The SOC focus panel's decision
    card shows the arbiter's pick, the SOC evaluator rationale, why-not-
    stronger, the release condition, and the audit line (trace · policy ·
    config hash · evidence ids · DRY RUN/ENFORCED); the NOC focus panel
    gains the mirrored card with the NOC jurisdiction's rationale. Falls
    back to the live actions payload when no explanation record exists.
  - Backend: the dashboard bundle gains an `activity` key — time-bucketed
    alert counts (1h/2min, 6h/20min) banded with the same thresholds and
    `_normalize_alert_event` normalizer as the alert queues; queue item caps
    raised 5→12 per band (8 for escalation) for the triage table. Documented
    in `docs/API_REFERENCE.md`.

- `GET /api/dashboard/bundle`: one-request snapshot for the dashboard poll,
  aggregating summary / actions / health / evidence / trends / state /
  topolite seed mode / Mattermost status plus role-gated operator-progress
  and handoff blocks (null for viewers). The WebUI now polls this single
  endpoint instead of ~11 parallel requests per tick — removing the
  documented worker-starvation / OFFLINE-flicker failure mode and reading
  shared inputs (state.json, AI metrics/advisory, JSONL tails) once
  server-side instead of once per endpoint. Per-panel endpoints unchanged;
  documented in `docs/API_REFERENCE.md`.

### Changed

- `ai-bridge.sock` moves to its own directory and is owner only (Edge#462
  item 2, short-term). Default path `/run/azazel-edge-ai/ai-bridge.sock`
  (was `/run/azazel-edge/ai-bridge.sock`) in the agent, the Web UI, the core's
  default and the core unit. The agent creates the directory with mode `0700`
  and its own account, binds the socket under umask `0177` with mode `0600`
  and its own user and group, and applies `AZAZEL_RUNTIME_SOCKET_GROUP` to
  neither. It refuses to start (no fallback) when the directory is a symlink,
  not a directory, owned by another account or has group/other bits, or when
  the socket path holds something other than a socket. Members of the shared
  group, which still use `control.sock` in `/run/azazel-edge` (unchanged),
  can no longer connect to, rename, remove or replace `ai-bridge.sock`.
  `AZAZEL_AI_SOCKET_MODE` is no longer applied (an existing value is ignored
  with a warning) and no longer seeded. The installer rewrites an
  `AZAZEL_AI_SOCKET` line that still holds the old default path. Root can still
  connect and forge; the core and the Web UI do not verify the socket's peer
  (Edge#471); privilege separation is tracked separately. Not validated on a
  VM or on hardware. Compatibility: a non-root tool that used the socket
  through the shared group loses that access, tools that hard-code the old
  path must use the new one, and an `AZAZEL_AI_SOCKET` value pointing into
  `/run/azazel-edge` that the installer does not rewrite makes the agent
  refuse to start.
- P0 alert path (Edge#462 items 1, 3, 4; notification and audit only, no
  change to decisions or enforcement):
  - `core-decision-audit.jsonl` rotates on a chain boundary at 16 MiB with
    one rotated file kept (`P0AuditLogger(max_bytes=, keep=1)`; other
    `keep` values are rejected). The chain
    continues across files (`chain_prev`, plus `chain_id` on each new
    file's first record); the relay's reconcile and the recorder's key
    window read the retained files as one consistent snapshot
    (`azazel_edge.audit.segments.read_chain`). A cursor rotated out is
    reported as `cursor_rotated_out` and the retained chain is replayed
    (bounded) instead of `cursor_not_in_chain`. New
    `P0AuditLogger.verify_rotated_chain`.
  - The reconcile cursor is per audit file and chain: queue entries carry
    `audit_path` and `audit_chain_id`, and a relay resumes from its own
    cursor. Another audit file's chain on a shared queue is reconciled as
    `fresh_chain`; a replaced or head-cut chain in the same file is
    `chain_replaced` (counted as `unreconcilable`, nothing replayed).
    Replays by `fresh_chain` or `cursor_rotated_out` are always presented
    as past decisions. Chain ids are not authenticated (documented).
  - P0 decisions dropped by the recorder's hand-off, the relay's hand-off
    or the audit listener hand-off are recovered while the agent runs
    (`core_loss_reconcile` / `loss_recovery` status records), with the
    same past-decision presentation, event-key/chain-hash deduplication
    and 256 bound as the startup reconcile.

- WebUI baseline language is now English: with no explicit `?lang=` /
  `X-AZAZEL-LANG` header / `azazel_lang` cookie / saved browser choice, pages
  render in English (`Content-Language: en`). Japanese remains fully available
  via the existing 日本語/English toggle, and an explicit or previously saved
  choice always wins. Aligns the UI with the repository language policy
  (English default, Japanese supplemental). Non-web surfaces (notifications,
  runbook wording defaults) are unchanged.

### Removed

- Wazuh active response (Edge#412, owner decision):
  `installer/internal/install_wazuh_agent.sh` no longer generates
  `/var/ossec/active-response/bin/azazel-block.sh`, the `iptables` DROP script
  the Wazuh manager could start. It was a second enforcer outside the Rust
  `azazel-edge-core`. On upgrade the installer removes the script if present
  and sets `<disabled>yes</disabled>` in the agent's `<active-response>` block,
  then restarts an already-running agent (`systemctl try-restart`) so the
  setting takes effect.
  The Wazuh agent (FIM and SCA) and Vector forwarding remain optional,
  observation-only integrations; defensive actions come only from the core.
  `tests/test_enforcement_boundary_inventory_v1.py` drops the exception entry,
  and `docs/X86_64_INTEGRATION_BOUNDARY.md` now states that no defensive path
  exists outside the core.
- Dashboard audience split (Beginner/Professional toggle): the Simple view
  now serves the "show me less" need, so the audience axis, the
  `pro-only`/`temp-only` gating, the Temporary Mission panel, the temporary
  triage / ask-tell blocks, and the dashboard progress-checklist block are
  gone. The workspace toggle (`Simple | All | NOC | SOC`) is fully available
  to every operator; `/api/dashboard/actions` still accepts `audience` for
  other surfaces (the dashboard always requests professional wording).
- Dashboard routes to the AI assist (M.I.O.): the topbar "Ask M.I.O." link,
  the M.I.O. assist rail (ask form, shortcuts, rationale/review blocks), and
  the per-panel "Ask about this" buttons are removed. The rail now hosts a
  deterministic Handoff panel (brief pack, copy, send to Ops Comm /
  Mattermost, Mattermost reachability). The `/api/ai/*` endpoints and the
  Ops Comm surface are unchanged.

- Simple view as the dashboard's default landing screen: three verdict tiles
  answering "Overall — are we safe? / SOC — any threat? / NOC — is the network
  healthy?", each with a one-line reason, the top "Do now" action, and
  glance chips; click a tile to drill into the full board or the SOC/NOC
  workspace. Verdicts have four states (GOOD/WATCH/BAD and UNKNOWN when
  inputs are stale — a stale snapshot never renders a false green) and reuse
  the existing deterministic `summarize*`/`strongestTone` logic, so the Simple
  tile can never disagree with the full board. Available in both audiences;
  the workspace toggle is now `Simple | All | NOC | SOC` (NOC/SOC still
  professional-only). Design rationale added to
  `docs/architecture/socnoc-workspace-design.md`.

- SOC / NOC workspace modes for the dashboard (design note:
  `docs/architecture/socnoc-workspace-design.md`, informed by SIEM/SOC/NOC
  dashboard design research — role-specific views over a single pane of glass,
  the 5-second rule, alert-by-exception, NOC glanceability). A topbar
  `All | NOC | SOC` toggle (professional audience only, persisted, `?workspace=`
  override) re-composes the existing panels per domain: the SOC workspace leads
  with posture → SOC/NOC split → action board → evidence timelines (split and
  evidence folds auto-open), hiding NOC-only detail blocks; the NOC workspace
  leads with client identity → path/service boards → runtime health → node
  fleet, hiding the threat-posture card, SOC detail split card, and the
  evidence audit board. Cross-domain glance cards are never hidden (the
  doctrine requires checking the other domain before stronger control). Fold
  persistence now records only explicit summary clicks so workspace defaults
  don't overwrite operator choices. No new endpoints or payload changes.

- Dashboard usability pass (post-BHUSA 2026 polish, roadmap #283): sticky
  section navigation over the dashboard panels (audience-aware; absorbs and
  replaces the old Topo-Lite mini nav panel) with a back-to-top button;
  `<details>` fold state now persists across reloads (localStorage);
  header freshness controls — an "UPD" seconds-since-last-update chip that
  turns amber when stale, a manual refresh button, and a pause/resume
  auto-refresh toggle (LINK chip shows `PAUSED`); evidence timelines gained a
  keyword filter and "+N more" expanders instead of silent `.slice()`
  truncation (alert queues now keep up to 8 now / 4 escalation entries
  available). Accessibility: `aria-pressed` on language/audience/mode/pause
  toggles, `role="group"` instead of misused `role="tablist"`.
  i18n: ~25 hardcoded English strings in `index.html` and the JS timeline
  empty-state/`Switch to Live` labels now go through `tr()` with new ja/en
  catalog keys. No API surface change; dashboard payload contracts unchanged
  (`tests/test_dashboard_data_contract.py` extended for the new elements).

### Changed

- Azazel-Fabric の pin を `v0.3.0` → `v0.4.0` に更新(`requirements/fabric.txt`)。
  `py/azazel_edge/audit/fabric_adapter.py` の AuditEvent 射影を、v0.4.0 で追加
  された `azazel_fabric.audit.project_audit_event`/`to_jsonl_line` に委譲する
  よう小さくリファクタ(ドロップイン、挙動変更ゼロ)。`event_id` は従来どおり
  Edge 側の `chain_hash`(フォールバック `trace_id:kind`)規約を明示的に渡すため
  `project_audit_event` の `make_event_id` デフォルトには委譲しない。ハッシュ
  チェーン書込み経路(`P0AuditLogger`)は無変更。emit されるフィールド集合は
  不変だが、シリアライズが Pydantic の `model_dump_json()`(挿入順・空白区切り)
  から `to_jsonl_line`(キーソート・コンパクト区切り)に変わり、
  `<name>.fabric.jsonl` の行はバイト同一ではなくなった(内容は意味的に同一。
  このストリームを行位置/バイト比較で読むコンシューマは存在しない)。
  `tests/test_fabric_adapters_v1.py` の `ApiStateStatusViewTests` を
  `azazel_fabric.testing.make_status_view` で簡素化(StatusView のマッピング
  ロジック自体は `StatusViewTests` で別途検証済みのため、API 読み戻しテストは
  Edge 独自のスナップショット変換に依存しない汎用フィクスチャへ切替)。
- Azazel-Fabric の pin をオプションの `requirements/fabric.txt` に分離(Fabric
  リポジトリは private のため、無認証環境 = CI では解決不能。全統合点は
  ガード付き no-op なので未導入でも動作は同一。導入時のみ射影が有効化)。

### Added
- Added `SECURITY.md` (private GitHub Security Advisory reporting process, response targets, and appliance-flavored in/out-of-scope boundary between scapegoat/deception surfaces and the protected segment / control plane). Aligned `CONTRIBUTING.md` with a "Security" section pointing to it and a "License" section (MIT), and updated the pytest checklist line with the current baseline (502 passing; known `bhusa` sandbox-only failures in constrained/offline environments).
- Azazel-Fabric adoption — Phase 3 (2026-07-10): Edge now ships the three §3
  emit-alongside projections from `docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md` plus
  an owner-directed StatusView extension, making Edge the top consumer of the
  shared contracts library. All paths are guarded (`try: import azazel_fabric`)
  and are exact no-ops when the package is absent — zero behavior change:
  - **DecisionExplanation projection** (§3.1): each persisted v2 decision
    explanation is additionally serialized as
    `azazel_fabric.schema.DecisionExplanation` to a separate
    `fabric-decision-explanations.jsonl` stream; Edge's own
    `decision-explanations.jsonl` is byte-for-byte unchanged. Lossy interop
    projection (`why_chosen` dict→str, `selected_action` name→`ActionIntent`,
    `why_not_others` flattened to strings).
  - **TrustCapsule projection** (§3.2): emitted as
    `azazel_fabric.schema.TrustCapsule` to `fabric-trust-capsules.jsonl` with
    the plan's field mapping (`hmac_sig`→`hmac`, `timestamp`→`issued_at`,
    `config_hash` sourced from the explanation).
  - **AuditEvent projection** (§3.3): `P0AuditLogger.log()` additionally
    projects `azazel_fabric.schema.AuditEvent` to a separate, non-interleaved
    sibling file (`<name>.fabric.jsonl`) so the hash chain and `verify_chain()`
    are never perturbed. `tactics_engine/decision_logger.py` is left untouched
    (§3.4, deferred).
  - **StatusView emit + surface** (scope extension, owner-directed): new
    `py/azazel_edge/fabric_view.py` builds `azazel_fabric.view.StatusView` from
    the runtime snapshot (carrying the full snapshot under
    `product_view.edge_snapshot`) and writes `ui_status_view.json` alongside
    `ui_snapshot.json`. `GET /api/state` gains a `status_view` key (null when
    unavailable). See `docs/API_REFERENCE.md`.
  - Pins `azazel-fabric` in `requirements/runtime.txt` at the exact merged
    commit (v0.3.0 tag pending).
- Documentation updates for the Azazel series naming change (2026-07-10): Azazel-CTI → Azazel-Knowledge (AZ-04) and Azazel-Common → Azazel-Fabric (AZ-05). Updated the README series table, `docs/INDEX.md`, and added a naming-update status note to `docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md` (file not renamed; body text and `azazel_common` references pre-`v0.3.0` are left as originally written).
- EPD-on-Web preview for Azazel-Edge: read-only, viewer-gated web routes that expose the physical e-paper panel state — `GET /api/epd` (mode/state plus raw `epd_state.json`, desired render spec, and last-drawn frame), `GET /api/epd/preview.png` (pixel-parity PNG rendered in-memory by the real `py/azazel_edge_epd.py` renderer, fail-closed `503` when the renderer/assets are unavailable), and `GET /dev/epd` (self-contained dark-themed dev page). Adds `AZAZEL_EPD_RUNTIME_DIR` / `AZAZEL_EPD_STATE_PATH` / `AZAZEL_EPD_LAST_RENDER_PATH` dev overrides. See `docs/API_REFERENCE.md` and `docs/CONFIGURATION.md`.
- Design-only integration plan `docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md` (2026-07-09) describing the azazel-common contract adapter for Edge; documents planning intent only (no shipped code), with Edge↔CTI integration deferred to FY2027+.
- Candidate CFP draft (`docs/cfp/blackhat-europe-arsenal-auditable-edge-socnoc.md`) and paper-style concept document (`docs/papers/auditable-edge-socnoc-paper.md`) for the Auditable Edge SOC/NOC profile (pre-acceptance planning material; not accepted-appearance records).
- Submission-preparation roadmap (`docs/archive/roadmaps/auditable-edge-socnoc-cfp-roadmap.md`) and gh-registerable issue drafts (`docs/archive/issues/auditable-edge-socnoc/`) for the Auditable Edge SOC/NOC profile.
- BHUSA 2026 booth-preparation document set covering docs sync, talk track, replay runbook, audit walkthrough, booth decision-support view, live/replay boundary, rehearsal runbook, freeze candidate, and final command sheet.
- BHUSA 2026 status helper (`bin/azazel-edge-bhusa-status`) to summarize recorded rehearsals, optional freeze-check results, and GitHub child issue state in one snapshot.
- BHUSA 2026 readiness reports now embed the status snapshot and persist `status.json` through report/archive/freeze-record artifacts.
- BHUSA 2026 issue helper can now render a parent roadmap progress comment from the current readiness snapshot.
- BHUSA 2026 status helper can now render and write the repository `15-status.md` tracking document from the live readiness snapshot.
- BHUSA 2026 issue helper can now sync the created-issue links doc from live GitHub child issue state.
- BHUSA 2026 issue helper can now persist the parent roadmap progress comment as a repo artifact.
- BHUSA 2026 issue helper can now persist the parent issue child-links comment as a repo artifact.
- BHUSA 2026 prep helper now includes `repo-sync` to refresh repo-side status and issue-tracking artifacts in one command.
- BHUSA 2026 prep helper now includes `daily-pack` to refresh repo-side tracking artifacts and generate the operator pack in one command.
- BHUSA 2026 prep helper now includes `candidate-pack` to refresh tracking artifacts, generate the operator/freeze packs, and run the local freeze gate in one command.
- BHUSA 2026 candidate-pack output now includes a concise freeze-readiness summary with open-issue and blocker counts.

### Changed

- Before the first hardware run (Edge#477): `azazel-edge-selftest` exits 1
  on a critical failure (it always exited 0, and a fast SD card ended it
  early under `set -e` before it wrote its result); Suricata and OpenCanary
  are checked only when enabled. Its SD write test times itself in bash (no
  `/usr/bin/time`) and writes under `/var/lib/azazel-edge/selftest`, not the
  tmpfs `/tmp` (on a tmpfs it is skipped with a warning). `install_all.sh`
  runs it last and fails with it, and now installs its timer
  (`install_selftest_timer.sh`, aarch64), which it never did. `install_ai_runtime.sh` is no longer copied to `/opt/azazel-edge`,
  where it could not run; `install_security_stack.sh` gets the checkout as
  `REPO_ROOT`; the installed `verify_runtime_sync.sh` asks for the checkout
  argument. Operator, AI and vehicle docs now give the HTTPS URL, the token
  file and the post-#471 paths; `docs/CONFIGURATION.md` lists the installer
  settings.

## [0.1.2] - 2026-05-17

### Changed
- Added interactive architecture flow document link to `README.md` and introduced `docs/architecture/azazel_edge_arch.html`.
- Synced benchmark report artifacts in `docs/BENCHMARK_RESULTS.json` and `docs/BENCHMARK_RESULTS.md` after validation rerun.
- Consolidated AI governance charter to a single authoritative `AGENTS.md` (English) and removed `AGENTS_EN.md`.
- Renamed concept profile mapping directory from `configs/profiles/` to `concept_profiles/` and updated documentation references accordingly.

## [0.1.1] - 2026-05-14

### Added
- Protocol-aware redirect policy baseline for prepared decoy services:
  - redirect mapping by destination port
  - unsupported-port deterministic fallback action
  - compatibility fallback to `AZAZEL_DEFENSE_HONEYPOT_PORT` only when policy file is absent
  - fail-safe `notify` fallback when redirect policy is invalid or disabled
  - enforcement metadata for mapping/fallback traceability
- Arsenal demo profile runbook (`docs/ARSENAL_DEMO_PROFILE.md`).
- Deployment profile matrix (`docs/DEPLOYMENT_PROFILES.md`) for constrained hardware clarity.
- Benchmark scope boundary and hardware-in-the-loop plan (`docs/BENCHMARK_SCOPE_AND_HIL_PLAN.md`).
- Benchmark report metadata fields:
  - `benchmark_mode`
  - `hardware`
  - `claim_scope`

### Changed
- README testing/current status wording to avoid stale validation claims.
- Benchmark report wording to identify software-only EVE replay scope.
- SOC policy guide updated with prepared decoy redirect model notes.

## [0.1.0] - 2026-05-13

### Added
- Aggregator MVP scaffold (design-to-implementation bridge):
  - in-memory node registry with registration and summary ingest
  - freshness classification (`fresh` / `stale` / `offline`)
  - protected APIs: `/api/aggregator/nodes/register`, `/api/aggregator/ingest/summary`, `/api/aggregator/nodes`
  - regression tests for registry behavior and API role enforcement
- Multi-node Azazel Aggregator architecture design baseline:
  - node identity/registration model
  - minimal summary schema
  - stale/offline behavior model
  - communication security assumptions
  - phased roadmap (`MVP` / `field-ready` / `extended`)
  - explicit out-of-scope boundaries
- Tamper-evident audit log chaining in `P0AuditLogger` with `chain_prev` and `chain_hash`.
- Audit chain verifier: `P0AuditLogger.verify_chain(path)` to detect tampering.
- CI supply-chain baseline job:
  - CycloneDX SBOM generation (`sbom-runtime.cdx.json`)
  - Dependency vulnerability scan baseline (`pip-audit-runtime.json`)
  - Artifact upload for supply-chain outputs
- Dashboard evidence alert queue aggregation (`now/watch/backlog`) with suppression snapshot and escalation candidate projection.
- Lightweight dashboard trends API (`/api/dashboard/trends`) backed by JSONL time-series points for queue depth, fallback rate, latency EMA, and stale flags.
- Dashboard evidence panel cards for Alert Queues and Trend Snapshot (wired to deterministic evidence and trends APIs).
- Tunable alert-queue thresholds via env vars:
  - `AZAZEL_ALERT_QUEUE_NOW_THRESHOLD`
  - `AZAZEL_ALERT_QUEUE_WATCH_THRESHOLD`
  - `AZAZEL_ALERT_QUEUE_ESCALATE_THRESHOLD`
- Auth hardening baseline:
  - fail-closed role-based API auth (`viewer/operator/responder/admin`)
  - optional mTLS fingerprint enforcement for action-capable endpoints
  - authorization audit log with principal, role, trace_id, requested action, and decision result
- Alert aggregation baseline with suppression window, aggregation window, and escalation count threshold.
- SOC policy baseline:
  - `config/soc_policy.yaml`
  - `AZAZEL_SOC_POLICY_PATH`
  - policy version/hash attached to arbiter decisions
- Rust defense enforcement path baseline for action set:
  - `observe`, `notify`, `throttle`, `redirect`, `isolate`
  - staged enforcement level (`advisory` / `semi-auto` / `full-auto`)
  - structured enforcement outcome with trace_id, selected action, target, command plan, result, and rollback hint
- SOC policy dry-run helper (`bin/azazel-soc-policy-dry-run`) and profile examples (`conservative`, `balanced`, `demo`).
- Dashboard trends expanded with CPU/memory/temperature/interface utilization fields and windowed trend query support.
- ATT&CK evidence enrichment baseline:
  - `config/attack_mapping.yaml` mapping rules with confidence
  - mapped/unmapped handling in SOC evaluator summary (`attack_techniques`)
  - mapping schema validation + mapped/unmapped/conflict tests
- Supply-chain CI baseline completion:
  - lightweight Python static check job (`compileall`)
  - release checksum artifact generation (`release-checksums.sha256`)
  - release verification documentation (`docs/RELEASE_VERIFICATION_GUIDE.md`)
- Notification transport hardening line:
  - Syslog CEF notifier adapter (`SyslogCEFNotifier`)
  - offline queue notifier with recovery flush (`OfflineQueueNotifier`)
  - summary-only transfer mode in `DecisionNotifier`
- Installer/runtime integration line:
  - Vector installer + service/config baseline
  - Wazuh ARM64 installer baseline
  - periodic self-test timer/service and helper script
  - encrypted storage default installer path (`SKIP_LUKS=1` opt-out)
  - captive portal consent page and registration API baseline
- Operations/deployment documentation pack:
  - operator/deployment/legal/maintenance guides
  - docs index and GitHub Pages docs landing refresh
  - implementation cycle feature inventory (`docs/IMPLEMENTATION_CYCLE_2026Q2_FEATURE_INVENTORY.md`)
- Cycle 3 implementation line:
  - aggregator pull-mode polling engine and admin poller control API
  - disaster-context TI IOC feeds with default SOC load path
  - MiniSigma YAML rule packs with default SOC integration
  - Wi-Fi congestion and rogue-AP Evidence Plane dispatch integration
  - TAXII 2.1 outbound push client and admin push/test APIs
  - optional SNMP/NetFlow sensor systemd units + installer wiring
  - captive portal multilingual baseline (`es`, `uk`, `tl`) with safe fallback
  - cycle tracker documentation/index updates (`#242`-`#249`)

### Changed
- Dependency review CI job now runs only when repository variable `ENABLE_DEPENDENCY_REVIEW` is set to `true`.
  - This avoids false CI failures on repositories where Dependency Graph is disabled.
- README refreshed to align with current runtime capabilities and fail-closed posture.
- Local developer runtime execution standardized on `.venv`:
  - new `bin/azazel-edge-dev` helper (`bootstrap`, `test`, `python`)
  - launcher scripts prefer repository `.venv` with `/opt/azazel-edge/venv` fallback
  - development dependency split introduced via `requirements/dev.txt`

## [2026-05-12]

### Added
- Tamper-evident audit chaining baseline in `P0AuditLogger` (`chain_prev`, `chain_hash`) and chain verification helper.
- Supply-chain CI baseline:
  - CycloneDX SBOM artifact generation
  - `pip-audit` dependency vulnerability baseline scan
  - artifact upload for security review workflows

### Changed
- CI dependency-review job is now guarded by repository variable `ENABLE_DEPENDENCY_REVIEW=true` to avoid unsupported-repository failures.

## [2026-05-11]

### Added
- Topo-Lite integration line:
  - Internal network default monitoring scope (`#176`)
  - Synthetic seed mode with live-evidence separation (`#177`)
  - Left-rail integration and single-screen triage UI (`#178`)
- Decision trust capsule output (`#167`).
- Correlation expansion for sequence/distributed patterns (`#168`).
- Dashboard AI governance visibility panel/API (`#169`).
- Notification fallback line with webhook/SMTP and ack audit (`#170`).
- SoT devices dynamic update API (`#166`).
- Baseline CI workflow for Python/Rust (`#162`).
- Runbook schema and approval quality gate tests (`#164`).
- Rust dry-run enforcement planning path (`#165`).
- 2026Q2 indexed execution plan docs (`#160`).

### Fixed
- EPD `--help` percent-format crash (`#161`).

### Changed
- Documentation line:
  - Added MIT license and aligned metadata (`#163`)
  - Consolidated docs to English-only
  - Standardized README badges and banner presentation
  - Synced open-work index and policy-to-implementation mapping (`#171`, `#175`)

## [2026-03-16]

### Fixed
- Stabilized onboarding guide behavior (`#103`).

## [2026-03-15]

### Added
- Client identity closure and documentation line completion (`#102`).

## [2026-03-14]

### Added
- Beginner-default dual audience mode in UI (`#95`).
- Normal Assurance, Primary Anomaly, and Client Identity View (`#94`).
- Live NOC runtime projection integration into control-daemon (`#88`).
- SOC state maturation and dashboard integration (`#86`).

### Changed
- Web UI auth contracts and i18n coverage hardening (`#87`).

## [2026-03-13]

### Added
- Dedicated demo workspace split from live dashboard (`#74`).
- Resource guard and localization refinement (`#75`).
- NOC operational line:
  - blast radius summaries (`#70`)
  - config drift health tracking (`#71`)
  - incident compression summaries (`#72`)
  - runbook workflow support (`#73`)
