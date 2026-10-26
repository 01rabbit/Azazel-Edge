#!/usr/bin/env bash
# Edge#471 stage 1: run the Web UI (azazel-edge-web) as the non-root account
# azazel-web. Idempotent; run as root, with the Web UI stopped.
#
#  1. Accounts: system group azazel-web, system user azazel-web (no login,
#     no home), system group azazel-control (may connect to control.sock),
#     azazel-web is a member of azazel-control and of nothing else. An
#     existing name that is not a system account stops the script.
#  2. /etc/default/azazel-edge-security: the old installer defaults
#     AZAZEL_RUNTIME_SOCKET_GROUP= (empty) and AZAZEL_RUNTIME_DIR_MODE=0770
#     become azazel-control and 0750. Any other value is left as it is and a
#     notice is printed. AZAZEL_UP_IF set only for the Web UI is copied to
#     the control daemon (it now performs the uplink disconnect).
#  3. /etc/default/azazel-edge-web: a path variable that still holds its old
#     default (a shared directory the Web UI can no longer write, or
#     ai-bridge.sock it can no longer reach) is moved to the new default. Any
#     other value is left and reported.
#  4. The Web UI's own directories and a one-time copy of its existing state
#     and logs into them (the originals are kept, for history and rollback).
#  5. Token files the Web UI reads: 0640 root:azazel-web.
#
# Nothing here grants a capability, a sudo rule, a polkit rule or the docker
# group.
set -euo pipefail

WEB_USER="azazel-web"
WEB_GROUP="azazel-web"
CONTROL_GROUP="azazel-control"
SECURITY_ENV="/etc/default/azazel-edge-security"
WEB_ENV="/etc/default/azazel-edge-web"
WEB_RUN_DIR="/run/azazel-edge-web"
WEB_LOG_DIR="/var/log/azazel-edge-web"
WEB_STATE_DIR="/var/lib/azazel-edge-web"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

say() { echo "[web-account] $*"; }
die() { echo "[web-account] ERROR: $*" >&2; exit 1; }

login_defs() {
  local key="$1" default="$2" value=""
  if [[ -r /etc/login.defs ]]; then
    value="$(awk -v k="$key" '$1 == k { v = $2 } END { print v }' /etc/login.defs)"
  fi
  if [[ "$value" =~ ^[0-9]+$ ]]; then echo "$value"; else echo "$default"; fi
}
SYS_UID_MAX="$(login_defs SYS_UID_MAX 999)"
SYS_GID_MAX="$(login_defs SYS_GID_MAX 999)"

ensure_system_group() {
  local name="$1" gid
  if gid="$(getent group "$name" | cut -d: -f3)" && [[ -n "$gid" ]]; then
    if (( gid == 0 || gid > SYS_GID_MAX )); then
      die "group $name already exists with gid $gid, which is not a system group; resolve this by hand"
    fi
    say "group $name exists (gid $gid)"
  else
    groupadd --system "$name"
    say "created group $name"
  fi
}

ensure_web_user() {
  local entry uid gid want_gid shell
  want_gid="$(getent group "$WEB_GROUP" | cut -d: -f3)"
  if entry="$(getent passwd "$WEB_USER")" && [[ -n "$entry" ]]; then
    uid="$(cut -d: -f3 <<<"$entry")"
    gid="$(cut -d: -f4 <<<"$entry")"
    if (( uid == 0 || uid > SYS_UID_MAX )); then
      die "user $WEB_USER already exists with uid $uid, which is not a system account; resolve this by hand"
    fi
    if [[ "$gid" != "$want_gid" ]]; then
      die "user $WEB_USER exists with primary group $gid, not $WEB_GROUP ($want_gid); resolve this by hand"
    fi
    say "user $WEB_USER exists (uid $uid)"
  else
    shell="/usr/sbin/nologin"
    [[ -x "$shell" ]] || shell="/bin/false"
    useradd --system --gid "$WEB_GROUP" --no-create-home --home-dir /nonexistent --shell "$shell" "$WEB_USER"
    say "created user $WEB_USER"
  fi
  if ! id -nG "$WEB_USER" | tr ' ' '\n' | grep -qx "$CONTROL_GROUP"; then
    usermod -a -G "$CONTROL_GROUP" "$WEB_USER"
    say "added $WEB_USER to $CONTROL_GROUP"
  fi
}

# Replace VAR's value in FILE only when it is exactly OLD (optionally quoted).
rewrite_old_default() {
  local file="$1" var="$2" old_re="$3" new="$4"
  sed -i -E "s#^${var}=([\"']?)${old_re}([\"']?)\$#${var}=\\1${new}\\2#" "$file"
}

# Report a VAR in FILE that does not hold NEW after the rewrite.
report_other_value() {
  local file="$1" var="$2" new="$3" line value
  line="$(grep -E "^${var}=" "$file" | tail -n 1 || true)"
  [[ -n "$line" ]] || return 0
  value="${line#*=}"
  value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
  if [[ "$value" != "$new" ]]; then
    say "NOTICE: $file keeps $var=$value (not the old default, left as set); expected $new"
  fi
}

echo "[web-account] 1/5 accounts"
ensure_system_group "$WEB_GROUP"
ensure_system_group "$CONTROL_GROUP"
ensure_web_user

echo "[web-account] 2/5 $SECURITY_ENV"
touch "$SECURITY_ENV"
rewrite_old_default "$SECURITY_ENV" AZAZEL_RUNTIME_SOCKET_GROUP "" "$CONTROL_GROUP"
rewrite_old_default "$SECURITY_ENV" AZAZEL_RUNTIME_DIR_MODE "0770" "0750"
grep -q '^AZAZEL_RUNTIME_SOCKET_GROUP=' "$SECURITY_ENV" || echo "AZAZEL_RUNTIME_SOCKET_GROUP=$CONTROL_GROUP" >> "$SECURITY_ENV"
grep -q '^AZAZEL_RUNTIME_DIR_MODE=' "$SECURITY_ENV" || echo "AZAZEL_RUNTIME_DIR_MODE=0750" >> "$SECURITY_ENV"
report_other_value "$SECURITY_ENV" AZAZEL_RUNTIME_SOCKET_GROUP "$CONTROL_GROUP"
report_other_value "$SECURITY_ENV" AZAZEL_RUNTIME_DIR_MODE "0750"
touch "$WEB_ENV"
if grep -q '^AZAZEL_UP_IF=' "$WEB_ENV" && ! grep -q '^AZAZEL_UP_IF=' "$SECURITY_ENV"; then
  grep '^AZAZEL_UP_IF=' "$WEB_ENV" | tail -n 1 >> "$SECURITY_ENV"
  say "copied AZAZEL_UP_IF from $WEB_ENV to $SECURITY_ENV (the control daemon now disconnects the uplink)"
fi

echo "[web-account] 3/5 $WEB_ENV"
# variable | old default (regex) | new default
while IFS='|' read -r var old_re new; do
  [[ -n "$var" ]] || continue
  rewrite_old_default "$WEB_ENV" "$var" "$old_re" "$new"
  report_other_value "$WEB_ENV" "$var" "$new"
done <<'EOF'
AZAZEL_TRIAGE_SESSION_DIR|/run/azazel-edge/triage-sessions|/run/azazel-edge-web/triage-sessions
AZAZEL_OPERATOR_PROGRESS_PATH|/run/azazel-edge/operator-progress\.json|/run/azazel-edge-web/operator-progress.json
AZAZEL_TOPOLITE_SEED_MODE_PATH|/run/azazel-edge/topolite_seed_mode\.json|/run/azazel-edge-web/topolite_seed_mode.json
AZAZEL_DASHBOARD_TRENDS_PATH|/run/azazel-edge/dashboard-trends\.jsonl|/run/azazel-edge-web/dashboard-trends.jsonl
AZAZEL_TRIAGE_AUDIT_PATH|/var/log/azazel-edge/triage-audit\.jsonl|/var/log/azazel-edge-web/triage-audit.jsonl
AZAZEL_AUTHZ_AUDIT_LOG|/var/log/azazel-edge/authz-events\.jsonl|/var/log/azazel-edge-web/authz-events.jsonl
AZAZEL_RUNBOOK_EVENT_LOG|/var/log/azazel-edge/runbook-events\.jsonl|/var/log/azazel-edge-web/runbook-events.jsonl
AZAZEL_AGGREGATOR_AUDIT_LOG|/var/log/azazel-edge/aggregator-events\.jsonl|/var/log/azazel-edge-web/aggregator-events.jsonl
AZAZEL_CAPTIVE_REGISTRY_PATH|/var/lib/azazel-edge/captive-allowlist\.json|/var/lib/azazel-edge-web/captive-allowlist.json
EOF
# The Web UI asks the agent on its query socket. AZAZEL_AI_SOCKET in the Web
# UI's own file moves there only from an old ai-bridge.sock default (before
# or after #472). The same name in $SECURITY_ENV is the agent's and the
# core's ai-bridge.sock and is never touched here.
QUERY_SOCKET="/run/azazel-edge-agent-query/agent-query.sock"
rewrite_old_default "$WEB_ENV" AZAZEL_AI_SOCKET '/run/azazel-edge/ai-bridge\.sock' "$QUERY_SOCKET"
rewrite_old_default "$WEB_ENV" AZAZEL_AI_SOCKET '/run/azazel-edge-ai/ai-bridge\.sock' "$QUERY_SOCKET"
report_other_value "$WEB_ENV" AZAZEL_AI_SOCKET "$QUERY_SOCKET"
if grep -Eq "^AZAZEL_AI_SOCKET=[\"']?${QUERY_SOCKET}" "$SECURITY_ENV"; then
  say "WARNING: $SECURITY_ENV points AZAZEL_AI_SOCKET at the query socket; that file is read by the agent and the core, which need ai-bridge.sock. Fix it by hand."
fi

echo "[web-account] 4/5 directories and existing state"
install -d -o "$WEB_USER" -g "$WEB_GROUP" -m 0750 "$WEB_RUN_DIR" "$WEB_LOG_DIR" "$WEB_STATE_DIR"
copy_once() {
  local src="$1" dst="$2"
  [[ -e "$src" && ! -L "$src" ]] || return 0
  if [[ -e "$dst" ]]; then
    say "keep $dst (already present; $src not copied)"
    return 0
  fi
  cp -a -- "$src" "$dst"
  chown -R "$WEB_USER:$WEB_GROUP" -- "$dst"
  if [[ -d "$dst" ]]; then
    find "$dst" -type d -exec chmod 0750 {} + ; find "$dst" -type f -exec chmod 0640 {} +
  else
    chmod 0640 -- "$dst"
  fi
  say "copied $src -> $dst (the original is kept)"
}
copy_once /var/lib/azazel-edge/captive-allowlist.json "$WEB_STATE_DIR/captive-allowlist.json"
for name in authz-events.jsonl runbook-events.jsonl aggregator-events.jsonl triage-audit.jsonl triage-audit.jsonl.1; do
  copy_once "/var/log/azazel-edge/$name" "$WEB_LOG_DIR/$name"
done
for name in operator-progress.json topolite_seed_mode.json dashboard-trends.jsonl triage-sessions; do
  copy_once "/run/azazel-edge/$name" "$WEB_RUN_DIR/$name"
done

echo "[web-account] 5/5 token files"
# /etc/azazel-edge stays searchable (0755); each secret carries its own mode.
if [[ -d /etc/azazel-edge ]]; then
  chmod 0755 /etc/azazel-edge
fi
token_files=(
  /etc/azazel-edge/web_token.txt
  /etc/azazel-edge/auth_tokens.json
  /etc/azazel-edge/client-cert-fingerprints.txt
  /etc/azazel-edge/mattermost-command-token
  /etc/azazel-edge/ntfy.token
  /etc/azazel/ntfy.token
)
configured_token="$(grep -E '^AZAZEL_WEB_TOKEN_FILE=' "$WEB_ENV" | tail -n 1 | cut -d= -f2- | tr -d "\"'" || true)"
[[ -z "$configured_token" ]] || token_files+=("$configured_token")
shopt -s nullglob
token_files+=(/etc/azazel-edge/mattermost-command-token.*)
shopt -u nullglob
for f in "${token_files[@]}"; do
  if [[ -f "$f" && ! -L "$f" ]]; then
    chown root:"$WEB_GROUP" -- "$f"
    chmod 0640 -- "$f"
    say "$f -> 0640 root:$WEB_GROUP"
  fi
done

say "done. Wazuh file-integrity monitoring will report these ownership changes once."
