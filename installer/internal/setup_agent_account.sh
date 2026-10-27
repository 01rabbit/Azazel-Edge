#!/usr/bin/env bash
# Edge#471 stage 2: run the AI agent (azazel-edge-ai-agent) as the non-root
# account azazel-agent. Idempotent; run as root, with the agent stopped, after
# setup_web_account.sh (stage 1: the azazel-web group must exist).
#
#  1. Accounts: system group azazel-agent and system user azazel-agent (no
#     login, no home, primary group azazel-agent, no other group). An
#     existing name that is not a system account stops the script.
#  2. Directories (tmpfiles.d, /etc/tmpfiles.d/azazel-edge-agent.conf):
#     /run/azazel-edge-agent, /run/azazel-edge-agent-query and
#     /var/log/azazel-edge/ai, 2750 azazel-agent:azazel-web; and
#     /var/lib/azazel-edge-agent (StateDirectory=), 0750 azazel-agent.
#  3. The agent's logs, the core-decision audit chain (+ .1) and the P0 queue
#     move from /var/log/azazel-edge to /var/log/azazel-edge/ai TOGETHER, and
#     the relay's reconcile cursor is carried to the new path
#     (azazel_edge.notify.migrate_audit_path), so the moved chain is not
#     replayed. Nothing is overwritten: if any of the three already exists at
#     the new place, none is moved and a notice is printed. If the two
#     directories are on different filesystems, nothing is moved either and
#     the notice gives the manual steps.
#  4. The decision log and the current runtime files are copied once (the
#     originals are kept).
#  5. /etc/default/azazel-edge-security and /etc/default/azazel-edge-web: a
#     path variable that still holds its old default moves to the new one;
#     any other value is kept and reported.
#
# Nothing here grants a capability, a sudo or polkit rule, or a group.
set -euo pipefail

AGENT_USER="azazel-agent"
AGENT_GROUP="azazel-agent"
WEB_GROUP="azazel-web"
SECURITY_ENV="/etc/default/azazel-edge-security"
WEB_ENV="/etc/default/azazel-edge-web"
OLD_LOG_DIR="/var/log/azazel-edge"
NEW_LOG_DIR="/var/log/azazel-edge/ai"
NEW_RUN_DIR="/run/azazel-edge-agent"
STATE_DIR="/var/lib/azazel-edge-agent"
OLD_DECISION_DIR="/opt/azazel-edge/logs/tactics_engine"
TMPFILES_CONF="/etc/tmpfiles.d/azazel-edge-agent.conf"
PYTHON="/opt/azazel-edge/venv/bin/python"
PY_ROOT="/opt/azazel-edge/py"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

say() { echo "[agent-account] $*"; }
die() { echo "[agent-account] ERROR: $*" >&2; exit 1; }

login_defs() {
  local key="$1" default="$2" value=""
  if [[ -r /etc/login.defs ]]; then
    value="$(awk -v k="$key" '$1 == k { v = $2 } END { print v }' /etc/login.defs)"
  fi
  if [[ "$value" =~ ^[0-9]+$ ]]; then echo "$value"; else echo "$default"; fi
}
SYS_UID_MAX="$(login_defs SYS_UID_MAX 999)"
SYS_GID_MAX="$(login_defs SYS_GID_MAX 999)"

echo "[agent-account] 1/5 accounts"
getent group "$WEB_GROUP" >/dev/null || die "group $WEB_GROUP does not exist; run setup_web_account.sh (stage 1) first"
if gid="$(getent group "$AGENT_GROUP" | cut -d: -f3)" && [[ -n "$gid" ]]; then
  if (( gid == 0 || gid > SYS_GID_MAX )); then
    die "group $AGENT_GROUP already exists with gid $gid, which is not a system group; resolve this by hand"
  fi
  say "group $AGENT_GROUP exists (gid $gid)"
else
  groupadd --system "$AGENT_GROUP"
  say "created group $AGENT_GROUP"
fi
want_gid="$(getent group "$AGENT_GROUP" | cut -d: -f3)"
if entry="$(getent passwd "$AGENT_USER")" && [[ -n "$entry" ]]; then
  uid="$(cut -d: -f3 <<<"$entry")"; pgid="$(cut -d: -f4 <<<"$entry")"
  if (( uid == 0 || uid > SYS_UID_MAX )); then
    die "user $AGENT_USER already exists with uid $uid, which is not a system account; resolve this by hand"
  fi
  [[ "$pgid" == "$want_gid" ]] || die "user $AGENT_USER exists with primary group $pgid, not $AGENT_GROUP; resolve this by hand"
  say "user $AGENT_USER exists (uid $uid)"
else
  shell="/usr/sbin/nologin"; [[ -x "$shell" ]] || shell="/bin/false"
  useradd --system --gid "$AGENT_GROUP" --no-create-home --home-dir /nonexistent --shell "$shell" "$AGENT_USER"
  say "created user $AGENT_USER"
fi
extra_groups="$(id -nG "$AGENT_USER" | tr ' ' '\n' | grep -vx "$AGENT_GROUP" || true)"
[[ -z "$extra_groups" ]] || say "NOTICE: $AGENT_USER is also in: $(echo $extra_groups) (not added by this script)"

echo "[agent-account] 2/5 directories"
[[ -f "$TMPFILES_CONF" ]] || die "$TMPFILES_CONF is missing (installed by install_migrated_tools.sh)"
if command -v systemd-tmpfiles >/dev/null 2>&1; then
  systemd-tmpfiles --create "$TMPFILES_CONF"
else
  install -d -o "$AGENT_USER" -g "$WEB_GROUP" -m 2750 "$NEW_RUN_DIR" /run/azazel-edge-agent-query "$NEW_LOG_DIR"
fi
install -d -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0750 "$STATE_DIR" "$STATE_DIR/decisions"

echo "[agent-account] 3/5 logs, the core-decision audit chain and the P0 queue"
move_once() {
  local src="$1" dst="$2"
  [[ -f "$src" && ! -L "$src" ]] || return 0
  if [[ -e "$dst" || -L "$dst" ]]; then
    say "NOTICE: keep $dst (already present); $src is left where it is"
    return 0
  fi
  mv -n -- "$src" "$dst"
  say "moved $src -> $dst"
}
# The chain (+ its rotated file and its Azazel-Fabric sidecar) and the P0
# queue move as one set and the relay's cursor is carried
# (azazel_edge.notify.migrate_audit_path.migrate_chain). Safe to run again
# after a crash at any point: it finishes a partial move. It never overwrites
# a file at the new place, and moves nothing when AZAZEL_AI_AUDIT_LOG is set
# to a custom path (the agent keeps its chain beside that file).
env_value() {
  local file="$1" var="$2" line
  line="$(grep -E "^${var}=" "$file" 2>/dev/null | tail -n 1 || true)"
  line="${line#*=}"; line="${line%\"}"; line="${line#\"}"; line="${line%\'}"; line="${line#\'}"
  printf '%s' "$line"
}
AUDIT_SETTING="$(env_value "$SECURITY_ENV" AZAZEL_AI_AUDIT_LOG)"
# What the installer says for migrate_chain's exit code and JSON line.
report_chain_result() {
  local rc="$1" out="$2"
  local carry_cmd="$PYTHON -I -c 'import sys; sys.path.insert(0, \"$PY_ROOT\"); from azazel_edge.notify.migrate_audit_path import carry_cursor; print(carry_cursor(*sys.argv[1:]))' <new queue> <old chain path> <new chain path>"
  case "$rc" in
    0) say "audit chain and P0 queue: in $NEW_LOG_DIR, relay cursor carried (or nothing to carry)" ;;
    2)
      if [[ "$out" == *'"state": "cross_filesystem"'* ]]; then
        say "NOTICE: the audit chain and the P0 queue were NOT moved: $OLD_LOG_DIR and $NEW_LOG_DIR are on different filesystems (link() failed with EXDEV). Nothing was copied, overwritten or deleted; every file is still in $OLD_LOG_DIR. To finish by hand: stop the agent; copy core-decision-audit.jsonl, core-decision-audit.jsonl.1, core-decision-audit.fabric.jsonl and p0-alert-queue.jsonl (those present) with 'cp -p -n' from $OLD_LOG_DIR to $NEW_LOG_DIR; compare each copy with its original ('cmp'); only then delete the originals; then run this script again (it finds the set in $NEW_LOG_DIR, carries the relay cursor and sets owners and modes). Or put both directories on one filesystem and run this script again."
      else
        say "NOTICE: the audit chain and the P0 queue were NOT moved (see the line above: a name in both places, a non-regular file, or a custom AZAZEL_AI_AUDIT_LOG). Nothing was overwritten. To finish by hand: stop the agent, move core-decision-audit.jsonl(.1, .fabric.jsonl) and p0-alert-queue.jsonl together beside the AI audit log the agent uses, then run: $carry_cmd"
      fi
      ;;
    *) say "WARNING: the P0 relay cursor was not carried; the next start reconciles the chain as fresh_chain (past decisions it does not find in the queue are alerted as past decisions)" ;;
  esac
}
# Isolated interpreter (no environment, no user site, no cwd on the path);
# only the installed code is imported.
set +e
chain_out="$(cd / && "$PYTHON" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from azazel_edge.notify.migrate_audit_path import main; sys.exit(main(sys.argv[2:]))' \
    "$PY_ROOT" --old-dir "$OLD_LOG_DIR" --new-dir "$NEW_LOG_DIR" --audit-log-setting "$AUDIT_SETTING")"
chain_rc=$?
set -e
[[ -z "$chain_out" ]] || printf '%s\n' "$chain_out"
report_chain_result "$chain_rc" "$chain_out"
# Each AI log moves only when its variable is unset or holds a default (a
# custom value means the agent writes elsewhere).
move_log_if_default() {
  local var="$1" base="$2" name="$3" value
  value="$(env_value "$SECURITY_ENV" "$var")"
  if [[ -n "$value" && "$value" != "$OLD_LOG_DIR/$base" && "$value" != "$NEW_LOG_DIR/$base" ]]; then
    say "NOTICE: $var is set to $value; $OLD_LOG_DIR/$name is not moved"
    return 0
  fi
  move_once "$OLD_LOG_DIR/$name" "$NEW_LOG_DIR/$name"
}
move_log_if_default AZAZEL_AI_EVENT_LOG ai-events.jsonl ai-events.jsonl
move_log_if_default AZAZEL_AI_LLM_LOG ai-llm.jsonl ai-llm.jsonl
move_log_if_default AZAZEL_AI_DEFERRED_LOG ai-deferred.jsonl ai-deferred.jsonl
for name in ai-audit.jsonl ai-audit.jsonl.1 ai-audit.fabric.jsonl; do
  move_log_if_default AZAZEL_AI_AUDIT_LOG ai-audit.jsonl "$name"
done
# The moved files belong to the agent; the Web UI reads through the group.
find "$NEW_LOG_DIR" -xdev -type f ! -name 'p0-alert-queue.jsonl*' -exec chown -h "$AGENT_USER:$WEB_GROUP" {} + -exec chmod 0640 {} +
find "$NEW_LOG_DIR" -xdev -type f -name 'p0-alert-queue.jsonl*' -exec chown -h "$AGENT_USER:$WEB_GROUP" {} + -exec chmod 0600 {} +

echo "[agent-account] 4/5 decision log and runtime files (copied, originals kept)"
copy_once() {
  local src="$1" dst="$2" owner="$3" mode="$4"
  [[ -f "$src" && ! -L "$src" ]] || return 0
  # Never through a symlink (a dangling one included) or over anything.
  if [[ -e "$dst" || -L "$dst" ]]; then
    say "keep $dst (already present or a symlink; not written)"
    return 0
  fi
  cp -P -p -- "$src" "$dst"
  chown -h "$owner" -- "$dst"
  chmod "$mode" -- "$dst"
  say "copied $src -> $dst"
}
copy_once "$OLD_DECISION_DIR/decision_explanations.jsonl" "$STATE_DIR/decisions/decision_explanations.jsonl" "$AGENT_USER:$AGENT_GROUP" 0640
for name in ai_advisory.json ai_metrics.json ai_runtime_policy.json; do
  copy_once "/run/azazel-edge/$name" "$NEW_RUN_DIR/$name" "$AGENT_USER:$WEB_GROUP" 0640
done

echo "[agent-account] 5/5 environment files"
rewrite_old_default() {
  local file="$1" var="$2" old_re="$3" new="$4"
  sed -i -E "s#^${var}=([\"']?)${old_re}([\"']?)\$#${var}=\\1${new}\\2#" "$file"
}
report_other_value() {
  local file="$1" var="$2" new="$3" line value
  line="$(grep -E "^${var}=" "$file" | tail -n 1 || true)"
  [[ -n "$line" ]] || return 0
  value="${line#*=}"; value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
  [[ "$value" == "$new" ]] || say "NOTICE: $file keeps $var=$value (not the old default, left as set); expected $new"
}
touch "$SECURITY_ENV" "$WEB_ENV"
for env_file in "$SECURITY_ENV" "$WEB_ENV"; do
  while IFS='|' read -r var old_re new; do
    [[ -n "$var" ]] || continue
    rewrite_old_default "$env_file" "$var" "$old_re" "$new"
    report_other_value "$env_file" "$var" "$new"
  done <<'EOF'
AZAZEL_AI_ADVISORY|/run/azazel-edge/ai_advisory\.json|/run/azazel-edge-agent/ai_advisory.json
AZAZEL_AI_METRICS|/run/azazel-edge/ai_metrics\.json|/run/azazel-edge-agent/ai_metrics.json
AZAZEL_AI_POLICY|/run/azazel-edge/ai_runtime_policy\.json|/run/azazel-edge-agent/ai_runtime_policy.json
AZAZEL_AI_EVENT_LOG|/var/log/azazel-edge/ai-events\.jsonl|/var/log/azazel-edge/ai/ai-events.jsonl
AZAZEL_AI_LLM_LOG|/var/log/azazel-edge/ai-llm\.jsonl|/var/log/azazel-edge/ai/ai-llm.jsonl
AZAZEL_AI_DEFERRED_LOG|/var/log/azazel-edge/ai-deferred\.jsonl|/var/log/azazel-edge/ai/ai-deferred.jsonl
AZAZEL_AI_AUDIT_LOG|/var/log/azazel-edge/ai-audit\.jsonl|/var/log/azazel-edge/ai/ai-audit.jsonl
AZAZEL_DECISION_LOG_DIR|/opt/azazel-edge/logs/tactics_engine|/var/lib/azazel-edge-agent/decisions
AZAZEL_DECISION_EXPLANATIONS_PATH|/var/log/azazel-edge/decision-explanations\.jsonl|/var/log/azazel-edge/ai/decision-explanations.jsonl
EOF
done
# v2 decision explanations (Edge#477): the agent writes them in $NEW_LOG_DIR;
# the Web UI and audit_review read them there. No service wrote the old file,
# so one there came from a manual run: kept as it is, not moved and not read.
if [[ -e "$OLD_LOG_DIR/decision-explanations.jsonl" || -L "$OLD_LOG_DIR/decision-explanations.jsonl" ]]; then
  say "NOTICE: $OLD_LOG_DIR/decision-explanations.jsonl is kept and no longer read (the agent writes $NEW_LOG_DIR/decision-explanations.jsonl); review it with: azazel-edge-audit-review --explanations-path $OLD_LOG_DIR/decision-explanations.jsonl"
fi
if grep -q '^AZAZEL_UI_SNAPSHOT=' "$SECURITY_ENV"; then
  say "NOTICE: $SECURITY_ENV sets AZAZEL_UI_SNAPSHOT; it is the control daemon's shared snapshot, the agent no longer writes it"
fi

say "done. Wazuh file-integrity monitoring will report the moved files once."
