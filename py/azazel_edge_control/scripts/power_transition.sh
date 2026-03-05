#!/usr/bin/env bash
set -euo pipefail
ACTION="${1:-}"
case "$ACTION" in
  shutdown) exec /bin/systemctl --no-block poweroff ;;
  reboot) exec /bin/systemctl --no-block reboot ;;
  *) echo "Usage: $0 {shutdown|reboot}" >&2; exit 2 ;;
esac
