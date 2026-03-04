#!/usr/bin/env bash
set -euo pipefail
mkdir -p /run/azazel-edge
printf '{"ts":%s,"action":"refresh"}\n' "$(date +%s)" >> /run/azazel-edge/action_requests.log
echo "Refresh requested"
