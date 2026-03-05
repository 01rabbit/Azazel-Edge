#!/usr/bin/env bash
set -euo pipefail
mkdir -p /run/azazel-edge
printf '{"ts":%s,"action":"contain"}\n' "$(date +%s)" >> /run/azazel-edge/action_requests.log
echo "Contain requested"
