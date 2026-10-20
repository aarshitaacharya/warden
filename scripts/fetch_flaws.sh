#!/usr/bin/env bash
# Download the public flaws.cloud CloudTrail dataset (~250 MB) into data/raw/flaws/.
set -euo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)/data/raw/flaws"
mkdir -p "$dir"
[ -f "$dir/flaws_cloudtrail_logs.tar" ] || curl -fL -o "$dir/flaws_cloudtrail_logs.tar" https://summitroute.com/downloads/flaws_cloudtrail_logs.tar
[ -d "$dir/extracted" ] || { mkdir -p "$dir/extracted" && tar -xf "$dir/flaws_cloudtrail_logs.tar" -C "$dir/extracted"; }
echo "ready: $dir/extracted"
