#!/usr/bin/env bash
set -euo pipefail

RAW="/var/lib/cloudflare/cloudflare-trusted-proxies.lst"
TMP="$(mktemp)"

cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

mkdir -p "$(dirname "$RAW")"

{
    echo "# Cloudflare trusted proxies"
    echo "# Generated on $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo
    curl -fsSL https://www.cloudflare.com/ips-v4
    echo
    curl -fsSL https://www.cloudflare.com/ips-v6
} > "$TMP"

LINES=$(grep -cE '^[0-9a-f:.\/]+$' "$TMP" || true)
if [ "$LINES" -lt 5 ]; then
    echo "ERROR: only $LINES ranges obtained. Aborting." >&2
    exit 1
fi

if cmp -s "$TMP" "$RAW" 2>/dev/null; then
    echo "No changes."
    exit 0
fi

mv "$TMP" "$RAW"
chmod 644 "$RAW"
echo "List updated ($LINES ranges)."