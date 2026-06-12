#!/usr/bin/env bash
set -euo pipefail

SRC="/var/lib/cloudflare/cloudflare-trusted-proxies.lst"

if [ ! -f "$SRC" ]; then
    echo "ERROR: $SRC does not exist. Run update-cloudflare-proxies.sh first." >&2
    exit 1
fi

CIDRS=$(grep -E '^[0-9a-f:.\/]+$' "$SRC")

if [ -z "$CIDRS" ]; then
    echo "ERROR: no CIDRs found in $SRC." >&2
    exit 1
fi

# Remove previous Cloudflare rules on ports 80 and 443
ufw status numbered | grep -E '80,443' | grep -oP '^\[\s*\K[0-9]+' | sort -rn | while read -r num; do
    yes | ufw delete "$num"
done

# Add updated rules
while IFS= read -r cidr; do
    ufw allow from "$cidr" to any port 80,443 proto tcp
done <<< "$CIDRS"

ufw reload
echo "ufw updated with $(echo "$CIDRS" | wc -l) ranges."