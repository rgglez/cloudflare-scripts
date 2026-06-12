#!/usr/bin/env bash
set -euo pipefail

SRC="/var/lib/cloudflare/cloudflare-trusted-proxies.lst"
OUT="/etc/nginx/snippets/cloudflare-trusted-proxies.conf"

{
    echo "# Generated from $SRC — do not edit"
    grep -E '^[0-9a-f:.\/]+$' "$SRC" | while IFS= read -r cidr; do
        echo "set_real_ip_from $cidr;"
    done
    echo "real_ip_header CF-Connecting-IP;"
} > "$OUT"

nginx -t 2>/dev/null && systemctl reload nginx