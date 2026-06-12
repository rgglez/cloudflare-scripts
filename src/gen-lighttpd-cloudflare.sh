#!/usr/bin/env bash
set -euo pipefail

SRC="/var/lib/cloudflare/cloudflare-trusted-proxies.lst"
OUT="/etc/lighttpd/conf-available/90-cloudflare-trusted-proxies.conf"

{
    echo "# Generated from $SRC — do not edit"
    echo 'server.modules += ("mod_extforward")'
    echo 'extforward.headers = ("CF-Connecting-IP")'
    printf 'extforward.forwarder = ('
    FIRST=1
    grep -E '^[0-9a-f:.\/]+$' "$SRC" | while IFS= read -r cidr; do
        [ "$FIRST" -eq 1 ] && FIRST=0 || printf ','
        printf '\n    "%s" => "trust"' "$cidr"
    done
    echo
    echo ')'
} > "$OUT"

lighttpd -t -f /etc/lighttpd/lighttpd.conf 2>/dev/null && systemctl reload lighttpd