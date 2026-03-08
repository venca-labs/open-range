#!/usr/bin/env bash
# Level 0 NPC: HTTP traffic generator (curl loop)
#
# Generates benign web traffic to simulate normal user browsing.
# Discovers available pages dynamically from the web server's document
# root so it adapts to any LLM-generated environment.
#
# Environment variables:
#   WEB_HOST   - hostname of the web server (default: web)
#   RATE_LAMBDA - requests per minute (default: 30)

set -euo pipefail

WEB_HOST="${WEB_HOST:-web}"
RATE_LAMBDA="${RATE_LAMBDA:-30}"

INTERVAL=$(awk "BEGIN {printf \"%.1f\", 60.0 / $RATE_LAMBDA}")

# Discover available pages from the web root
discover_pages() {
    local pages=("/")
    # Try common doc roots
    for root in /var/www/html /var/www/portal /var/www; do
        if [ -d "$root" ]; then
            while IFS= read -r f; do
                # Strip doc root to get URL path
                local url_path="${f#$root}"
                [ -n "$url_path" ] && pages+=("$url_path")
            done < <(find "$root" -maxdepth 2 -name '*.php' -o -name '*.html' 2>/dev/null | head -20)
            break
        fi
    done
    # Fallback: probe common endpoints
    if [ ${#pages[@]} -le 1 ]; then
        for p in /index.php /index.html /login.php /dashboard.php; do
            if curl -s -o /dev/null -w '%{http_code}' "http://${WEB_HOST}${p}" 2>/dev/null | grep -q '^[23]'; then
                pages+=("$p")
            fi
        done
    fi
    printf '%s\n' "${pages[@]}"
}

# Build page list once at startup
mapfile -t PAGES < <(discover_pages)
[ ${#PAGES[@]} -eq 0 ] && PAGES=("/")

echo "[NPC-HTTP] Starting HTTP traffic to ${WEB_HOST} at ${RATE_LAMBDA} req/min (${#PAGES[@]} pages)"

while true; do
    IDX=$(( RANDOM % ${#PAGES[@]} ))
    PAGE="${PAGES[$IDX]}"
    curl -s -o /dev/null -w '' \
        -A "NPC-Traffic/1.0 (benign)" \
        "http://${WEB_HOST}${PAGE}" 2>/dev/null || true

    sleep "${INTERVAL}"
done
