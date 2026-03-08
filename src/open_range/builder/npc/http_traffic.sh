#!/usr/bin/env bash
# Level 0 NPC: HTTP traffic generator (curl loop)
#
# Generates benign web traffic to simulate normal user browsing.
# All requests are labeled as NPC traffic in the access log via User-Agent.
#
# Environment variables:
#   WEB_HOST   - hostname of the web server (default: web)
#   RATE_LAMBDA - requests per minute (default: 30)

set -euo pipefail

WEB_HOST="${WEB_HOST:-web}"
RATE_LAMBDA="${RATE_LAMBDA:-30}"

# Calculate sleep interval in seconds
INTERVAL=$(awk "BEGIN {printf \"%.1f\", 60.0 / $RATE_LAMBDA}")

# Common pages and endpoints that a normal user would visit
PAGES=(
    "/"
    "/index.php"
    "/about"
    "/products"
    "/contact"
    "/login"
    "/api/users/1/profile"
    "/search?q=quarterly+report"
    "/search?q=product+catalog"
    "/download?file=report.pdf"
    "/dashboard"
    "/help"
)

# Common form submissions
FORMS=(
    "-d 'username=jsmith&password=Welcome1' http://${WEB_HOST}/login"
    "-d 'q=marketing+materials' http://${WEB_HOST}/search"
    "-d 'name=Janet&email=jsmith@acmecorp.local&message=Hello' http://${WEB_HOST}/contact"
)

echo "[NPC-HTTP] Starting HTTP traffic to ${WEB_HOST} at ${RATE_LAMBDA} req/min"

while true; do
    # 80% GET requests, 20% POST requests
    if (( RANDOM % 5 == 0 )); then
        # POST request (form submission)
        IDX=$(( RANDOM % ${#FORMS[@]} ))
        FORM="${FORMS[$IDX]}"
        curl -s -o /dev/null -w '' \
            -A "NPC-Traffic/1.0 (benign)" \
            -X POST ${FORM} 2>/dev/null || true
    else
        # GET request (page browse)
        IDX=$(( RANDOM % ${#PAGES[@]} ))
        PAGE="${PAGES[$IDX]}"
        curl -s -o /dev/null -w '' \
            -A "NPC-Traffic/1.0 (benign)" \
            "http://${WEB_HOST}${PAGE}" 2>/dev/null || true
    fi

    sleep "${INTERVAL}"
done
