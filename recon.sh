#!/bin/bash

# =============================================================================
# VDP-PRO SAFE RECON PIPELINE
# Passive enumeration + DNS + HTTP fingerprinting + reporting
#
# AUTHORIZED SECURITY TESTING ONLY
# =============================================================================

set -uo pipefail

export PATH="$HOME/go/bin:$PATH"

# =============================================================================
# TARGET CONFIGURATION
# =============================================================================

DOMAINS=(
   
)

# Optional scope file.
# Leave empty to use DOMAINS and their discovered subdomains.
SCOPE_FILE=""

THREADS=10
RATE_LIMIT=15

RESOLVERS_FILE="/usr/share/wordlists/resolvers.txt"

EXCLUDE_PATTERNS=(
    "staging"
    "dev"
    "internal"
    "test"
    "qa"
)

CUSTOM_OUTDIR=""
MODE=""
TARGET_URL=""

usage() {
    cat <<'USAGE'
Usage:
  ./recon.sh --url http://192.168.21.136/dvwa/
  ./recon.sh --domain example.com
  ./recon.sh --domain example.com --scope scope.txt

Options:
  --url URL             Authorized local/lab HTTP target.
  --domain DOMAIN       Authorized domain/VDP target. May be repeated.
  --scope FILE          Optional domain scope file.
  --outdir DIR          Custom output directory.
  --threads N           Screenshot/HTTP threads.
  --rate N              Rate-limit setting.
  -h, --help            Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)
            [[ $# -ge 2 ]] || { echo "[!] --url requires a value"; exit 2; }
            TARGET_URL="$2"
            MODE="url"
            shift 2
            ;;
        --domain)
            [[ $# -ge 2 ]] || { echo "[!] --domain requires a value"; exit 2; }
            DOMAINS+=("$2")
            MODE="domain"
            shift 2
            ;;
        --scope)
            [[ $# -ge 2 ]] || { echo "[!] --scope requires a file"; exit 2; }
            SCOPE_FILE="$2"
            shift 2
            ;;
        --outdir)
            [[ $# -ge 2 ]] || { echo "[!] --outdir requires a directory"; exit 2; }
            CUSTOM_OUTDIR="$2"
            shift 2
            ;;
        --threads)
            [[ $# -ge 2 ]] || { echo "[!] --threads requires a number"; exit 2; }
            THREADS="$2"
            shift 2
            ;;
        --rate)
            [[ $# -ge 2 ]] || { echo "[!] --rate requires a number"; exit 2; }
            RATE_LIMIT="$2"
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[!] Unknown argument: $1"; usage; exit 2 ;;
    esac
done

if [[ -z "$MODE" ]]; then
    echo "[!] No target supplied."
    usage
    exit 2
fi

if [[ "$MODE" == "url" ]]; then
    if [[ ! "$TARGET_URL" =~ ^https?://[^[:space:]]+$ ]]; then
        echo "[!] Invalid URL: $TARGET_URL"
        echo "    Example: http://192.168.21.136/dvwa/"
        exit 2
    fi
    if (( ${#DOMAINS[@]} > 0 )); then
        echo "[!] Use either --url or --domain, not both."
        exit 2
    fi
fi

if [[ "$MODE" == "domain" && ${#DOMAINS[@]} -eq 0 ]]; then
    echo "[!] No domain supplied."
    exit 2
fi

# =============================================================================
# WARNING
# =============================================================================

cat << 'EOF'

############################################################################
#  WARNING: AUTHORIZED SECURITY TESTING ONLY                              #
#                                                                          #
#  Only run this script against systems for which you have authorization. #
############################################################################

EOF

sleep 1

# =============================================================================
# OUTPUT DIRECTORIES
# =============================================================================

if [[ -n "$CUSTOM_OUTDIR" ]]; then
    OUTDIR="$CUSTOM_OUTDIR"
else
    OUTDIR="vdp_pro_${MODE}_$(date +%Y%m%d_%H%M%S)"
fi

mkdir -p "$OUTDIR"
mkdir -p "$OUTDIR/subenum"
mkdir -p "$OUTDIR/live"
mkdir -p "$OUTDIR/historical"
mkdir -p "$OUTDIR/js"
mkdir -p "$OUTDIR/vulns"
mkdir -p "$OUTDIR/ports"
mkdir -p "$OUTDIR/screenshots"
mkdir -p "$OUTDIR/reports"
mkdir -p "$OUTDIR/cloud"

LOG="$OUTDIR/pipeline.log"

# =============================================================================
# INITIALIZE ALL OUTPUT FILES
# =============================================================================

touch \
    "$OUTDIR/subenum/all_subs_raw.txt" \
    "$OUTDIR/subenum/all_subs.txt" \
    "$OUTDIR/subenum/in_scope_subs.txt" \
    "$OUTDIR/subenum/resolved_subs.txt" \
    "$OUTDIR/subenum/cname_records.txt" \
    "$OUTDIR/subenum/crtsh_subs.txt" \
    "$OUTDIR/live/live_hosts_full.txt" \
    "$OUTDIR/live/live_urls.txt" \
    "$OUTDIR/historical/wayback_urls.txt" \
    "$OUTDIR/historical/otx_urls.txt" \
    "$OUTDIR/historical/all_urls.txt" \
    "$OUTDIR/historical/params.txt" \
    "$OUTDIR/historical/high_value_params.txt" \
    "$OUTDIR/js/js_files.txt" \
    "$OUTDIR/js/js_from_html.txt" \
    "$OUTDIR/js/all_js.txt" \
    "$OUTDIR/js/js_urls_found.txt" \
    "$OUTDIR/js/api_paths.txt" \
    "$OUTDIR/js/secrets_raw.txt" \
    "$OUTDIR/js/firebase_urls.txt" \
    "$OUTDIR/js/internal_paths.txt" \
    "$OUTDIR/cloud/bucket_candidates.txt" \
    "$OUTDIR/cloud/open_buckets.txt" \
    "$OUTDIR/vulns/cors_wildcard.txt" \
    "$OUTDIR/vulns/cors_creds.txt" \
    "$OUTDIR/vulns/missing_headers.txt" \
    "$OUTDIR/vulns/git_exposure.txt" \
    "$OUTDIR/vulns/env_exposure.txt" \
    "$OUTDIR/vulns/takeover_candidates.txt" \
    "$OUTDIR/vulns/nuclei_all.txt" \
    "$OUTDIR/ports/naabu_results.txt" \
    "$OUTDIR/ports/interesting_ports.txt"

# =============================================================================
# LOGGING
# =============================================================================

echo "[*] VDP-PRO Safe Recon Pipeline" | tee "$LOG"
echo "[*] Output: $OUTDIR/" | tee -a "$LOG"
echo "[*] Mode: $MODE" | tee -a "$LOG"
if [[ "$MODE" == "url" ]]; then
    echo "[*] Target URL: $TARGET_URL" | tee -a "$LOG"
else
    echo "[*] Targets: ${DOMAINS[*]}" | tee -a "$LOG"
fi
echo "========================================" | tee -a "$LOG"

log() {
    echo "$(date '+%H:%M:%S') $*" | tee -a "$LOG"
}

check_tool() {
    local tool="$1"

    if command -v "$tool" >/dev/null 2>&1; then
        return 0
    fi

    log "  [!] Tool not found: $tool"
    return 1
}

count_file() {
    local file="$1"

    if [[ -f "$file" ]]; then
        wc -l < "$file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# =============================================================================
# TOOL VERSIONS
# =============================================================================

log ""
log "[*] Checking installed tools..."

for tool in subfinder amass dnsx puredns httpx curl jq dig; do
    if check_tool "$tool"; then
        log "  [+] $tool: available"
    else
        log "  [-] $tool: unavailable"
    fi
done

# =============================================================================
# RESOLVERS
# =============================================================================

if [[ -f "$RESOLVERS_FILE" ]]; then
    RESOLVERS="$RESOLVERS_FILE"
else
    RESOLVERS="$OUTDIR/resolvers.txt"

    cat > "$RESOLVERS" << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
208.67.222.222
208.67.220.220
EOF
fi

log "[*] Resolver file: $RESOLVERS"

# =============================================================================
# EXCLUSION FUNCTION
# =============================================================================

filter_exclusions() {

    local input="$1"
    local output="$2"

    : > "$output"

    [[ ! -f "$input" ]] && return 0

    if [[ ${#EXCLUDE_PATTERNS[@]} -eq 0 ]]; then
        cp "$input" "$output"
        return 0
    fi

    local pattern
    pattern=$(IFS='|'; echo "${EXCLUDE_PATTERNS[*]}")

    grep -viE "$pattern" "$input" > "$output" 2>/dev/null || true
}

# =============================================================================
# STAGE 1
# PASSIVE SUBDOMAIN ENUMERATION
# =============================================================================

log ""
log "[*] Stage 1: Passive subdomain enumeration ..."

for d in "${DOMAINS[@]}"; do

    log "  [-] Enumerating $d ..."

    SUBFINDER_OUT="$OUTDIR/subenum/subfinder_$d.txt"
    AMASS_OUT="$OUTDIR/subenum/amass_$d.txt"
    COMBINED_OUT="$OUTDIR/subenum/combined_$d.txt"

    : > "$SUBFINDER_OUT"
    : > "$AMASS_OUT"
    : > "$COMBINED_OUT"

    # -------------------------------------------------------------------------
    # SUBFINDER
    # -------------------------------------------------------------------------

    if check_tool subfinder; then

        log "      [subfinder] running..."

        if subfinder \
            -d "$d" \
            -all \
            -silent \
            -o "$SUBFINDER_OUT" \
            2>>"$LOG"; then

            SUB_COUNT=$(count_file "$SUBFINDER_OUT")

            log "      [subfinder] completed — $SUB_COUNT results."

        else

            EXIT_CODE=$?

            log "      [!] subfinder failed — exit $EXIT_CODE."

        fi
    fi

    # -------------------------------------------------------------------------
    # AMASS
    # -------------------------------------------------------------------------

    if check_tool amass; then

        log "      [amass] running..."

        if amass enum \
            -passive \
            -d "$d" \
            -o "$AMASS_OUT" \
            2>>"$LOG"; then

            AMASS_COUNT=$(count_file "$AMASS_OUT")

            log "      [amass] completed — $AMASS_COUNT results."

        else

            EXIT_CODE=$?

            log "      [!] amass failed — exit $EXIT_CODE."

        fi
    fi

    # -------------------------------------------------------------------------
    # MERGE
    # -------------------------------------------------------------------------

    {
        cat "$SUBFINDER_OUT" 2>/dev/null || true
        cat "$AMASS_OUT" 2>/dev/null || true
    } |
        sed '/^[[:space:]]*$/d' |
        tr '[:upper:]' '[:lower:]' |
        sort -u > "$COMBINED_OUT"

    COUNT=$(count_file "$COMBINED_OUT")

    log "      [*] $d: $COUNT unique candidates."

done

# =============================================================================
# CRT.SH
# =============================================================================

log "  [-] Querying crt.sh ..."

: > "$OUTDIR/subenum/crtsh_subs.txt"

if check_tool curl && check_tool jq; then

    for d in "${DOMAINS[@]}"; do

        curl -sk \
            --max-time 30 \
            "https://crt.sh/?q=%25.$d&output=json" \
            2>>"$LOG" |
            jq -r '.[].name_value' 2>/dev/null |
            sed 's/\*\.//' |
            tr '[:upper:]' '[:lower:]' |
            sed '/^[[:space:]]*$/d' |
            sort -u >> "$OUTDIR/subenum/crtsh_subs.txt"

    done
fi

sort -u \
    "$OUTDIR/subenum/crtsh_subs.txt" \
    -o "$OUTDIR/subenum/crtsh_subs.txt" 2>/dev/null || true

# =============================================================================
# MERGE ALL SUBDOMAINS
# =============================================================================

{

    for file in "$OUTDIR"/subenum/combined_*.txt; do

        [[ -f "$file" ]] || continue

        cat "$file"

    done

    cat "$OUTDIR/subenum/crtsh_subs.txt"

} |
    sed '/^[[:space:]]*$/d' |
    sort -u > "$OUTDIR/subenum/all_subs_raw.txt"

filter_exclusions \
    "$OUTDIR/subenum/all_subs_raw.txt" \
    "$OUTDIR/subenum/all_subs.txt"

TOTAL_SUBS=$(count_file "$OUTDIR/subenum/all_subs.txt")

log "  [*] $TOTAL_SUBS unique subdomains after filtering."

if [[ "$TOTAL_SUBS" -eq 0 ]]; then
    log "  [!] No passive subdomains discovered."
    log "  [!] Pipeline will continue safely."
fi

# =============================================================================
# SCOPE
# =============================================================================

if [[ -n "${SCOPE_FILE:-}" && -f "$SCOPE_FILE" ]]; then

    log "  [*] Applying scope file: $SCOPE_FILE"

    grep -Fxf \
        "$SCOPE_FILE" \
        "$OUTDIR/subenum/all_subs.txt" \
        > "$OUTDIR/subenum/in_scope_subs.txt" 2>/dev/null || true

    SUBS_FILE="$OUTDIR/subenum/in_scope_subs.txt"

else

    cp \
        "$OUTDIR/subenum/all_subs.txt" \
        "$OUTDIR/subenum/in_scope_subs.txt"

    SUBS_FILE="$OUTDIR/subenum/in_scope_subs.txt"

fi

touch "$SUBS_FILE"

log "  [*] Scope input: $SUBS_FILE"
log "  [*] Scope entries: $(count_file "$SUBS_FILE")"

# =============================================================================
# URL/LAB MODE OVERRIDE
# =============================================================================
# A local DVWA/VM target has no useful subdomain enumeration or public DNS
# workflow. Seed the HTTP stage directly and continue with HTTP/reporting.
if [[ "$MODE" == "url" ]]; then
    log ""
    log "[*] URL/lab mode: skipping passive subdomain enumeration and DNS."
    : > "$OUTDIR/subenum/all_subs_raw.txt"
    : > "$OUTDIR/subenum/all_subs.txt"
    : > "$OUTDIR/subenum/in_scope_subs.txt"
    : > "$OUTDIR/subenum/resolved_subs.txt"
    : > "$OUTDIR/subenum/cname_records.txt"
    : > "$OUTDIR/subenum/crtsh_subs.txt"

    printf '%s\n' "$TARGET_URL" > "$OUTDIR/live/live_urls.txt"
    : > "$OUTDIR/live/live_hosts_full.txt"

    if check_tool httpx; then
        httpx -u "$TARGET_URL" -silent -sc -cl -ct -location -title -web-server -tech-detect -method -follow-redirects -ip \
            -o "$OUTDIR/live/live_hosts_full.txt" 2>>"$LOG" || true
    fi

    if [[ ! -s "$OUTDIR/live/live_hosts_full.txt" ]] && check_tool curl; then
        if curl -skI --max-time 10 "$TARGET_URL" > /dev/null 2>&1; then
            printf '%s\n' "$TARGET_URL" > "$OUTDIR/live/live_urls.txt"
        else
            : > "$OUTDIR/live/live_urls.txt"
            log "  [!] Target did not return an HTTP response."
        fi
    fi

    log "  [*] Local target: $TARGET_URL"
    log "  [*] Live URL entries: $(count_file "$OUTDIR/live/live_urls.txt")"
else
# =============================================================================
# STAGE 2
# DNS RESOLUTION
# =============================================================================

log ""
log "[*] Stage 2: DNS resolution ..."

: > "$OUTDIR/subenum/resolved_subs.txt"

if [[ -s "$SUBS_FILE" ]]; then

    if check_tool puredns; then

        puredns resolve \
            "$SUBS_FILE" \
            -r "$RESOLVERS" \
            -o "$OUTDIR/subenum/resolved_subs.txt" \
            2>>"$LOG" || true

    elif check_tool dnsx; then

        dnsx \
            -l "$SUBS_FILE" \
            -silent \
            -o "$OUTDIR/subenum/resolved_subs.txt" \
            2>>"$LOG" || true

    else

        log "  [!] No DNS resolver tool available."

    fi

fi

sort -u \
    "$OUTDIR/subenum/resolved_subs.txt" \
    -o "$OUTDIR/subenum/resolved_subs.txt" 2>/dev/null || true

RESOLVED=$(count_file "$OUTDIR/subenum/resolved_subs.txt")

log "  [*] $RESOLVED resolved hosts."

# =============================================================================
# CNAME
# =============================================================================

log "  [-] Extracting CNAME records ..."

: > "$OUTDIR/subenum/cname_records.txt"

if [[ -s "$SUBS_FILE" ]] && check_tool dnsx; then

    dnsx \
        -l "$SUBS_FILE" \
        -cname \
        -silent \
        2>>"$LOG" |
        sort -u > "$OUTDIR/subenum/cname_records.txt" || true

fi

log "  [*] $(count_file "$OUTDIR/subenum/cname_records.txt") CNAME records."

fi

# =============================================================================
# STAGE 3
# HTTP LIVENESS
# =============================================================================

log ""
log "[*] Stage 3: HTTP liveness + fingerprinting ..."

if [[ "$MODE" == "domain" ]]; then
    : > "$OUTDIR/live/live_hosts_full.txt"
    : > "$OUTDIR/live/live_urls.txt"
fi

if [[ "$MODE" == "domain" && -s "$OUTDIR/subenum/resolved_subs.txt" ]] && check_tool httpx; then

    httpx \
        -l "$OUTDIR/subenum/resolved_subs.txt" \
        -silent \
        -sc \
        -cl \
        -ct \
        -location \
        -title \
        -web-server \
        -tech-detect \
        -method \
        -follow-redirects \
        -ip \
        -o "$OUTDIR/live/live_hosts_full.txt" \
        2>>"$LOG" || true

    awk '{print $1}' \
        "$OUTDIR/live/live_hosts_full.txt" |
        sed '/^[[:space:]]*$/d' |
        sort -u > "$OUTDIR/live/live_urls.txt"

fi

LIVE=$(count_file "$OUTDIR/live/live_urls.txt")

log "  [*] $LIVE live HTTP(S) hosts."

# =============================================================================
# STAGE 4
# HISTORICAL URL DISCOVERY
# =============================================================================

log ""
log "[*] Stage 4: Passive historical URL discovery ..."

: > "$OUTDIR/historical/wayback_urls.txt"
: > "$OUTDIR/historical/otx_urls.txt"

if [[ "$MODE" == "domain" && -s "$OUTDIR/live/live_urls.txt" ]] && check_tool gau; then

    gau \
        --blacklist png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css \
        < "$OUTDIR/live/live_urls.txt" \
        > "$OUTDIR/historical/wayback_urls.txt" \
        2>>"$LOG" || true

fi

# OTX

if check_tool curl && check_tool jq; then

    for d in "${DOMAINS[@]}"; do

        curl -sk \
            --max-time 20 \
            "https://otx.alienvault.com/api/v1/indicators/domain/$d/url_list?limit=500" \
            2>>"$LOG" |
            jq -r '.url_list[]?.url' \
            2>/dev/null >> "$OUTDIR/historical/otx_urls.txt" || true

    done

fi

sort -u \
    "$OUTDIR/historical/otx_urls.txt" \
    -o "$OUTDIR/historical/otx_urls.txt" 2>/dev/null || true

cat \
    "$OUTDIR/historical/wayback_urls.txt" \
    "$OUTDIR/historical/otx_urls.txt" 2>/dev/null |
    sed '/^[[:space:]]*$/d' |
    sort -u > "$OUTDIR/historical/all_urls.txt"

HIST_COUNT=$(count_file "$OUTDIR/historical/all_urls.txt")

log "  [*] $HIST_COUNT historical URLs."

# =============================================================================
# STAGE 5
# PARAMETER EXTRACTION
# =============================================================================

log ""
log "[*] Stage 5: Parameter extraction ..."

: > "$OUTDIR/historical/params.txt"
: > "$OUTDIR/historical/high_value_params.txt"

if [[ -s "$OUTDIR/historical/all_urls.txt" ]]; then

    grep -oE '[?&][^=& ]+' \
        "$OUTDIR/historical/all_urls.txt" |
        sed 's/^[?&]//' |
        sort -u > "$OUTDIR/historical/params.txt" || true

    grep -Ei \
        '(\?|&)(id=|file=|page=|redirect=|url=|path=|cmd=|exec=|debug=|token=|api[_-]?key|secret=|password=|auth=|session=|upload=|download=|admin=|config=|backup=|db=|sql=)' \
        "$OUTDIR/historical/all_urls.txt" \
        > "$OUTDIR/historical/high_value_params.txt" 2>/dev/null || true

fi

log "  [-] $(count_file "$OUTDIR/historical/params.txt") unique parameters."
log "  [-] $(count_file "$OUTDIR/historical/high_value_params.txt") high-value URLs."

# =============================================================================
# STAGE 6
# JAVASCRIPT DISCOVERY
# =============================================================================

log ""
log "[*] Stage 6: JavaScript analysis ..."

: > "$OUTDIR/js/js_files.txt"
: > "$OUTDIR/js/js_from_html.txt"
: > "$OUTDIR/js/all_js.txt"
: > "$OUTDIR/js/js_urls_found.txt"
: > "$OUTDIR/js/api_paths.txt"
: > "$OUTDIR/js/secrets_raw.txt"
: > "$OUTDIR/js/firebase_urls.txt"
: > "$OUTDIR/js/internal_paths.txt"

grep -Ei \
    '\.js($|\?)' \
    "$OUTDIR/historical/all_urls.txt" \
    > "$OUTDIR/js/js_files.txt" 2>/dev/null || true

if [[ -s "$OUTDIR/live/live_urls.txt" ]] && check_tool httpx; then

    httpx \
        -l "$OUTDIR/live/live_urls.txt" \
        -silent \
        -extract-regex 'https?://[^"[:space:]]+\.js' \
        > "$OUTDIR/js/js_from_html.txt" \
        2>>"$LOG" || true

fi

cat \
    "$OUTDIR/js/js_files.txt" \
    "$OUTDIR/js/js_from_html.txt" 2>/dev/null |
    sort -u > "$OUTDIR/js/all_js.txt"

JS_COUNT=$(count_file "$OUTDIR/js/all_js.txt")

log "  [-] $JS_COUNT JS files discovered."

# =============================================================================
# STAGE 7
# TAKEOVER CANDIDATE IDENTIFICATION
#
# NOTE: This version only identifies candidates from passive CNAME information.
# =============================================================================

log ""
log "[*] Stage 7: Passive takeover candidate identification ..."

grep -Ei \
    '(\.s3\.amazonaws\.com|\.cloudfront\.net|\.herokuapp\.com|\.github\.io|\.surge\.sh|\.netlify\.com|\.pantheonsite\.io)' \
    "$OUTDIR/subenum/cname_records.txt" \
    > "$OUTDIR/vulns/takeover_candidates.txt" 2>/dev/null || true

log "  [-] $(count_file "$OUTDIR/vulns/takeover_candidates.txt") passive candidates."

# =============================================================================
# STAGE 8
# TECHNOLOGY SUMMARY
# =============================================================================

log ""
log "[*] Stage 8: Technology summary ..."

: > "$OUTDIR/live/technology_summary.txt"

if [[ -s "$OUTDIR/live/live_hosts_full.txt" ]]; then

    grep -oiE \
        '(nginx|apache|iis|wordpress|joomla|drupal|laravel|php|node|express|next\.js|nuxt)' \
        "$OUTDIR/live/live_hosts_full.txt" |
        sort |
        uniq -c |
        sort -nr > "$OUTDIR/live/technology_summary.txt" || true

fi

# =============================================================================
# STAGE 9
# SECURITY HEADER INVENTORY
# =============================================================================

log ""
log "[*] Stage 9: Security header inventory ..."

: > "$OUTDIR/vulns/missing_headers.txt"
: > "$OUTDIR/vulns/cors_wildcard.txt"
: > "$OUTDIR/vulns/cors_creds.txt"

if check_tool curl; then

    while IFS= read -r url; do

        [[ -z "$url" ]] && continue

        headers=$(curl \
            -sk \
            -I \
            --max-time 8 \
            "$url" 2>/dev/null || true)

        if echo "$headers" |
            grep -qi '^access-control-allow-origin:[[:space:]]*\*'; then

            echo "$url: CORS wildcard" \
                >> "$OUTDIR/vulns/cors_wildcard.txt"

        fi

        if echo "$headers" |
            grep -qi '^access-control-allow-credentials:[[:space:]]*true'; then

            echo "$url: CORS credentials" \
                >> "$OUTDIR/vulns/cors_creds.txt"

        fi

        if ! echo "$headers" | grep -qi '^strict-transport-security:'; then
            echo "$url: MISSING HSTS" \
                >> "$OUTDIR/vulns/missing_headers.txt"
        fi

        if ! echo "$headers" | grep -qi '^x-content-type-options:'; then
            echo "$url: MISSING X-Content-Type-Options" \
                >> "$OUTDIR/vulns/missing_headers.txt"
        fi

        if ! echo "$headers" | grep -qi '^x-frame-options:' &&
           ! echo "$headers" | grep -qi '^content-security-policy:'; then

            echo "$url: Clickjacking protection not detected" \
                >> "$OUTDIR/vulns/missing_headers.txt"

        fi

        if ! echo "$headers" | grep -qi '^content-security-policy:'; then
            echo "$url: MISSING CSP" \
                >> "$OUTDIR/vulns/missing_headers.txt"
        fi

    done < "$OUTDIR/live/live_urls.txt"

fi

# =============================================================================
# STAGE 10
# PORT INVENTORY
# =============================================================================

log ""
log "[*] Stage 10: Port inventory disabled in safe pipeline."

echo "Active port scanning intentionally disabled." \
    > "$OUTDIR/ports/README.txt"

# =============================================================================
# STAGE 11
# CLOUD CANDIDATE GENERATION
# =============================================================================

log ""
log "[*] Stage 11: Cloud storage candidate generation ..."

: > "$OUTDIR/cloud/bucket_candidates.txt"

if [[ -s "$OUTDIR/subenum/all_subs.txt" ]]; then

    while IFS= read -r sub; do

        prefix="${sub%%.*}"

        [[ -z "$prefix" ]] && continue

        for suffix in \
            assets \
            backup \
            data \
            uploads \
            media \
            storage \
            files \
            static \
            public \
            archive; do

            echo "${prefix}-${suffix}"

        done

    done < "$OUTDIR/subenum/all_subs.txt" |
        sort -u > "$OUTDIR/cloud/bucket_candidates.txt"

fi

log "  [-] $(count_file "$OUTDIR/cloud/bucket_candidates.txt") candidates generated."

# No automatic bucket probing.

echo "Active cloud bucket probing disabled." \
    > "$OUTDIR/cloud/README.txt"

# =============================================================================
# STAGE 12
# ACTIVE VULNERABILITY SCANNING
# =============================================================================

log ""
log "[*] Stage 12: Active vulnerability scanning disabled."

cat > "$OUTDIR/vulns/README.txt" << 'EOF'
Active vulnerability scanning is intentionally disabled in this safe
reconnaissance version.

Use your organization's approved scanner and explicitly authorized target
scope separately.
EOF



# =============================================================================
# STAGE 13: SCREENSHOTS
# =============================================================================
log ""
log "[*] Stage 13: Screenshots ..."

SCREEN_COUNT=0

if check_tool gowitness; then
    if [[ -s "$OUTDIR/live/live_urls.txt" ]]; then
        log "  [-] Running gowitness 3.x screenshot scan..."

        gowitness scan file \
            -f "$OUTDIR/live/live_urls.txt" \
            --screenshot-path "$OUTDIR/screenshots" \
            --screenshot-format png \
            --threads "$THREADS" \
            --timeout 30 \
            --write-none \
            2>>"$LOG" || {
                log "  [!] gowitness returned an error — continuing."
            }

        SCREEN_COUNT=$(find "$OUTDIR/screenshots" \
            -type f \( -iname '*.png' -o -iname '*.jpeg' -o -iname '*.jpg' \) \
            2>/dev/null | wc -l)

        log "  [-] $SCREEN_COUNT screenshots taken."
    else
        log "  [-] No live URLs available — skipping screenshots."
    fi
else
    log "  [!] gowitness not found — skipping screenshots."
fi
# =============================================================================
# STAGE 14
# EXPOSURE CHECKS
# =============================================================================

log ""
log "[*] Stage 14: Exposure checks disabled."

cat > "$OUTDIR/vulns/exposure_checks_README.txt" << 'EOF'
Active .git/.env probing is intentionally disabled.

Review these endpoints only through an approved authorized testing
workflow.
EOF

# =============================================================================
# STAGE 15
# REPORT
# =============================================================================

log ""
log "[*] Stage 15: Generating report ..."

SUMMARY="$OUTDIR/reports/summary.txt"

{
    echo "VDP-PRO SAFE RECONNAISSANCE REPORT"
    echo "========================================"
    echo "Date: $(date)"
    echo "Mode:    $MODE"
    if [[ "$MODE" == "url" ]]; then echo "Target:  $TARGET_URL"; else echo "Targets: ${DOMAINS[*]}"; fi
    echo "Output: $OUTDIR"
    echo ""

    echo "--- SUBDOMAIN ENUMERATION ---"
    echo "Total subdomains:    $(count_file "$OUTDIR/subenum/all_subs.txt")"
    echo "Resolved hosts:      $(count_file "$OUTDIR/subenum/resolved_subs.txt")"
    echo "Live HTTP hosts:     $(count_file "$OUTDIR/live/live_urls.txt")"
    echo "CNAME records:       $(count_file "$OUTDIR/subenum/cname_records.txt")"
    echo ""

    echo "--- HISTORICAL DISCOVERY ---"
    echo "Historical URLs:     $(count_file "$OUTDIR/historical/all_urls.txt")"
    echo "Parameters:          $(count_file "$OUTDIR/historical/params.txt")"
    echo "High-value URLs:     $(count_file "$OUTDIR/historical/high_value_params.txt")"
    echo ""

    echo "--- JAVASCRIPT ---"
    echo "JS files:            $(count_file "$OUTDIR/js/all_js.txt")"
    echo "API paths:           $(count_file "$OUTDIR/js/api_paths.txt")"
    echo "Potential secrets:   $(count_file "$OUTDIR/js/secrets_raw.txt")"
    echo ""

    echo "--- PASSIVE CANDIDATES ---"
    echo "Takeover candidates: $(count_file "$OUTDIR/vulns/takeover_candidates.txt")"
    echo "Cloud candidates:    $(count_file "$OUTDIR/cloud/bucket_candidates.txt")"
    echo ""

    echo "--- SECURITY HEADERS ---"
    echo "CORS wildcard:       $(count_file "$OUTDIR/vulns/cors_wildcard.txt")"
    echo "CORS credentials:    $(count_file "$OUTDIR/vulns/cors_creds.txt")"
    echo "Missing headers:     $(count_file "$OUTDIR/vulns/missing_headers.txt")"
    echo ""

    echo "--- TECHNOLOGY ---"

    if [[ -s "$OUTDIR/live/technology_summary.txt" ]]; then
        cat "$OUTDIR/live/technology_summary.txt"
    else
        echo "No technology data."
    fi

    echo ""

    echo "--- OUTPUT FILES ---"
    echo "Subdomains:          $OUTDIR/subenum/all_subs.txt"
    echo "Resolved:            $OUTDIR/subenum/resolved_subs.txt"
    echo "Live hosts:          $OUTDIR/live/live_hosts_full.txt"
    echo "Historical URLs:     $OUTDIR/historical/all_urls.txt"
    echo "JS files:            $OUTDIR/js/all_js.txt"
    echo "Headers:             $OUTDIR/vulns/missing_headers.txt"
    echo "Takeover candidates: $OUTDIR/vulns/takeover_candidates.txt"
    echo ""

    echo "========================================"
    echo "Active vulnerability scanning: DISABLED"
    echo "Active port scanning:          DISABLED"
    echo "Active cloud probing:          DISABLED"
    echo "Active .git/.env probing:      DISABLED"
    echo "========================================"

} > "$SUMMARY"

cat "$SUMMARY"

log ""
log "[*] Pipeline complete."
log "[*] Report: $SUMMARY"
