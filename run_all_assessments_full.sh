#!/usr/bin/env bash
# run_assessments_core.sh
# Runs only Trivy, Nmap, pip-audit, and Bandit for Flask + Nginx project.

set -euo pipefail

OUTPUT_DIR="assessment_results_$(date +%Y-%m-%d_%H-%M)"
mkdir -p "$OUTPUT_DIR"

# Default container names
FALLBACK_FLASK_CONTAINER="application_2-flask-1"
FALLBACK_NGINX_CONTAINER="application_2-nginx-1"

FLASK_APP_FILE="flask_app.py"

# Colors
RED="$(printf '\033[31m')"
GREEN="$(printf '\033[32m')"
YELLOW="$(printf '\033[33m')"
RESET="$(printf '\033[0m')"

run_and_log() {
  local label="$1"; shift
  echo
  echo "------------------------------------------------------------"
  echo "[$label] $(date --iso-8601=seconds)"
  echo "------------------------------------------------------------" | tee -a "$OUTPUT_DIR/summary.log"
  "$@" 2>&1 | tee "$OUTPUT_DIR/${label// /_}.txt"
  echo "[$label] finished" | tee -a "$OUTPUT_DIR/summary.log"
}

try_and_log() {
  local label="$1"; shift
  echo
  echo "------------------------------------------------------------"
  echo "[$label] $(date --iso-8601=seconds)"
  echo "------------------------------------------------------------" | tee -a "$OUTPUT_DIR/summary.log"
  if "$@" 2>&1 | tee "$OUTPUT_DIR/${label// /_}.txt"; then
    echo "[$label] SUCCESS" | tee -a "$OUTPUT_DIR/summary.log"
  else
    echo "[$label] FAILED (see $OUTPUT_DIR/${label// /_}.txt)" | tee -a "$OUTPUT_DIR/summary.log"
  fi
}

echo "[+] Output directory: $OUTPUT_DIR" | tee -a "$OUTPUT_DIR/summary.log"

# Discover containers
FLASK_CONTAINER="$(docker ps --format '{{.Names}}' | grep -i flask || true)"
NGINX_CONTAINER="$(docker ps --format '{{.Names}}' | grep -i nginx || true)"
FLASK_CONTAINER="${FLASK_CONTAINER:-$FALLBACK_FLASK_CONTAINER}"
NGINX_CONTAINER="${NGINX_CONTAINER:-$FALLBACK_NGINX_CONTAINER}"
echo "Flask container: $FLASK_CONTAINER" | tee -a "$OUTPUT_DIR/summary.log"
echo "Nginx container: $NGINX_CONTAINER" | tee -a "$OUTPUT_DIR/summary.log"

# Resolve images
FLASK_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$FLASK_CONTAINER")"
NGINX_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$NGINX_CONTAINER")"

# ------------------- Trivy Scans -------------------
echo "${YELLOW}[INFO] Running Trivy scans${RESET}" | tee -a "$OUTPUT_DIR/summary.log"
try_and_log "trivy_flask_image_scan" trivy image --format table --severity CRITICAL,HIGH "$FLASK_IMAGE" || true
try_and_log "trivy_nginx_image_scan" trivy image --format table --severity CRITICAL,HIGH "$NGINX_IMAGE" || true

# ------------------- Nmap Scans -------------------
NGINX_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NGINX_CONTAINER")"
echo "${YELLOW}[INFO] Running Nmap scans on $NGINX_IP${RESET}" | tee -a "$OUTPUT_DIR/summary.log"
run_and_log "nmap_basic_${NGINX_IP}" nmap -sV -sC -Pn "$NGINX_IP"
run_and_log "nmap_ssl_enum_${NGINX_IP}" nmap --script ssl-enum-ciphers -p 443 "$NGINX_IP"

# ------------------- Bandit -------------------
echo "${YELLOW}[INFO] Running Bandit (static Python analysis)${RESET}" | tee -a "$OUTPUT_DIR/summary.log"
if [ -f "$FLASK_APP_FILE" ]; then
  try_and_log "bandit_scan" bandit -r "$FLASK_APP_FILE" || true
else
  echo "${RED}[WARN] $FLASK_APP_FILE not found; skipping Bandit${RESET}" | tee -a "$OUTPUT_DIR/summary.log"
fi

# ------------------- pip-audit -------------------
echo "${YELLOW}[INFO] Running pip-audit${RESET}" | tee -a "$OUTPUT_DIR/summary.log"
if command -v pip-audit &>/dev/null; then
  try_and_log "pip_audit" pip-audit || true
else
  echo "${RED}[WARN] pip-audit not installed; review dependencies manually${RESET}" | tee -a "$OUTPUT_DIR/summary.log"
fi

# ------------------- Summary -------------------
echo
echo "====================================================" | tee -a "$OUTPUT_DIR/summary.log"
echo "ASSESSMENT SUMMARY (core tools only)" | tee -a "$OUTPUT_DIR/summary.log"
echo " - Trivy: $OUTPUT_DIR/trivy_flask_image_scan.txt, $OUTPUT_DIR/trivy_nginx_image_scan.txt" | tee -a "$OUTPUT_DIR/summary.log"
echo " - Nmap: $OUTPUT_DIR/nmap_basic_${NGINX_IP}.txt" | tee -a "$OUTPUT_DIR/summary.log"
echo " - Bandit: $OUTPUT_DIR/bandit_scan.txt" | tee -a "$OUTPUT_DIR/summary.log"
echo " - pip-audit: $OUTPUT_DIR/pip_audit.txt" | tee -a "$OUTPUT_DIR/summary.log"
echo "====================================================" | tee -a "$OUTPUT_DIR/summary.log"

echo "${GREEN}DONE. Inspect files in: ${OUTPUT_DIR}${RESET}"
