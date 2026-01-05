#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo " START AWS ISO 27001 AUDIT"
echo "========================================="

echo
echo "This report generated at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# This script requires that the following are installed:
# - aws CLI (configured to your AWS account)
# - jq
command -v aws >/dev/null 2>&1 || { echo "aws CLI required"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 1; }