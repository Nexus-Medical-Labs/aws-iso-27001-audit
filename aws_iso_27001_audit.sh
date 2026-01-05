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

# AWS SECURITY REVIEW

# Can only go back 90 days because that is the furthest back CloudTrail can check by default.
DAYS_BACK=90
START_TIME=$(date -v-"$DAYS_BACK"d +%s)
END_TIME=$(date +%s)

echo
echo "========================================="
echo " AWS SECURITY REVIEW (Last $DAYS_BACK days)"
echo "========================================="

run_check() {
    local desc="$1"
    local cmd="$2"

    echo
    echo "=== $desc ==="

    OUTPUT=$(eval "$cmd")
    if [[ -z "$OUTPUT" || "$OUTPUT" == "[]" ]]; then
        echo "No events found"
    else
        echo "$OUTPUT"
    fi
}

# 1) Check for failed Console Logins
run_check "Check for failed console logins" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time $START_TIME --end-time $END_TIME \
  --query 'Events[?contains(CloudTrailEvent, \`Failed\`)].{Time:EventTime,User:Username}' \
  --output table"

# 2) Check for AccessDenied events

# List of events to check
EVENTS=(
  "CreateUser" "CreateAccessKey" "DeleteAccessKey" "AttachUserPolicy" "DetachUserPolicy"
  "PutUserPolicy" "CreateRole" "UpdateAssumeRolePolicy" "AttachRolePolicy" "PutRolePolicy"
  "PutBucketPolicy" "PutBucketAcl" "PutObject" "DeleteObject" "AuthorizeSecurityGroupIngress"
  "RevokeSecurityGroupIngress" "CreateSecurityGroup" "CreateKey" "DisableKey" "CreateStack"
  "UpdateStack"
)
# NOTE 1/5/26 - Removed AssumeRole from EVENTS above due to high volume of benign AccessDenied events. Was taking too long and hanging. Find a way to add it in the future.

for EVENT in "${EVENTS[@]}"; do
    run_check "Check for AccessDenied in $EVENT events" \
    "aws cloudtrail lookup-events \
      --lookup-attributes AttributeKey=EventName,AttributeValue=$EVENT \
      --start-time \"$START_TIME\" \
      --end-time \"$END_TIME\" \
      --query 'Events[?contains(CloudTrailEvent, \`AccessDenied\`)].{Time:EventTime,User:Username,Event:EventName}' \
      --output table || true"
done