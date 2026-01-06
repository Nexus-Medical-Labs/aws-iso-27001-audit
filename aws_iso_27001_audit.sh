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

echo
echo "========================================="
echo " AWS SECURITY REVIEW"
echo "========================================="
echo
echo "NOTE: This only checks the last 90 days because it uses CloudTrail lookup-events which only goes back 90 days by default."

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
      --query 'Events[?contains(CloudTrailEvent, \`AccessDenied\`)].{Time:EventTime,User:Username,Event:EventName}' \
      --output table || true"
done

# 3) Check for root account usage events
run_check "Check for root account usage events" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --query 'Events[].{Time:EventTime,Event:EventName}' \
  --output table"

# 4) Check for any IAM Changes
run_check "Check for any IAM Changes" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
  --query 'Events[].{Time:EventTime,User:Username,Event:EventName}' \
  --output table"

# 5) Check for any security group ingress changes
run_check "Check for any security group ingress changes" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --query 'Events[].{Time:EventTime,User:Username}' \
  --output table"

# 6) Check for any S3 Bucket Policy Changes
run_check "Check for any S3 Bucket Policy Changes" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --query 'Events[].{Time:EventTime,User:Username}' \
  --output table"

echo
echo "========================================="
echo " AWS SECURITY REVIEW COMPLETE"
echo "========================================="