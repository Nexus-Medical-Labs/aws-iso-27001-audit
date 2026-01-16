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

# Disable AWS CLI paging
export AWS_PAGER=""

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
  --output json"

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
      --output json || true"
done

# 3) Check for root account usage events
run_check "Check for root account usage events" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --query 'Events[].{Time:EventTime,Event:EventName}' \
  --output json"

# 4) Check for any IAM Changes
run_check "Check for any IAM Changes" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
  --query 'Events[].{Time:EventTime,User:Username,Event:EventName}' \
  --output json"

# 5) Check for any security group ingress changes
run_check "Check for any security group ingress changes" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --query 'Events[].{Time:EventTime,User:Username}' \
  --output json"

# 6) Check for any S3 Bucket Policy Changes
run_check "Check for any S3 Bucket Policy Changes" \
"aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --query 'Events[].{Time:EventTime,User:Username}' \
  --output json"

echo
echo "========================================="
echo " AWS SECURITY REVIEW COMPLETE"
echo "========================================="


# Scan all RDS instances across all regions for backup settings and recent snapshots.
echo
echo "========================================="
echo " Scan all RDS instances across all regions for backup settings and recent snapshots."
echo "========================================="

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Get all regions
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

out_file="$TMPDIR/instances.jsonl"
: > "$out_file"

for region in $REGIONS; do
  echo "Scanning region: $region"
  # List DB instances in region
  aws rds describe-db-instances --region "$region" --output json 2>/dev/null || echo '{"DBInstances":[]}'

  # Same as above but now just get the DB instance IDs in region
  instance_ids=$(aws rds describe-db-instances --region "$region" --query 'DBInstances[].DBInstanceIdentifier' --output text 2>/dev/null || echo "")

  for id in $instance_ids; do
    # List DB instance snapshots
    aws rds describe-db-snapshots --region "$region" --db-instance-identifier "$id" --output json 2>/dev/null || echo '{"DBSnapshots":[]}'

    # search other regions for snapshot copies referencing this instance
    for rr in $REGIONS; do
      if [[ "$rr" == "$region" ]]; then continue; fi
      aws rds describe-db-snapshots --region "$rr" --query "DBSnapshots[?DBInstanceIdentifier=='$id']" --output json 2>/dev/null || echo '[]'
    done
  done
done

echo
echo "========================================="
echo " AWS RDS scan complete"
echo "========================================="