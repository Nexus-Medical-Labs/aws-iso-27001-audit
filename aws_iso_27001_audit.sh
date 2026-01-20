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

# Get all regions
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

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


echo
echo "========================================="
echo " List all IAM users and gather summary details for each"
echo "========================================="
# List all IAM users and gather summary details for each:
# - username, userId, arn, createDate, passwordLastUsed, groups, attached policies, access keys, mfa devices

jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{generated_at:$generated_at}'


# Fetch all users
users_json=$(aws iam list-users --query 'Users[].UserName' --output text)

# Iterate usernames to avoid subshell issues
for username in $users_json; do
  aws iam get-user --user-name "$username" --output json 2>/dev/null || echo '{"User":{}}'
  aws iam list-groups-for-user --user-name "$username" --output json 2>/dev/null || echo '{"Groups":[]}'
  aws iam list-attached-user-policies --user-name "$username" --output json 2>/dev/null || echo '{"AttachedPolicies":[]}'
  aws iam list-access-keys --user-name "$username" --output json 2>/dev/null || echo '{"AccessKeyMetadata":[]}'
  aws iam list-mfa-devices --user-name "$username" --output json 2>/dev/null || echo '{"MFADevices":[]}'
done


# IAM Identity Center (SSO) users.
echo
echo "===== List all identity center (SSO) users for us-east-1 ====="

for region in $REGIONS; do
  echo "Scanning region: $region"

  # Get Identity Center instance details (if any)
  INSTANCE_INFO=$(aws sso-admin list-instances --region "$region" --query 'Instances[0].[IdentityStoreId]' --output text 2>/dev/null || true)

  IDENTITY_STORE_ID=$(echo "$INSTANCE_INFO" | awk '{print $1}')

  if [ -z "$IDENTITY_STORE_ID" ] || [ "$IDENTITY_STORE_ID" == "None" ]; then
    echo "No IAM Identity Center instance found in "$region""
  else
    # List Identity Center users
    aws identitystore list-users --identity-store-id "$IDENTITY_STORE_ID" --region "$region" --query 'Users[].UserName' --output json
  fi
done

echo
echo "========================================="
echo " Listing of all IAM users complete"
echo "========================================="


# Check multi-region replication for common services.
# - Checks: S3 (CRR), DynamoDB (global tables / replicas), RDS (read-replicas / global clusters), ECR replication configuration, Secrets Manager multi-region replication
echo
echo "========================================="
echo " Check multi-region replication for common services"
echo "========================================="


########################################################################
# S3 Cross-Region Replication
########################################################################
echo
echo "Checking S3 buckets for replication..."

buckets=$(aws s3api list-buckets --query 'Buckets[].Name' --output text)

for b in $buckets; do
  # Check if replication is configured by querying for rules
  rules_status=$(aws s3api get-bucket-replication --bucket "$b" --query 'ReplicationConfiguration.Rules[0].Status' --output text 2>/dev/null || echo "NoRules")
  
  if [[ "$rules_status" != "NoRules" && "$rules_status" != "None" ]]; then
    # Get all destination bucket ARNs
    echo "Bucket $b has replication configured to the following destination buckets:"
    aws s3api get-bucket-replication --bucket "$b" --query 'ReplicationConfiguration.Rules[].Destination.Bucket' --output json 2>/dev/null || echo ""
  else
    echo "Bucket $b has no replication configured"
  fi
done

echo "S3 check complete"


########################################################################
# RDS – Cross-Region Replication
########################################################################
echo "Checking RDS instances for replication..."

for r in $REGIONS; do
  echo "Scanning region: $r"
  
  # Get primary instances and their replicas
  aws rds describe-db-instances --region "$r" --query 'DBInstances[?length(ReadReplicaDBInstanceIdentifiers)>`0`].[DBInstanceIdentifier,ReadReplicaDBInstanceIdentifiers]' --output json 2>/dev/null || echo ""
done

echo "RDS check complete"


########################################################################
# ECR – Replication configuration
########################################################################
echo "Checking ECR replication configuration..."

for r in $REGIONS; do
  echo "Scanning region: $r"
  aws ecr describe-registry --region "$r" --output json
done

echo "ECR check complete"


########################################################################
# Secrets Manager – Cross-Region Replication
########################################################################
echo "Checking Secrets Manager for cross-region replication..."

for r in $REGIONS; do
  echo "Scanning region: $r"

  secrets=$(aws secretsmanager list-secrets --region "$r" --query 'SecretList[].ARN' --output text 2>/dev/null || echo "")

  for s in $secrets; do
    echo "Getting replica regions for Secret ARN: $s"
    replica_regions=$(aws secretsmanager describe-secret --secret-id "$s" --query 'ReplicaRegions[].Region' --output json 2>/dev/null || echo '[]')

    if [[ "$replica_regions" == "[]" || "$replica_regions" == "null" || -z "$replica_regions" ]]; then
      echo "No replica regions found"
    else
      echo "$replica_regions"
    fi
  done
done
echo "Secrets Manager check complete"


########################################################################
# The next few sections check for encryption at rest and in transit.
# - At rest: Storage encryption using AES-256 or AWS KMS is confirmed for EC2 EBS volumes, S3 buckets and RDS/Aurora databases.
# - In transit: TLS 1.2+ enforcement is confirmed via load balancer SSL policies, S3 SecureTransport bucket policies, and database SSL configuration.
########################################################################

############################################
# EC2 – EBS encryption at rest and in transit
# Check for encryption at rest. No separate check for in transit needed becauseEBS encryption in transit is automatically enabled when you encrypt a volume at rest.
# (EBS encryption in transit is not a separate setting - it's an inherent feature of encrypted EBS volumes. The encryption happens in the hypervisor layer between the instance and the storage, using the same KMS key.)
############################################
for r in $REGIONS; do
  echo
  echo "Scanning region: $r"
  
  echo
  echo "Checking for EC2/EBS encryption at rest and in transit..."

  aws ec2 describe-volumes --region "$r" --query 'Volumes[].{VolumeId:VolumeId,Encrypted:Encrypted,KmsKeyId:KmsKeyId}' --output json

  # Also check that encryption for new EC2 instances is enforced by default
  echo
  echo "Checking for EC2/EBS default encryption set to true for creation of new instances..."

  aws ec2 get-ebs-encryption-by-default --region "$r" --query 'EbsEncryptionByDefault' --output json
done


############################################
# S3 – Encryption at rest
# No need to search every region. The list of S3 buckets will be the same for all of them.
# (S3 bucket names are globally unique across all AWS accounts and regions. While each bucket exists in a specific region, the list-buckets API call is a global operation that always returns every bucket you own.)
############################################
echo
echo "Checking for default setting of S3 encryption at rest..."

S3_BUCKETS=$(aws s3api list-buckets --query 'Buckets[].Name' --output text)

for BUCKET in $S3_BUCKETS; do
  echo
  echo "Bucket: $BUCKET"

  aws s3api get-bucket-encryption --bucket "$BUCKET" --output json
done