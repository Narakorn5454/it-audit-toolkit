#!/bin/bash
# ============================================================================
#  IT Audit Toolkit - AWS configuration collection (READ-ONLY)
#  สคริปต์เก็บข้อมูลการตั้งค่า AWS เพื่อการตรวจสอบ: เรียกเฉพาะคำสั่งอ่าน ไม่เปลี่ยนแปลงบัญชี
#
#  ต้องมี: AWS CLI v2 ที่ตั้งค่า credential ซึ่งมีสิทธิ์อ่าน (AWS managed policy "SecurityAudit")
#  วิธีใช้:  bash collect_aws.sh            (หรือ AWS_PROFILE=audit bash collect_aws.sh)
#  ผลลัพธ์: aws_audit_<account>_<date>.zip ส่งกลับให้ผู้ตรวจสอบ
#
#  หมายเหตุ: คำสั่ง generate-credential-report เป็นการสร้างรายงานภายใน IAM
#            ไม่เปลี่ยนการตั้งค่าใด ๆ ของบัญชี
# ============================================================================
set -u
ACCT=$(aws sts get-caller-identity --query Account --output text) || { echo "AWS CLI ไม่พร้อมใช้งาน"; exit 1; }
OUT="aws_audit_${ACCT}_$(date +%Y%m%d_%H%M)"
mkdir -p "$OUT"

echo "[1/7] IAM credential report..."
for i in 1 2 3 4 5 6 7 8 9 10; do
  STATE=$(aws iam generate-credential-report --query State --output text)
  [ "$STATE" = "COMPLETE" ] && break
  sleep 3
done
aws iam get-credential-report --query Content --output text | base64 --decode > "$OUT/credential_report.csv"

echo "[2/7] IAM password policy..."
aws iam get-account-password-policy > "$OUT/password_policy.json" 2>/dev/null \
  || { echo "  (ยังไม่ได้ตั้ง password policy)"; rm -f "$OUT/password_policy.json"; }

echo "[3/7] AdministratorAccess holders..."
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  > "$OUT/admin_policy_entities.json"

echo "[4/7] Security groups (ทุก region)..."
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws ec2 describe-security-groups --region "$R" > "$OUT/security_groups_${R}.json" 2>/dev/null \
    || rm -f "$OUT/security_groups_${R}.json"
done

echo "[5/7] CloudTrail..."
aws cloudtrail describe-trails > "$OUT/cloudtrail_trails.json"
echo "trail_name,is_logging" > "$OUT/cloudtrail_status.csv"
for T in $(aws cloudtrail describe-trails --query 'trailList[].TrailARN' --output text); do
  NAME=$(basename "$T")
  LOG=$(aws cloudtrail get-trail-status --name "$T" --query IsLogging --output text 2>/dev/null || echo "Unknown")
  echo "${NAME},${LOG}" >> "$OUT/cloudtrail_status.csv"
done

echo "[6/7] S3 Block Public Access (ระดับบัญชี)..."
aws s3control get-public-access-block --account-id "$ACCT" > "$OUT/s3_account_public_access.json" 2>/dev/null \
  || rm -f "$OUT/s3_account_public_access.json"

echo "[7/7] S3 buckets..."
echo "bucket,block_public_acls,ignore_public_acls,block_public_policy,restrict_public_buckets,policy_is_public" \
  > "$OUT/s3_public_access.csv"
for B in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  PAB=$(aws s3api get-public-access-block --bucket "$B" \
        --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
        --output text 2>/dev/null | tr '\t' ',')
  [ -z "$PAB" ] && PAB="False,False,False,False"
  PUB=$(aws s3api get-bucket-policy-status --bucket "$B" --query PolicyStatus.IsPublic --output text 2>/dev/null \
        || echo "False")
  echo "${B},${PAB},${PUB}" >> "$OUT/s3_public_access.csv"
done

if command -v zip >/dev/null 2>&1; then zip -qr "$OUT.zip" "$OUT"; echo "Done: $OUT.zip"
else tar -czf "$OUT.tar.gz" "$OUT"; echo "Done: $OUT.tar.gz"; fi
