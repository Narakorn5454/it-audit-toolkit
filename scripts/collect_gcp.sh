#!/bin/bash
# ============================================================================
#  IT Audit Toolkit - Google Cloud configuration collection (READ-ONLY)
#  สคริปต์เก็บข้อมูลการตั้งค่า GCP เพื่อการตรวจสอบ: เรียกเฉพาะคำสั่งอ่าน ไม่เปลี่ยนแปลงระบบ
#
#  ต้องมี: gcloud CLI ที่ล็อกอินแล้ว (แนะนำรันใน Google Cloud Shell)
#  สิทธิ์ที่ต้องใช้ (อ่านอย่างเดียว) ระดับ project:
#    roles/viewer และ roles/iam.securityReviewer
#  วิธีใช้:  bash collect_gcp.sh                (ใช้ project ปัจจุบันใน gcloud config)
#            bash collect_gcp.sh <project-id>
#  ผลลัพธ์: gcp_audit_<project>_<date>.zip ส่งกลับให้ผู้ตรวจสอบ
#  หมายเหตุ: ถ้า project ยังไม่เปิด API บางตัว (เช่น Compute, Cloud SQL) ส่วนนั้นจะถูกข้าม
# ============================================================================
set -u
PROJECT="${1:-$(gcloud config get-value project 2>/dev/null)}"
[ -z "$PROJECT" ] && { echo "ระบุ project: bash collect_gcp.sh <project-id>"; exit 1; }
OUT="gcp_audit_${PROJECT}_$(date +%Y%m%d_%H%M)"
mkdir -p "$OUT"
keep_or_drop() { [ -s "$1" ] || rm -f "$1"; }

echo "[1/7] Project..."
gcloud projects describe "$PROJECT" --format=json > "$OUT/project_info.json"
gcloud projects get-iam-policy "$PROJECT" --format=json > "$OUT/project_iam_policy.json"

echo "[2/7] Firewall rules..."
gcloud compute firewall-rules list --project "$PROJECT" --format=json > "$OUT/firewall_rules.json" 2>/dev/null
keep_or_drop "$OUT/firewall_rules.json"

echo "[3/7] VPC networks..."
gcloud compute networks list --project "$PROJECT" --format=json > "$OUT/networks.json" 2>/dev/null
keep_or_drop "$OUT/networks.json"

echo "[4/7] Service accounts and user-managed keys..."
gcloud iam service-accounts list --project "$PROJECT" --format=json > "$OUT/service_accounts.json"
for SA in $(gcloud iam service-accounts list --project "$PROJECT" --format="value(email)"); do
  gcloud iam service-accounts keys list --iam-account "$SA" --managed-by=user --format=json \
    > "$OUT/sa_keys_${SA%%@*}.json" 2>/dev/null
  keep_or_drop "$OUT/sa_keys_${SA%%@*}.json"
done

echo "[5/7] Cloud Storage buckets..."
gcloud storage buckets list --project "$PROJECT" --format=json > "$OUT/buckets.json" 2>/dev/null
keep_or_drop "$OUT/buckets.json"

echo "[6/7] Bucket IAM policies..."
for B in $(gcloud storage buckets list --project "$PROJECT" --format="value(name)" 2>/dev/null); do
  gcloud storage buckets get-iam-policy "gs://${B}" --format=json > "$OUT/bucket_iam_${B}.json" 2>/dev/null
  keep_or_drop "$OUT/bucket_iam_${B}.json"
done

echo "[7/7] Cloud SQL instances..."
gcloud sql instances list --project "$PROJECT" --format=json > "$OUT/sql_instances.json" 2>/dev/null
keep_or_drop "$OUT/sql_instances.json"

if command -v zip >/dev/null 2>&1; then zip -qr "$OUT.zip" "$OUT"; echo "Done: $OUT.zip"
else tar -czf "$OUT.tar.gz" "$OUT"; echo "Done: $OUT.tar.gz"; fi
