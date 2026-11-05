#!/bin/bash
# ============================================================================
#  IT Audit Toolkit - Microsoft Azure configuration collection (READ-ONLY)
#  สคริปต์เก็บข้อมูลการตั้งค่า Azure เพื่อการตรวจสอบ: เรียกเฉพาะคำสั่งอ่าน ไม่เปลี่ยนแปลงระบบ
#
#  ต้องมี: Azure CLI ที่ล็อกอินแล้ว (แนะนำรันใน Azure Cloud Shell แบบ Bash)
#  สิทธิ์ที่ต้องใช้ (อ่านอย่างเดียว):
#    - Azure RBAC ระดับ subscription: "Reader" และ "Security Reader"
#    - Entra ID: "Global Reader" (หรือ "Reports Reader" + "Directory Readers") สำหรับข้อมูล MFA และผู้ดูแลระบบ
#  วิธีใช้:  bash collect_azure.sh                 (ใช้ subscription ปัจจุบัน)
#            bash collect_azure.sh <subscription-id>
#  ผลลัพธ์: azure_audit_<subscription>_<date>.zip ส่งกลับให้ผู้ตรวจสอบ
# ============================================================================
set -u
[ $# -ge 1 ] && az account set --subscription "$1"
SUB=$(az account show --query id -o tsv) || { echo "Azure CLI ยังไม่ได้ล็อกอิน (az login)"; exit 1; }
OUT="azure_audit_${SUB:0:8}_$(date +%Y%m%d_%H%M)"
mkdir -p "$OUT"

echo "[1/9] Subscription..."
az account show -o json > "$OUT/account.json"

echo "[2/9] Role assignments..."
az role assignment list --all --include-inherited -o json > "$OUT/role_assignments.json"

echo "[3/9] Network security groups..."
az network nsg list -o json > "$OUT/nsgs.json"

echo "[4/9] Storage accounts..."
az storage account list -o json > "$OUT/storage_accounts.json"

echo "[5/9] Azure SQL firewall rules..."
az sql server list --query "[].[name,resourceGroup]" -o tsv 2>/dev/null | while IFS=$'\t' read -r NAME RG; do
  [ -n "$NAME" ] && az sql server firewall-rule list -g "$RG" -s "$NAME" -o json > "$OUT/sql_firewall_${NAME}.json"
done

echo "[6/9] Microsoft Defender for Cloud plans..."
az security pricing list -o json > "$OUT/defender_pricing.json" 2>/dev/null || rm -f "$OUT/defender_pricing.json"

echo "[7/9] Activity log diagnostic settings..."
az monitor diagnostic-settings subscription list -o json > "$OUT/activity_log_diagnostics.json" 2>/dev/null \
  || rm -f "$OUT/activity_log_diagnostics.json"

echo "[8/9] Key Vaults..."
for KV in $(az keyvault list --query "[].name" -o tsv 2>/dev/null); do
  az keyvault show -n "$KV" -o json > "$OUT/keyvault_${KV}.json"
done

echo "[9/9] Entra ID (MFA, Global Administrators, guests)..."
URL="https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
PAGE=1
while [ -n "$URL" ] && [ "$PAGE" -le 50 ]; do
  if az rest --method get --url "$URL" -o json > "$OUT/entra_mfa_registration_${PAGE}.json" 2>/dev/null; then
    URL=$(az rest --method get --url "$URL" --query '"@odata.nextLink"' -o tsv 2>/dev/null)
    PAGE=$((PAGE + 1))
  else
    echo "  (ข้าม MFA: ต้องมีสิทธิ์ Reports Reader / Global Reader)"
    rm -f "$OUT/entra_mfa_registration_${PAGE}.json"
    URL=""
  fi
done
az rest --method get -o json \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members" \
  > "$OUT/entra_global_admins.json" 2>/dev/null || rm -f "$OUT/entra_global_admins.json"
az ad user list --filter "userType eq 'Guest'" -o json > "$OUT/entra_guest_users.json" 2>/dev/null \
  || rm -f "$OUT/entra_guest_users.json"

if command -v zip >/dev/null 2>&1; then zip -qr "$OUT.zip" "$OUT"; echo "Done: $OUT.zip"
else tar -czf "$OUT.tar.gz" "$OUT"; echo "Done: $OUT.tar.gz"; fi
