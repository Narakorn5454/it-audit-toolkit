# ============================================================================
#  IT Audit Toolkit - Windows configuration collection (READ-ONLY)
#  สคริปต์เก็บข้อมูลการตั้งค่าเพื่อการตรวจสอบ: อ่านอย่างเดียว ไม่เปลี่ยนแปลงระบบ
#
#  วิธีใช้: เปิด PowerShell แบบ "Run as Administrator" แล้วรัน
#      powershell -ExecutionPolicy Bypass -File .\collect_windows.ps1
#  ผลลัพธ์: ไฟล์ zip ในโฟลเดอร์ TEMP ส่งกลับให้ผู้ตรวจสอบ
#
#  ข้อมูลที่เก็บ: นโยบายความปลอดภัย (secedit), audit policy, นโยบายรหัสผ่าน,
#                รายชื่อบัญชี local และสมาชิกกลุ่ม Administrators
#  ไม่เก็บ: รหัสผ่าน, hash, ข้อมูลธุรกิจ
#  หมายเหตุ: auditpol ต้องเป็น Windows ภาษาอังกฤษ จึงจะตรวจอัตโนมัติได้
# ============================================================================

$ErrorActionPreference = "Continue"
$stamp = Get-Date -Format "yyyyMMdd_HHmm"
$out = Join-Path $env:TEMP ("audit_{0}_{1}" -f $env:COMPUTERNAME, $stamp)
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Host "[1/6] Security policy (secedit)..."
secedit /export /cfg "$out\secpol.inf" /areas SECURITYPOLICY USER_RIGHTS /quiet

Write-Host "[2/6] Audit policy..."
auditpol /get /category:* | Out-File "$out\auditpol.txt" -Encoding utf8

Write-Host "[3/6] Password policy (net accounts)..."
net accounts | Out-File "$out\net_accounts.txt" -Encoding utf8

Write-Host "[4/6] Domain password policy (if AD module available)..."
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory
    Get-ADDefaultDomainPasswordPolicy | Out-File "$out\ad_password_policy.txt" -Encoding utf8
}

Write-Host "[5/6] Local users..."
try {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, PasswordExpires |
        Export-Csv "$out\local_users.csv" -NoTypeInformation -Encoding UTF8
    Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource |
        Export-Csv "$out\local_administrators.csv" -NoTypeInformation -Encoding UTF8
} catch { Write-Host "  (skipped: $_)" }

Write-Host "[6/6] System info..."
Get-ComputerInfo -Property WindowsProductName, WindowsVersion, OsBuildNumber, CsDomain |
    Out-File "$out\system_info.txt" -Encoding utf8

Compress-Archive -Path "$out\*" -DestinationPath "$out.zip" -Force
Write-Host ""
Write-Host "เสร็จแล้ว / Done: $out.zip" -ForegroundColor Green
