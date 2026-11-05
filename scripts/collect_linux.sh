#!/bin/sh
# ============================================================================
#  IT Audit Toolkit - Linux configuration collection (READ-ONLY)
#  สคริปต์เก็บข้อมูลการตั้งค่าเพื่อการตรวจสอบ: อ่านอย่างเดียว ไม่เปลี่ยนแปลงระบบ
#
#  วิธีใช้:  sudo sh collect_linux.sh
#  ผลลัพธ์: /tmp/audit_<hostname>_<date>.tar.gz ส่งกลับให้ผู้ตรวจสอบ
#
#  ข้อมูลที่เก็บ: sshd_config, passwd, group, sudoers, login.defs, pwquality, faillock, PAM remember
#  ไม่เก็บ: /etc/shadow (hash รหัสผ่าน), ไฟล์ข้อมูลธุรกิจ
# ============================================================================

OUT="/tmp/audit_$(hostname)_$(date +%Y%m%d_%H%M)"
mkdir -p "$OUT"

echo "[1/5] Configuration files..."
for f in /etc/ssh/sshd_config /etc/passwd /etc/group /etc/login.defs \
         /etc/security/pwquality.conf /etc/security/faillock.conf; do
  [ -r "$f" ] && cp "$f" "$OUT/$(basename "$f")"
done

echo "[2/5] Effective SSH configuration..."
if command -v sshd >/dev/null 2>&1; then
  sshd -T > "$OUT/sshd_effective.txt" 2>/dev/null || rm -f "$OUT/sshd_effective.txt"
fi

echo "[3/5] sudoers..."
if [ -r /etc/sudoers ]; then
  { cat /etc/sudoers; cat /etc/sudoers.d/* 2>/dev/null; } > "$OUT/sudoers"
else
  echo "  (skipped: run with sudo to include sudoers)"
fi

echo "[4/5] PAM password history..."
grep -hs "remember=" /etc/pam.d/* > "$OUT/pam_remember.txt"

echo "[5/5] System info..."
{ uname -a; cat /etc/os-release 2>/dev/null; } > "$OUT/system_info.txt"

tar -czf "$OUT.tar.gz" -C /tmp "$(basename "$OUT")"
echo ""
echo "Done: $OUT.tar.gz"
