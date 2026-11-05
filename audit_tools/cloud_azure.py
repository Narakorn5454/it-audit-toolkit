"""
Microsoft Azure Configuration Review — ตรวจการตั้งค่าความปลอดภัย Azure จากไฟล์ export (อ่านอย่างเดียว)
=====================================================================================================
ไฟล์จาก scripts/collect_azure.sh (Azure CLI / Microsoft Graph) — ระบบตรวจชนิดไฟล์ให้อัตโนมัติ:
  role_assignments.json            az role assignment list --all
  nsgs.json                        az network nsg list
  storage_accounts.json            az storage account list
  sql_firewall_<server>.json       az sql server firewall-rule list
  defender_pricing.json            az security pricing list
  activity_log_diagnostics.json    az monitor diagnostic-settings subscription list
  keyvault_<name>.json             az keyvault show
  entra_mfa_registration*.json     Graph: reports/authenticationMethods/userRegistrationDetails
  entra_global_admins.json         Graph: directoryRoles (Global Administrator) members
  entra_guest_users.json           az ad user list --filter "userType eq 'Guest'"
แนวเกณฑ์: CIS Microsoft Azure Foundations Benchmark
"""

from __future__ import annotations

import json
import re

import pandas as pd

from .cloud_aws import ADMIN_PORTS, DB_PORTS
from .common import AuditError, make_findings, read_text, sort_findings, write_findings_report

CHECKS = {
    "AZ-01": ("ผู้ใช้ Entra ID ที่ยังไม่ได้ลงทะเบียน MFA", "High", "บังคับ MFA ผ่าน Conditional Access หรือ Security defaults ให้ผู้ใช้ทุกคน",
              "CIS Azure — Identity: MFA สำหรับผู้ใช้ทุกคน โดยเฉพาะผู้ดูแลระบบ"),
    "AZ-02": ("จำนวน Global Administrator ไม่เหมาะสม", "Medium",
              "ให้มี Global Administrator 2–4 คน (รวมบัญชีฉุกเฉิน) และใช้ role ที่จำกัดกว่าสำหรับงานประจำ",
              "สิทธิ์สูงสุดของ tenant ควรมีจำนวนน้อยที่สุดที่จำเป็น"),
    "AZ-03": ("บัญชีผู้ใช้ภายนอก (Guest) ใน tenant", "Review",
              "ทบทวนความจำเป็นของ guest ทุกบัญชีและตั้งรอบ Access review", "CIS Azure — Identity: ทบทวน guest users"),
    "AZ-04": ("สิทธิ์ Owner / User Access Administrator ระดับ subscription ให้ผู้ใช้โดยตรง", "Medium",
              "ให้สิทธิ์ผ่านกลุ่ม ใช้ PIM แบบ just-in-time และจำกัดจำนวนผู้ถือสิทธิ์",
              "ผู้ถือ Owner ควบคุมทรัพยากรทั้งหมดและให้สิทธิ์ผู้อื่นได้"),
    "AZ-05": ("NSG เปิดพอร์ตผู้ดูแลระบบ/ทุกพอร์ตจากอินเทอร์เน็ต", "High",
              "จำกัดแหล่งที่มา หรือใช้ Azure Bastion / Just-in-time VM access",
              "CIS Azure — Networking: ห้ามเปิด RDP/SSH จากอินเทอร์เน็ต"),
    "AZ-06": ("NSG เปิดพอร์ตฐานข้อมูลจากอินเทอร์เน็ต", "High", "ใช้ Private Endpoint และจำกัดการเข้าถึงเฉพาะ application",
              "ฐานข้อมูลไม่ควรเข้าถึงได้จากอินเทอร์เน็ต"),
    "AZ-07": ("Storage account อนุญาตให้เข้าถึง blob แบบสาธารณะ", "High", "ตั้ง allowBlobPublicAccess = false",
              "CIS Azure — Storage: ปิด public access"),
    "AZ-08": ("Storage account ไม่บังคับ HTTPS หรือใช้ TLS ต่ำกว่า 1.2", "Medium",
              "เปิด Secure transfer required และตั้ง Minimum TLS 1.2", "CIS Azure — Storage: secure transfer, TLS 1.2"),
    "AZ-09": ("Azure SQL firewall เปิดกว้าง", "High", "ลบ rule ที่เปิดทุก IP และใช้ Private Endpoint",
              "CIS Azure — Database: ห้ามเปิด 0.0.0.0–255.255.255.255"),
    "AZ-10": ("Microsoft Defender for Cloud ยังไม่เปิดแผนป้องกัน", "Medium",
              "เปิด Defender plans สำหรับทรัพยากรสำคัญ (Servers, SQL, Storage, Key Vault ฯลฯ)",
              "CIS Azure — Microsoft Defender for Cloud"),
    "AZ-11": ("ไม่ได้ส่ง Activity log ไปจัดเก็บ", "Medium",
              "ตั้ง Diagnostic setting ระดับ subscription ส่ง Activity log ไป Log Analytics / Storage",
              "CIS Azure — Logging: เก็บ activity log เพื่อตรวจสอบย้อนหลัง"),
    "AZ-12": ("Key Vault ไม่ได้เปิด purge protection", "Medium", "เปิด purge protection เพื่อป้องกันการลบ key ถาวร",
              "CIS Azure — Key Vault: recoverable"),
}
CATEGORY = {"AZ-01": "Identity & MFA", "AZ-02": "Privileged access", "AZ-03": "Identity & MFA",
            "AZ-04": "Privileged access", "AZ-05": "Network exposure", "AZ-06": "Network exposure",
            "AZ-07": "Storage & data", "AZ-08": "Storage & data", "AZ-09": "Network exposure",
            "AZ-10": "Threat detection", "AZ-11": "Logging", "AZ-12": "Storage & data"}

COL_TH = {"resource": "ทรัพยากร", "resource_type": "ประเภท", "region": "ตำแหน่ง"}
FIELDS = ["resource", "resource_type", "region"]
INTERNET = {"*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "::/0"}
GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"


def _value(j):
    """Graph / ARM บางคำสั่งคืน {"value": [...]} บางคำสั่งคืน list"""
    return j.get("value", []) if isinstance(j, dict) and "value" in j else (j if isinstance(j, list) else [j])


def detect(text: str, fname: str) -> str:
    f = fname.lower()
    try:
        j = json.loads(text)
    except json.JSONDecodeError:
        raise AuditError(f"{fname}: ไม่ใช่ไฟล์ JSON")
    items = _value(j)
    first = items[0] if items and isinstance(items[0], dict) else {}
    if "global_admin" in f:
        return "global_admins"
    if "guest" in f:
        return "guests"
    if "diagnostic" in f or "activity_log" in f:
        return "diagnostics"
    if "isMfaRegistered" in first or "mfa" in f:
        return "mfa"
    if "roleDefinitionName" in first or "role_assign" in f:
        return "roles"
    if "securityRules" in first or f.startswith("nsg"):
        return "nsgs"
    if "allowBlobPublicAccess" in first or "primaryEndpoints" in first or "storage" in f:
        return "storage"
    if "startIpAddress" in first or "sql_firewall" in f:
        return "sql_firewall"
    if "pricingTier" in first or "pricing" in f or "defender" in f:
        return "defender"
    if isinstance(j, dict) and "enablePurgeProtection" in (j.get("properties") or {}) or "keyvault" in f:
        return "keyvault"
    if isinstance(j, dict) and "tenantId" in j and "isDefault" in j:
        return "account"
    raise AuditError(f"{fname}: ไม่รู้จักรูปแบบไฟล์ Azure นี้")


def load_files(files: list[tuple[object, str]]) -> dict:
    data: dict = {"mfa": [], "sql_firewall": [], "keyvault": [], "skipped": []}
    for src, fname in files:
        text = read_text(src, fname)
        try:
            kind = detect(text, fname)
        except AuditError:
            data["skipped"].append(fname)
            continue
        j = json.loads(text)
        if kind == "mfa":
            data["mfa"] += _value(j)
        elif kind == "sql_firewall":
            m = re.search(r"sql_firewall_(.+)\.json", fname)
            for r in _value(j):
                srv = re.search(r"/servers/([^/]+)/", r.get("id", ""))
                r["_server"] = srv.group(1) if srv else (m.group(1) if m else "")
                data["sql_firewall"].append(r)
        elif kind == "keyvault":
            data["keyvault"].append(j)
        else:
            data[kind] = j
    if len(data) == 4 and not (data["mfa"] or data["sql_firewall"] or data["keyvault"]):
        raise AuditError("ไม่พบไฟล์ Azure ที่อ่านได้ — ใช้ไฟล์จาก scripts/collect_azure.sh")
    return data


def _ports(rule: dict) -> list[tuple[int, int]]:
    ranges = [rule.get("destinationPortRange")] + list(rule.get("destinationPortRanges") or [])
    out = []
    for r in ranges:
        if not r:
            continue
        r = str(r)
        if r == "*":
            out.append((0, 65535))
        elif "-" in r:
            a, b = r.split("-", 1)
            out.append((int(a), int(b)))
        elif r.isdigit():
            out.append((int(r), int(r)))
    return out


def analyze(data: dict) -> dict:
    rows, status = [], {}

    def add(cid, resource, rtype, detail, region="", severity=None):
        r = {"check_id": cid, "resource": resource, "resource_type": rtype, "region": region, "detail": detail}
        if severity:
            r["severity"] = severity
        rows.append(r)

    # --- Entra ID ---
    if data["mfa"]:
        for u in data["mfa"]:
            if not u.get("isMfaRegistered", False):
                admin = bool(u.get("isAdmin"))
                add("AZ-01", u.get("userPrincipalName", "?"), "Entra ID user" + (" (admin)" if admin else ""),
                    ("[ผู้ดูแลระบบ] " if admin else "") + "ยังไม่ได้ลงทะเบียน MFA", severity=None if admin else "Medium")
    else:
        status["AZ-01"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ MFA registration"
    ga = data.get("global_admins")
    if ga is None:
        status["AZ-02"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ Global Administrator"
    else:
        members = [m.get("userPrincipalName") or m.get("displayName") or "?" for m in _value(ga)]
        if len(members) > 4:
            add("AZ-02", "Tenant", "Entra ID role", f"มี Global Administrator {len(members)} คน (แนะนำ 2–4): "
                + ", ".join(members))
        elif len(members) < 2:
            add("AZ-02", "Tenant", "Entra ID role", f"มี Global Administrator เพียง {len(members)} คน "
                "เสี่ยงต่อการถูกล็อกออกจาก tenant (ควรมีบัญชีฉุกเฉิน)", severity="Low")
    guests = data.get("guests")
    if guests is None:
        status["AZ-03"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ guest users"
    elif _value(guests):
        g = [x.get("userPrincipalName") or x.get("mail") or "?" for x in _value(guests)]
        add("AZ-03", "Tenant", "Entra ID guest", f"มี guest {len(g)} บัญชี: " + ", ".join(g[:15])
            + (" ..." if len(g) > 15 else ""))

    # --- RBAC ---
    roles = data.get("roles")
    owners = pd.DataFrame()
    if roles is None:
        status["AZ-04"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ role assignments"
    else:
        ra = pd.DataFrame(_value(roles))
        if not ra.empty:
            for c in ("principalName", "principalType", "roleDefinitionName", "scope"):
                if c not in ra:
                    ra[c] = ""
            owners = ra[ra["roleDefinitionName"].isin(["Owner", "User Access Administrator", "Contributor"])][
                ["principalName", "principalType", "roleDefinitionName", "scope"]]
            sub_level = ra["scope"].astype(str).str.fullmatch(r"/subscriptions/[^/]+") | (ra["scope"] == "/")
            hit = ra[sub_level & (ra["principalType"] == "User")
                     & ra["roleDefinitionName"].isin(["Owner", "User Access Administrator"])]
            for r in hit.itertuples():
                add("AZ-04", r.principalName, "Role assignment", f"{r.roleDefinitionName} ที่ {r.scope} (ให้ผู้ใช้โดยตรง)")

    # --- NSG ---
    nsgs = data.get("nsgs")
    if nsgs is None:
        status["AZ-05"] = status["AZ-06"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ NSG"
    else:
        for n in _value(nsgs):
            for rule in n.get("securityRules", []):
                if str(rule.get("access", "")).lower() != "allow" or str(rule.get("direction", "")).lower() != "inbound":
                    continue
                srcs = {str(rule.get("sourceAddressPrefix") or "").lower()} | \
                       {str(x).lower() for x in rule.get("sourceAddressPrefixes") or []}
                if not srcs & INTERNET:
                    continue
                name = f"{n.get('name')} / {rule.get('name')}"
                ports = _ports(rule)
                if (0, 65535) in ports:
                    add("AZ-05", name, "Network security group", "อนุญาตทุกพอร์ตจากอินเทอร์เน็ต", n.get("location", ""))
                    continue
                for lo, hi in ports:
                    for port, svc in ADMIN_PORTS.items():
                        if lo <= port <= hi:
                            add("AZ-05", name, "Network security group", f"เปิด {svc} ({port}) จากอินเทอร์เน็ต",
                                n.get("location", ""))
                    for port, svc in DB_PORTS.items():
                        if lo <= port <= hi:
                            add("AZ-06", name, "Network security group", f"เปิด {svc} ({port}) จากอินเทอร์เน็ต",
                                n.get("location", ""))

    # --- Storage ---
    st = data.get("storage")
    if st is None:
        status["AZ-07"] = status["AZ-08"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ storage accounts"
    else:
        for s in _value(st):
            if s.get("allowBlobPublicAccess") is True:
                add("AZ-07", s.get("name"), "Storage account", "allowBlobPublicAccess = true", s.get("location", ""))
            gaps = []
            https = s.get("enableHttpsTrafficOnly", s.get("supportsHttpsTrafficOnly"))
            if https is False:
                gaps.append("ไม่บังคับ HTTPS")
            tls = str(s.get("minimumTlsVersion") or "")
            if tls and tls not in ("TLS1_2", "TLS1_3"):
                gaps.append(f"TLS ขั้นต่ำ {tls}")
            if gaps:
                add("AZ-08", s.get("name"), "Storage account", "; ".join(gaps), s.get("location", ""))

    # --- SQL firewall ---
    if not data["sql_firewall"]:
        status["AZ-09"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ SQL firewall (หรือไม่มี SQL server)"
    for r in data["sql_firewall"]:
        a, b = r.get("startIpAddress"), r.get("endIpAddress")
        name = f"{r['_server']} / {r.get('name')}"
        if a == "0.0.0.0" and b == "255.255.255.255":
            add("AZ-09", name, "Azure SQL firewall", "เปิดให้ทุก IP บนอินเทอร์เน็ต (0.0.0.0–255.255.255.255)")
        elif a == "0.0.0.0" and b == "0.0.0.0":
            add("AZ-09", name, "Azure SQL firewall", "Allow Azure services: ทุก resource ใน Azure (รวมของลูกค้ารายอื่น) "
                "เชื่อมต่อได้", severity="Medium")

    # --- Defender ---
    df = data.get("defender")
    if df is None:
        status["AZ-10"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ Defender pricing"
    else:
        free = [p.get("name") for p in _value(df)
                if str(p.get("pricingTier") or (p.get("properties") or {}).get("pricingTier")).lower() == "free"]
        if free:
            add("AZ-10", "Subscription", "Defender for Cloud", "แผนที่ยังเป็น Free: " + ", ".join(free))

    # --- Activity log ---
    dg = data.get("diagnostics")
    if dg is None:
        status["AZ-11"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ diagnostic settings"
    elif not _value(dg):
        add("AZ-11", "Subscription", "Activity log", "ไม่มี diagnostic setting ระดับ subscription")

    # --- Key Vault ---
    if not data["keyvault"]:
        status["AZ-12"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ Key Vault (หรือไม่มี Key Vault)"
    for kv in data["keyvault"]:
        if not (kv.get("properties") or {}).get("enablePurgeProtection"):
            add("AZ-12", kv.get("name"), "Key Vault", "enablePurgeProtection ไม่ได้เปิด", kv.get("location", ""))

    findings = sort_findings(make_findings(rows, CHECKS, FIELDS), ["resource"])
    acct = data.get("account") or {}
    sub_label = f"{acct['name']} ({acct['id']})" if acct.get("name") and acct.get("id") else (acct.get("id") or "-")
    stats = {"subscription": sub_label,
             "users_mfa_checked": len(data["mfa"]),
             "nsgs": len(_value(nsgs)) if nsgs is not None else 0,
             "storage_accounts": len(_value(st)) if st is not None else 0, "skipped": data.get("skipped", [])}
    return {"findings": findings, "status": status, "stats": stats,
            "admins": owners.rename(columns={"principalName": "ผู้ถือสิทธิ์", "principalType": "ประเภท",
                                             "roleDefinitionName": "Role", "scope": "ขอบเขต"})}


def write_report(res: dict, out, name: str = "(ไม่ระบุ)"):
    s = res["stats"]
    info = [("Azure subscription / tenant", name if name != "(ไม่ระบุ)" else s["subscription"]),
            ("ผู้ใช้ที่ตรวจ MFA", s["users_mfa_checked"]), ("Network security groups", s["nsgs"]),
            ("Storage accounts", s["storage_accounts"])]
    write_findings_report(out, "รายงานการตรวจสอบการตั้งค่า Microsoft Azure (Cloud Configuration Review)", info, CHECKS,
                          res["findings"], COL_TH, status=res["status"],
                          extra_sheets={"Privileged Roles": res["admins"]},
                          note="เกณฑ์อ้างอิงแนว CIS Microsoft Azure Foundations Benchmark — ควรยืนยันกับเวอร์ชันล่าสุด")


# ----------------------------------------------------------------------------
# ไฟล์ตัวอย่าง (รูปแบบเหมือน output จริงของ az / Graph)
# ----------------------------------------------------------------------------

def demo_files() -> list[tuple[bytes, str]]:
    sub = "/subscriptions/3f2a1b0c-1111-2222-3333-444455556666"
    files = {
        "account.json": {"id": "3f2a1b0c-1111-2222-3333-444455556666", "name": "Corp-Production", "isDefault": True,
                         "tenantId": "9a8b7c6d-0000-1111-2222-333344445555", "state": "Enabled"},
        "role_assignments.json": [
            {"principalName": "cloud.admin@corp.example", "principalType": "User", "roleDefinitionName": "Owner", "scope": sub},
            {"principalName": "somchai@corp.example", "principalType": "User", "roleDefinitionName": "Owner", "scope": sub},
            {"principalName": "vendor.ops@partner.example", "principalType": "User",
             "roleDefinitionName": "User Access Administrator", "scope": sub},
            {"principalName": "Cloud-Admins", "principalType": "Group", "roleDefinitionName": "Owner", "scope": sub},
            {"principalName": "nida@corp.example", "principalType": "User", "roleDefinitionName": "Contributor",
             "scope": sub + "/resourceGroups/rg-app"},
            {"principalName": "app-deploy-sp", "principalType": "ServicePrincipal", "roleDefinitionName": "Contributor",
             "scope": sub},
        ],
        "nsgs.json": [
            {"name": "nsg-web", "location": "southeastasia", "securityRules": [
                {"name": "allow-https", "access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "*",
                 "destinationPortRange": "443", "protocol": "Tcp", "priority": 100},
                {"name": "allow-rdp", "access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "Internet",
                 "destinationPortRange": "3389", "protocol": "Tcp", "priority": 110}]},
            {"name": "nsg-db", "location": "southeastasia", "securityRules": [
                {"name": "sql-any", "access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "0.0.0.0/0",
                 "destinationPortRanges": ["1433", "5432"], "protocol": "Tcp", "priority": 100}]},
            {"name": "nsg-mgmt", "location": "southeastasia", "securityRules": [
                {"name": "ssh-office", "access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "203.0.113.10/32",
                 "destinationPortRange": "22", "protocol": "Tcp", "priority": 100},
                {"name": "temp-any", "access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "*",
                 "destinationPortRange": "*", "protocol": "*", "priority": 4000}]},
        ],
        "storage_accounts.json": [
            {"name": "corppublicassets", "location": "southeastasia", "allowBlobPublicAccess": True,
             "enableHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2"},
            {"name": "corplegacyfiles", "location": "southeastasia", "allowBlobPublicAccess": False,
             "enableHttpsTrafficOnly": False, "minimumTlsVersion": "TLS1_0"},
            {"name": "corpbackups", "location": "southeastasia", "allowBlobPublicAccess": False,
             "enableHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2"},
        ],
        "sql_firewall_sql-core-prod.json": [
            {"id": sub + "/resourceGroups/rg-db/providers/Microsoft.Sql/servers/sql-core-prod/firewallRules/AllowAll",
             "name": "AllowAll", "startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"},
            {"id": sub + "/resourceGroups/rg-db/providers/Microsoft.Sql/servers/sql-core-prod/firewallRules/"
                         "AllowAllWindowsAzureIps",
             "name": "AllowAllWindowsAzureIps", "startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"},
            {"id": sub + "/resourceGroups/rg-db/providers/Microsoft.Sql/servers/sql-core-prod/firewallRules/Office",
             "name": "Office", "startIpAddress": "203.0.113.10", "endIpAddress": "203.0.113.10"},
        ],
        "defender_pricing.json": {"value": [
            {"name": "VirtualMachines", "pricingTier": "Standard"}, {"name": "SqlServers", "pricingTier": "Free"},
            {"name": "StorageAccounts", "pricingTier": "Free"}, {"name": "KeyVaults", "pricingTier": "Standard"}]},
        "activity_log_diagnostics.json": {"value": []},
        "keyvault_kv-corp-prod.json": {"name": "kv-corp-prod", "location": "southeastasia",
                                       "properties": {"enableSoftDelete": True, "enablePurgeProtection": True}},
        "keyvault_kv-dev-test.json": {"name": "kv-dev-test", "location": "southeastasia",
                                      "properties": {"enableSoftDelete": True, "enablePurgeProtection": None}},
        "entra_mfa_registration_1.json": {"value": [
            {"userPrincipalName": "cloud.admin@corp.example", "isAdmin": True, "isMfaRegistered": True},
            {"userPrincipalName": "somchai@corp.example", "isAdmin": True, "isMfaRegistered": False},
            {"userPrincipalName": "nida@corp.example", "isAdmin": False, "isMfaRegistered": True},
            {"userPrincipalName": "preecha@corp.example", "isAdmin": False, "isMfaRegistered": False},
            {"userPrincipalName": "kanya@corp.example", "isAdmin": False, "isMfaRegistered": True},
            {"userPrincipalName": "svc.report@corp.example", "isAdmin": False, "isMfaRegistered": False}]},
        "entra_global_admins.json": {"value": [{"userPrincipalName": u} for u in
                                               ("cloud.admin@corp.example", "somchai@corp.example",
                                                "it.manager@corp.example", "ceo@corp.example",
                                                "old.admin@corp.example", "breakglass@corp.example")]},
        "entra_guest_users.json": [{"userPrincipalName": "vendor.ops_partner.example#EXT#@corp.onmicrosoft.com"},
                                   {"userPrincipalName": "auditor_bigfour.example#EXT#@corp.onmicrosoft.com"}],
    }
    return [(json.dumps(v, indent=2).encode(), k) for k, v in files.items()]
