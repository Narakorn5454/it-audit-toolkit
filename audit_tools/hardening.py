"""
System Hardening Review — ตรวจค่าความปลอดภัยของเครื่อง Windows / Linux เทียบเกณฑ์แนว CIS Benchmark
=================================================================================================
รับไฟล์ที่ได้จากสคริปต์เก็บข้อมูล (scripts/collect_windows.ps1, scripts/collect_linux.sh)
ระบบตรวจชนิดไฟล์ให้อัตโนมัติ:
  Linux  : sshd_config, /etc/passwd, /etc/group, sudoers
  Windows: secedit export (.inf), auditpol /get /category:*

หมายเหตุ: เกณฑ์เป็น "แนว CIS" ที่คัดเฉพาะข้อสำคัญ ควรปรับให้ตรงกับเวอร์ชัน Benchmark และนโยบายองค์กร
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import pandas as pd

from .common import AuditError, read_text, sort_findings, write_findings_report


@dataclass
class Rule:
    rule_id: str
    platform: str
    category: str
    setting: str
    expected: str
    severity: str
    recommendation: str


RULES = [
    # --- Linux SSH ---
    Rule("SSH-01", "Linux", "SSH", "PermitRootLogin", "no", "High", "ตั้ง PermitRootLogin no ให้ผู้ดูแลเข้าด้วยบัญชีส่วนตัวแล้วใช้ sudo"),
    Rule("SSH-02", "Linux", "SSH", "PermitEmptyPasswords", "no", "High", "ตั้ง PermitEmptyPasswords no"),
    Rule("SSH-03", "Linux", "SSH", "MaxAuthTries", "≤ 4", "Medium", "ตั้ง MaxAuthTries 4 หรือน้อยกว่า"),
    Rule("SSH-04", "Linux", "SSH", "LoginGraceTime", "1–60 วินาที", "Low", "ตั้ง LoginGraceTime 60"),
    Rule("SSH-05", "Linux", "SSH", "ClientAliveInterval", "1–900 วินาที", "Medium", "ตั้งให้ตัดการเชื่อมต่อที่ไม่ใช้งาน"),
    Rule("SSH-06", "Linux", "SSH", "X11Forwarding", "no", "Low", "ปิด X11Forwarding ถ้าไม่จำเป็น"),
    Rule("SSH-07", "Linux", "SSH", "HostbasedAuthentication", "no", "Medium", "ปิด HostbasedAuthentication"),
    Rule("SSH-08", "Linux", "SSH", "IgnoreRhosts", "yes", "Medium", "ตั้ง IgnoreRhosts yes"),
    Rule("SSH-09", "Linux", "SSH", "Banner", "กำหนดข้อความแจ้งเตือน", "Low", "ตั้ง Banner แจ้งเงื่อนไขการใช้งาน"),
    # --- Linux accounts ---
    Rule("NIX-01", "Linux", "Accounts", "บัญชี UID 0", "มีเฉพาะ root", "High", "ลบหรือเปลี่ยน UID ของบัญชีอื่นที่เป็น 0"),
    Rule("NIX-02", "Linux", "Accounts", "UID ซ้ำ", "ไม่มี", "Medium", "กำหนด UID ไม่ซ้ำกัน เพื่อให้ตรวจย้อนได้รายบุคคล"),
    Rule("NIX-03", "Linux", "Accounts", "บัญชีไม่มีรหัสผ่าน (passwd field ว่าง)", "ไม่มี", "High", "กำหนดรหัสผ่านหรือล็อกบัญชี"),
    Rule("NIX-04", "Linux", "Accounts", "บัญชีระบบที่มี shell เข้าใช้งานได้", "ไม่มี", "Low", "ตั้ง shell เป็น /sbin/nologin"),
    Rule("NIX-05", "Linux", "Privilege", "สมาชิกกลุ่มสิทธิ์สูง (sudo/wheel/adm/docker)", "ทบทวนรายชื่อ", "Review", "ยืนยันความจำเป็นกับเจ้าของระบบ"),
    Rule("NIX-06", "Linux", "Privilege", "sudo แบบไม่ต้องใส่รหัสผ่าน (NOPASSWD)", "ไม่มี", "Medium", "ยกเลิก NOPASSWD ยกเว้นบัญชีบริการที่จำกัดคำสั่ง"),
    Rule("NIX-07", "Linux", "Privilege", "sudo สิทธิ์ ALL ให้ผู้ใช้รายบุคคล", "ทบทวนรายชื่อ", "Review", "ให้สิทธิ์ผ่านกลุ่ม และจำกัดคำสั่งตามหน้าที่"),
    # --- Windows ---
    Rule("WIN-01", "Windows", "Accounts", "Guest account", "Disabled (0)", "High", "ปิดบัญชี Guest"),
    Rule("WIN-02", "Windows", "Accounts", "Anonymous SID/Name translation", "Disabled (0)", "Medium", "ปิด LSAAnonymousNameLookup"),
    Rule("WIN-03", "Windows", "Accounts", "Rename Administrator account", "ไม่ใช้ชื่อ Administrator", "Low", "เปลี่ยนชื่อบัญชี Administrator"),
    Rule("WIN-04", "Windows", "Security Options", "LAN Manager authentication level", "5 (NTLMv2 only, refuse LM & NTLM)", "High", "ตั้ง LmCompatibilityLevel = 5"),
    Rule("WIN-05", "Windows", "Security Options", "Do not store LAN Manager hash", "Enabled (1)", "High", "เปิด NoLMHash"),
    Rule("WIN-06", "Windows", "Security Options", "Restrict anonymous access (RestrictAnonymous)", "Enabled (1)", "Medium", "ตั้ง RestrictAnonymous = 1"),
    Rule("WIN-07", "Windows", "Security Options", "Restrict anonymous SAM enumeration", "Enabled (1)", "Medium", "ตั้ง RestrictAnonymousSAM = 1"),
    Rule("WIN-08", "Windows", "Security Options", "User Account Control (EnableLUA)", "Enabled (1)", "High", "เปิด UAC"),
    Rule("WIN-09", "Windows", "Security Options", "Machine inactivity limit", "1–900 วินาที", "Medium", "ตั้ง InactivityTimeoutSecs ไม่เกิน 900"),
    Rule("WIN-10", "Windows", "Security Options", "SMB server: digitally sign (always)", "Enabled (1)", "Medium", "เปิด RequireSecuritySignature"),
    Rule("WIN-11", "Windows", "User Rights", "Debug programs (SeDebugPrivilege)", "Administrators เท่านั้น", "Medium", "จำกัดสิทธิ์ Debug programs"),
    Rule("WIN-12", "Windows", "User Rights", "Allow log on through Remote Desktop", "ไม่รวม Everyone / Users", "Medium", "จำกัดกลุ่มที่ RDP ได้"),
    Rule("WIN-13", "Windows", "User Rights", "Access this computer from the network", "ไม่รวม Everyone", "Medium", "ใช้ Authenticated Users แทน Everyone"),
]

AUDIT_RULES = [  # (id, subcategory, ต้องมี Success, ต้องมี Failure, severity)
    ("AUD-01", "Credential Validation", True, True, "Medium"),
    ("AUD-02", "Logon", True, True, "High"),
    ("AUD-03", "Account Lockout", False, True, "Medium"),
    ("AUD-04", "Special Logon", True, False, "Medium"),
    ("AUD-05", "User Account Management", True, True, "High"),
    ("AUD-06", "Security Group Management", True, False, "Medium"),
    ("AUD-07", "Audit Policy Change", True, False, "High"),
    ("AUD-08", "Sensitive Privilege Use", True, True, "Medium"),
    ("AUD-09", "Process Creation", True, False, "Low"),
]
for aid, sub, s, f, sev in AUDIT_RULES:
    exp = " and ".join(x for x, need in (("Success", s), ("Failure", f)) if need)
    RULES.append(Rule(aid, "Windows", "Audit Policy", f"Audit {sub}", exp, sev, f"ตั้ง Audit {sub} ให้มี {exp}"))

RULE_BY_ID = {r.rule_id: r for r in RULES}
CHECKS = {r.rule_id: (f"[{r.platform}] {r.setting}", r.severity, r.recommendation, f"เกณฑ์: {r.expected}")
          for r in RULES}

PRIV_GROUPS = {"sudo", "wheel", "adm", "admin", "docker", "root", "lxd"}
SID = {"*S-1-5-32-544": "Administrators", "*S-1-5-32-545": "Users", "*S-1-1-0": "Everyone",
       "*S-1-5-11": "Authenticated Users", "*S-1-5-32-555": "Remote Desktop Users",
       "*S-1-5-32-551": "Backup Operators", "*S-1-5-32-546": "Guests"}


# ----------------------------------------------------------------------------
# ตรวจชนิดไฟล์
# ----------------------------------------------------------------------------

def detect(text: str, fname: str = "") -> str:
    f = fname.lower()
    if "[System Access]" in text or "[Privilege Rights]" in text or "[Registry Values]" in text:
        return "secedit"
    if re.search(r"System audit policy|Category/Subcategory|Logon/Logoff", text):
        return "auditpol"
    if "sshd" in f or re.search(r"^\s*#?\s*(?:PermitRootLogin|PasswordAuthentication|ChallengeResponse)",
                                text, re.M | re.I):
        return "sshd_config"
    if "sudoers" in f or re.search(r"^\s*(%?\w[\w.-]*)\s+ALL\s*=", text, re.M):
        return "sudoers"
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
    if lines and all(l.count(":") >= 6 for l in lines[:20]):
        return "passwd"
    if lines and all(l.count(":") == 3 for l in lines[:20]):
        return "group"
    raise AuditError(f"ไม่รู้จักชนิดไฟล์ {fname} — รองรับ sshd_config, passwd, group, sudoers, "
                     "secedit .inf, auditpol")


# ----------------------------------------------------------------------------
# ตรวจแต่ละชนิดไฟล์ → list ของ (rule_id, actual, result, detail)
# ----------------------------------------------------------------------------

def _int(v, default=None):
    m = re.search(r"-?\d+", str(v))
    return int(m.group()) if m else default


def check_sshd(text: str):
    cfg = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.lower().startswith("match "):
            if line.lower().startswith("match "):
                break                                # ค่าหลัง Match ไม่ใช่ค่ากลาง
            continue
        k, _, v = line.partition(" ")
        cfg.setdefault(k.lower(), v.strip())        # sshd ใช้ค่าแรกที่พบ
    defaults = {"permitrootlogin": "prohibit-password", "permitemptypasswords": "no", "maxauthtries": "6",
                "logingracetime": "120", "clientaliveinterval": "0", "x11forwarding": "no",
                "hostbasedauthentication": "no", "ignorerhosts": "yes", "banner": "none"}
    get = lambda k: (cfg.get(k), k not in cfg)
    out = []

    def add(rid, key, ok_fn):
        v, is_default = get(key)
        val = v if v is not None else defaults[key]
        ok = ok_fn(val)
        out.append((rid, f"{val}" + (" (ค่า default)" if is_default else ""), "Pass" if ok else "Fail",
                    "" if ok else f"{RULE_BY_ID[rid].setting} = {val}" + (" (ไม่ได้ตั้งค่า ใช้ค่า default)" if is_default else "")))

    add("SSH-01", "permitrootlogin", lambda v: v.lower() == "no")
    add("SSH-02", "permitemptypasswords", lambda v: v.lower() == "no")
    add("SSH-03", "maxauthtries", lambda v: (_int(v, 99) or 99) <= 4)
    add("SSH-04", "logingracetime", lambda v: 1 <= (_int(v, 0) or 0) <= 60)
    add("SSH-05", "clientaliveinterval", lambda v: 1 <= (_int(v, 0) or 0) <= 900)
    add("SSH-06", "x11forwarding", lambda v: v.lower() == "no")
    add("SSH-07", "hostbasedauthentication", lambda v: v.lower() == "no")
    add("SSH-08", "ignorerhosts", lambda v: v.lower() == "yes")
    add("SSH-09", "banner", lambda v: v.lower() not in ("none", ""))
    return out


def check_passwd(text: str):
    users = []
    for l in text.splitlines():
        p = l.strip().split(":")
        if len(p) >= 7 and not l.startswith("#"):
            users.append({"name": p[0], "pw": p[1], "uid": _int(p[2], -1), "shell": p[6]})
    out = []
    uid0 = [u["name"] for u in users if u["uid"] == 0 and u["name"] != "root"]
    out.append(("NIX-01", ", ".join(["root"] + uid0), "Fail" if uid0 else "Pass",
                f"บัญชี UID 0 นอกจาก root: {', '.join(uid0)}" if uid0 else ""))
    seen = {}
    for u in users:
        seen.setdefault(u["uid"], []).append(u["name"])
    dup = {k: v for k, v in seen.items() if len(v) > 1}
    out.append(("NIX-02", f"{len(dup)} UID ซ้ำ", "Fail" if dup else "Pass",
                "; ".join(f"UID {k}: {', '.join(v)}" for k, v in dup.items())))
    empty = [u["name"] for u in users if u["pw"] == ""]
    out.append(("NIX-03", f"{len(empty)} บัญชี", "Fail" if empty else "Pass", ", ".join(empty)))
    ok_sys = {"root", "sync", "shutdown", "halt"}
    nologin = ("nologin", "/false", "/bin/sync", "/sbin/shutdown", "/sbin/halt")
    sys_shell = [f"{u['name']} ({u['shell']})" for u in users
                 if 0 < u["uid"] < 1000 and u["name"] not in ok_sys and not u["shell"].endswith(nologin)]
    out.append(("NIX-04", f"{len(sys_shell)} บัญชี", "Fail" if sys_shell else "Pass", ", ".join(sys_shell)))
    return out


def check_group(text: str):
    members = []
    for l in text.splitlines():
        p = l.strip().split(":")
        if len(p) == 4 and p[0] in PRIV_GROUPS and p[3].strip():
            members.append(f"{p[0]}: {p[3]}")
    return [("NIX-05", "; ".join(members) or "ไม่มีสมาชิก", "Review" if members else "Pass", "; ".join(members))]


def check_sudoers(text: str):
    nopw, all_users = [], []
    for l in text.splitlines():
        s = l.split("#", 1)[0].strip()
        if not s or s.startswith(("Defaults", "Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias", "@include", "#include")):
            continue
        if "NOPASSWD" in s:
            nopw.append(s)
        who = s.split()[0]
        if re.search(r"=\s*(\([^)]*\)\s*)?(NOPASSWD:\s*)?ALL\s*$", s) and not who.startswith("%") and who != "root":
            all_users.append(s)
    return [("NIX-06", f"{len(nopw)} รายการ", "Fail" if nopw else "Pass", " | ".join(nopw)),
            ("NIX-07", f"{len(all_users)} รายการ", "Review" if all_users else "Pass", " | ".join(all_users))]


def _inf_sections(text: str) -> dict[str, dict[str, str]]:
    sec, cur = {}, None
    for l in text.splitlines():
        l = l.strip()
        m = re.match(r"^\[(.+)\]$", l)
        if m:
            cur = m.group(1)
            sec[cur] = {}
        elif cur and "=" in l:
            k, _, v = l.partition("=")
            sec[cur][k.strip()] = v.strip().strip('"')
    return sec


def check_secedit(text: str):
    sec = _inf_sections(text)
    sa, reg, pr = sec.get("System Access", {}), sec.get("Registry Values", {}), sec.get("Privilege Rights", {})
    out = []

    def sa_rule(rid, key, ok_fn, fmt=lambda v: v):
        v = sa.get(key)
        if v is None:
            out.append((rid, "ไม่พบ", "Not found", "ไม่พบค่าในไฟล์"))
        else:
            ok = ok_fn(v)
            out.append((rid, fmt(v), "Pass" if ok else "Fail", "" if ok else f"{key} = {v}"))

    sa_rule("WIN-01", "EnableGuestAccount", lambda v: v == "0")
    sa_rule("WIN-02", "LSAAnonymousNameLookup", lambda v: v == "0")
    sa_rule("WIN-03", "NewAdministratorName", lambda v: v.lower() != "administrator")
    base_lsa = r"MACHINE\System\CurrentControlSet\Control\Lsa"
    base_sys = r"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    base_smb = r"MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters"
    regmap = {k.lower(): v for k, v in reg.items()}

    def reg_rule(rid, path, ok_fn):
        raw = regmap.get(path.lower())
        if raw is None:
            out.append((rid, "ไม่พบ", "Not found", f"ไม่ได้กำหนดผ่านนโยบาย ({path.split(chr(92))[-1]})"))
            return
        v = _int(raw.split(",", 1)[-1])
        ok = v is not None and ok_fn(v)
        out.append((rid, str(v), "Pass" if ok else "Fail", "" if ok else f"{path.split(chr(92))[-1]} = {v}"))

    reg_rule("WIN-04", base_lsa + r"\LmCompatibilityLevel", lambda v: v >= 5)
    reg_rule("WIN-05", base_lsa + r"\NoLMHash", lambda v: v == 1)
    reg_rule("WIN-06", base_lsa + r"\RestrictAnonymous", lambda v: v >= 1)
    reg_rule("WIN-07", base_lsa + r"\RestrictAnonymousSAM", lambda v: v == 1)
    reg_rule("WIN-08", base_sys + r"\EnableLUA", lambda v: v == 1)
    reg_rule("WIN-09", base_sys + r"\InactivityTimeoutSecs", lambda v: 1 <= v <= 900)
    reg_rule("WIN-10", base_smb + r"\RequireSecuritySignature", lambda v: v == 1)

    def holders(key):
        raw = pr.get(key, "")
        return [SID.get(x.strip(), x.strip()) for x in raw.split(",") if x.strip()]

    if pr:
        dbg = holders("SeDebugPrivilege")
        ok = set(dbg) <= {"Administrators"}
        out.append(("WIN-11", ", ".join(dbg) or "ไม่มี", "Pass" if ok else "Fail",
                    "" if ok else f"ผู้ถือสิทธิ์: {', '.join(dbg)}"))
        rdp = holders("SeRemoteInteractiveLogonRight")
        bad = [x for x in rdp if x in ("Everyone", "Users")]
        out.append(("WIN-12", ", ".join(rdp) or "ไม่มี", "Fail" if bad else "Pass",
                    f"มีกลุ่ม {', '.join(bad)}" if bad else ""))
        net = holders("SeNetworkLogonRight")
        out.append(("WIN-13", ", ".join(net) or "ไม่มี", "Fail" if "Everyone" in net else "Pass",
                    "มี Everyone" if "Everyone" in net else ""))
    return out


def check_auditpol(text: str):
    settings = {}
    for l in text.splitlines():
        m = re.match(r"^\s{2,}(.+?)\s{2,}(Success and Failure|Success|Failure|No Auditing)\s*$", l)
        if m:
            settings[m.group(1).strip().lower()] = m.group(2)
    out = []
    for aid, sub, need_s, need_f, _ in AUDIT_RULES:
        v = settings.get(sub.lower())
        if v is None:
            out.append((aid, "ไม่พบ", "Not found", "ไม่พบ subcategory (ไฟล์อาจเป็นภาษาอื่น)"))
            continue
        ok = (not need_s or "Success" in v) and (not need_f or "Failure" in v)
        out.append((aid, v, "Pass" if ok else "Fail", "" if ok else f"ตั้งไว้ '{v}'"))
    return out


CHECKERS = {"sshd_config": check_sshd, "passwd": check_passwd, "group": check_group,
            "sudoers": check_sudoers, "secedit": check_secedit, "auditpol": check_auditpol}


def review(files: list[tuple[str, object, str]]) -> dict:
    """files: [(host, src, filename)]"""
    rows, kinds = [], []
    for host, src, fname in files:
        text = read_text(src, fname)
        try:
            kind = detect(text, fname)
        except AuditError:
            kinds.append({"host": host, "file": fname, "type": "ข้าม (ไม่ใช่ไฟล์ที่ตรวจในหน้านี้)"})
            continue
        kinds.append({"host": host, "file": fname, "type": kind})
        for rid, actual, result, detail in CHECKERS[kind](text):
            r = RULE_BY_ID[rid]
            rows.append({"host": host, "check_id": rid, "platform": r.platform, "category": r.category,
                         "setting": r.setting, "expected": r.expected, "actual": actual, "result": result,
                         "severity": r.severity, "detail": detail, "source_file": fname})
    matrix = pd.DataFrame(rows)
    if matrix.empty:
        raise AuditError("ไม่พบไฟล์ที่ตรวจได้ — รองรับ sshd_config, passwd, group, sudoers, "
                         "secedit (.inf) และ auditpol")
    fails = matrix[matrix["result"].isin(["Fail", "Review"])].copy()
    fails["recommendation"] = fails["check_id"].map(lambda c: RULE_BY_ID[c].recommendation)
    fails["severity"] = fails.apply(lambda r: "Review" if r["result"] == "Review" else r["severity"], axis=1)
    findings = sort_findings(fails[["check_id", "severity", "host", "category", "setting", "expected", "actual",
                                    "detail", "recommendation"]], ["host"])
    scored = matrix[matrix["result"].isin(["Pass", "Fail"])]
    score = (scored.assign(ok=scored["result"] == "Pass").groupby(["host", "category"])["ok"]
             .agg(["sum", "count"]).reset_index())
    score["compliance_pct"] = (score["sum"] / score["count"] * 100).round(0)
    score = score.rename(columns={"sum": "passed", "count": "tested"})
    host_score = (scored.assign(ok=scored["result"] == "Pass").groupby("host")["ok"].mean().mul(100).round(0)
                  .rename("compliance_pct").reset_index())
    return {"matrix": matrix, "findings": findings, "score": score, "host_score": host_score,
            "files": pd.DataFrame(kinds)}


COL_TH = {"host": "เครื่อง", "platform": "แพลตฟอร์ม", "category": "หมวด", "setting": "การตั้งค่า",
          "expected": "เกณฑ์", "actual": "ค่าที่พบ", "result": "ผล", "source_file": "ไฟล์",
          "passed": "ผ่าน", "tested": "ทดสอบ", "compliance_pct": "% ผ่านเกณฑ์", "file": "ไฟล์", "type": "ชนิด"}


def write_report(res: dict, out, org: str = "(ไม่ระบุ)"):
    hs = res["host_score"]
    info = [("องค์กร", org), ("จำนวนเครื่อง", len(hs)),
            ("% ผ่านเกณฑ์ (รายเครื่อง)", ", ".join(f"{r.host} {r.compliance_pct:.0f}%" for r in hs.itertuples()))]
    tested = set(res["matrix"]["check_id"])
    checks = {k: v for k, v in CHECKS.items() if k in tested}
    write_findings_report(out, "รายงานการตรวจสอบการตั้งค่าความปลอดภัยของระบบ (System Hardening)", info, checks,
                          res["findings"], COL_TH, per_check_sheets=False,
                          extra_sheets={"Compliance Matrix": res["matrix"], "Score by Category": res["score"],
                                        "Files Reviewed": res["files"]},
                          note="เกณฑ์เป็นแนว CIS Benchmark ที่คัดเฉพาะข้อสำคัญ — ควรยืนยันกับเวอร์ชัน Benchmark "
                               "และนโยบายขององค์กรก่อนสรุปผล")


# ----------------------------------------------------------------------------
# ไฟล์ตัวอย่าง
# ----------------------------------------------------------------------------

DEMO = {
    ("web-prod-01", "sshd_config"): """# $OpenBSD: sshd_config
Port 22
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 6
X11Forwarding yes
ClientAliveInterval 300
Subsystem sftp /usr/lib/openssh/sftp-server
""",
    ("web-prod-01", "passwd"): """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/bin/bash
postgres:x:112:120:PostgreSQL:/var/lib/postgresql:/bin/bash
backdoor:x:0:0::/home/backdoor:/bin/bash
somchai:x:1001:1001:Somchai:/home/somchai:/bin/bash
nida:x:1002:1002:Nida:/home/nida:/bin/bash
tempuser::1003:1003::/home/tempuser:/bin/bash
olddev:x:1002:1002:Old dev:/home/olddev:/bin/bash
""",
    ("web-prod-01", "group"): """root:x:0:
sudo:x:27:somchai,nida,olddev
docker:x:998:somchai,tempuser
users:x:100:
""",
    ("web-prod-01", "sudoers"): """Defaults env_reset
root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
deploy  ALL=(ALL) NOPASSWD: ALL
nida    ALL=(ALL) ALL
""",
    ("DC01", "secpol.inf"): """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 8
EnableGuestAccount = 1
LSAAnonymousNameLookup = 0
NewAdministratorName = "Administrator"
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,3
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=4,0
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs=4,0
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,1
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
""",
    ("DC01", "auditpol.txt"): """System audit policy
Category/Subcategory                      Setting
System
  Security State Change                   Success
Logon/Logoff
  Logon                                   Success
  Logoff                                  Success
  Account Lockout                         Success
  Special Logon                           Success
Privilege Use
  Sensitive Privilege Use                 No Auditing
Detailed Tracking
  Process Creation                        No Auditing
Policy Change
  Audit Policy Change                     Success
Account Management
  User Account Management                 Success and Failure
  Security Group Management               Success
Account Logon
  Credential Validation                   Success and Failure
""",
}


def demo_files():
    return [(host, content.encode(), fname) for (host, fname), content in DEMO.items()]
