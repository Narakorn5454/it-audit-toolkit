"""
Password Policy Review — เทียบค่านโยบายรหัสผ่านที่ตั้งจริงในระบบกับเกณฑ์มาตรฐาน
=================================================================================
รองรับไฟล์ (ตรวจรูปแบบให้อัตโนมัติ):
  • Windows: secedit /export (.inf), net accounts, Get-ADDefaultDomainPasswordPolicy
  • Linux: /etc/login.defs, /etc/security/pwquality.conf, /etc/security/faillock.conf, PAM (remember=)
  • ระบบงานอื่น: ตาราง system, parameter, value
"""

from __future__ import annotations

import math
import re

import pandas as pd

from .common import AuditError, read_raw, read_text, write_findings_report

PARAMS = {  # รหัส: (ชื่อ, หน่วย)
    "min_length": ("ความยาวรหัสผ่านขั้นต่ำ", "ตัวอักษร"),
    "complexity": ("บังคับความซับซ้อน", "1=เปิด"),
    "max_age_days": ("อายุรหัสผ่านสูงสุด", "วัน (∞ = ไม่หมดอายุ)"),
    "min_age_days": ("อายุรหัสผ่านต่ำสุด", "วัน"),
    "history": ("จำรหัสผ่านเดิมย้อนหลัง", "รหัส"),
    "lockout_threshold": ("ล็อกบัญชีเมื่อผิด", "ครั้ง (0 = ไม่ล็อก)"),
    "lockout_duration_min": ("ระยะเวลาล็อกบัญชี", "นาที"),
    "lockout_window_min": ("ช่วงนับจำนวนครั้งที่ผิด", "นาที"),
    "reversible_encryption": ("เก็บรหัสผ่านแบบถอดกลับได้", "1=เปิด"),
}

# เกณฑ์: param -> (min, max, severity, คำอธิบาย)   None = ไม่กำหนด
BASELINES = {
    "CIS-style (Windows / AD)": {
        "min_length": (14, None, "High", "อย่างน้อย 14 ตัวอักษร"),
        "complexity": (1, 1, "Medium", "ต้องเปิดใช้"),
        "max_age_days": (1, 365, "Medium", "ไม่เกิน 365 วัน และต้องไม่ตั้งเป็นไม่หมดอายุ"),
        "min_age_days": (1, None, "Low", "อย่างน้อย 1 วัน"),
        "history": (24, None, "Medium", "อย่างน้อย 24 รหัส"),
        "lockout_threshold": (1, 5, "High", "1–5 ครั้ง (0 = ไม่ล็อก ถือว่าไม่ผ่าน)"),
        "lockout_duration_min": (15, None, "Medium", "อย่างน้อย 15 นาที"),
        "lockout_window_min": (15, None, "Low", "อย่างน้อย 15 นาที"),
        "reversible_encryption": (0, 0, "High", "ต้องปิด"),
    },
    "นโยบายองค์กรทั่วไป": {
        "min_length": (8, None, "High", "อย่างน้อย 8 ตัวอักษร"),
        "complexity": (1, 1, "Medium", "ต้องเปิดใช้"),
        "max_age_days": (1, 90, "Medium", "ไม่เกิน 90 วัน"),
        "min_age_days": (1, None, "Low", "อย่างน้อย 1 วัน"),
        "history": (5, None, "Medium", "อย่างน้อย 5 รหัส"),
        "lockout_threshold": (1, 5, "High", "1–5 ครั้ง"),
        "lockout_duration_min": (30, None, "Medium", "อย่างน้อย 30 นาที"),
        "lockout_window_min": (30, None, "Low", "อย่างน้อย 30 นาที"),
        "reversible_encryption": (0, 0, "High", "ต้องปิด"),
    },
}
CHECK_IDS = {p: f"PWD-{i + 1:02d}" for i, p in enumerate(PARAMS)}

INF = math.inf


def _num(v) -> float | None:
    v = str(v).strip().lower()
    if v in ("never", "unlimited", "none", "ไม่จำกัด", "ไม่หมดอายุ"):
        return None
    m = re.search(r"-?\d+(\.\d+)?", v)
    return float(m.group()) if m else None


def _timespan_min(v: str) -> float | None:
    """'00:30:00' → 30, '42.00:00:00' → 60480, '1.00:00:00' → 1440"""
    v = v.strip()
    m = re.match(r"^(?:(\d+)\.)?(\d+):(\d+):(\d+)", v)
    if not m:
        return _num(v)
    d, h, mi, s = (int(x) if x else 0 for x in m.groups())
    return d * 1440 + h * 60 + mi + s / 60


def parse_text(text: str) -> tuple[str, dict]:
    """คืนค่า (ชนิดไฟล์, {param: value}) ; value=INF หมายถึงไม่หมดอายุ"""
    out: dict[str, float] = {}
    t = text.replace("\r", "")
    if "[System Access]" in t:                                         # secedit
        kv = dict(re.findall(r"^\s*(\w+)\s*=\s*(-?\d+)", t, re.M))
        m = {"MinimumPasswordLength": "min_length", "PasswordComplexity": "complexity",
             "MaximumPasswordAge": "max_age_days", "MinimumPasswordAge": "min_age_days",
             "PasswordHistorySize": "history", "LockoutBadCount": "lockout_threshold",
             "LockoutDuration": "lockout_duration_min", "ResetLockoutCount": "lockout_window_min",
             "ClearTextPassword": "reversible_encryption"}
        for k, p in m.items():
            if k in kv:
                out[p] = float(kv[k])
        if out.get("max_age_days") in (-1, 0):
            out["max_age_days"] = INF
        return "Windows secedit", out
    if re.search(r"Minimum password length", t, re.I):              # net accounts
        pats = {"min_length": r"Minimum password length\s*:?\s*(.+)",
                "max_age_days": r"Maximum password age.*?:\s*(.+)",
                "min_age_days": r"Minimum password age.*?:\s*(.+)",
                "history": r"Length of password history maintained\s*:?\s*(.+)",
                "lockout_threshold": r"Lockout threshold\s*:?\s*(.+)",
                "lockout_duration_min": r"Lockout duration.*?:\s*(.+)",
                "lockout_window_min": r"Lockout observation window.*?:\s*(.+)"}
        for p, rx in pats.items():
            mm = re.search(rx, t, re.I)
            if mm:
                v = _num(mm.group(1))
                out[p] = (INF if p == "max_age_days" else 0.0) if v is None else v
        return "Windows net accounts", out
    if re.search(r"ComplexityEnabled\s*:", t):                       # Get-ADDefaultDomainPasswordPolicy
        g = dict((k, v.strip()) for k, v in re.findall(r"^(\w+)\s*:\s*(.*)$", t, re.M))
        bool1 = lambda v: 1.0 if v.lower() == "true" else 0.0
        if "MinPasswordLength" in g:
            out["min_length"] = float(g["MinPasswordLength"])
        if "ComplexityEnabled" in g:
            out["complexity"] = bool1(g["ComplexityEnabled"])
        if "PasswordHistoryCount" in g:
            out["history"] = float(g["PasswordHistoryCount"])
        if "LockoutThreshold" in g:
            out["lockout_threshold"] = float(g["LockoutThreshold"])
        if "ReversibleEncryptionEnabled" in g:
            out["reversible_encryption"] = bool1(g["ReversibleEncryptionEnabled"])
        for k, p, div in (("MaxPasswordAge", "max_age_days", 1440), ("MinPasswordAge", "min_age_days", 1440),
                          ("LockoutDuration", "lockout_duration_min", 1), ("LockoutObservationWindow",
                                                                            "lockout_window_min", 1)):
            if k in g:
                v = _timespan_min(g[k])
                out[p] = v / div if v is not None else 0.0
        if out.get("max_age_days") == 0:
            out["max_age_days"] = INF
        return "Active Directory default domain policy", out
    linux = False
    for k, p in (("PASS_MAX_DAYS", "max_age_days"), ("PASS_MIN_DAYS", "min_age_days"),
                 ("PASS_MIN_LEN", "min_length")):
        mm = re.search(rf"^\s*{k}\s+(\d+)", t, re.M)
        if mm:
            linux = True
            out[p] = float(mm.group(1))
    if out.get("max_age_days", 0) >= 99999:
        out["max_age_days"] = INF
    mm = re.search(r"^\s*minlen\s*=\s*(\d+)", t, re.M)
    if mm:
        linux, out["min_length"] = True, float(mm.group(1))
    mc = re.search(r"^\s*minclass\s*=\s*(\d+)", t, re.M)
    credits = re.findall(r"^\s*[dulo]credit\s*=\s*(-?\d+)", t, re.M)
    if mc or credits:
        linux = True
        out["complexity"] = 1.0 if (mc and int(mc.group(1)) >= 3) or sum(int(c) < 0 for c in credits) >= 3 else 0.0
    for k, p, div in (("deny", "lockout_threshold", 1), ("unlock_time", "lockout_duration_min", 60),
                      ("fail_interval", "lockout_window_min", 60)):
        mm = re.search(rf"^\s*{k}\s*=\s*(\d+)", t, re.M)
        if mm:
            linux, out[p] = True, float(mm.group(1)) / div
    mm = re.search(r"remember=(\d+)", t)
    if mm:
        linux, out["history"] = True, float(mm.group(1))
    if linux:
        return "Linux (login.defs / PAM)", out
    raise AuditError("ไม่รู้จักรูปแบบไฟล์นี้ — รองรับ secedit, net accounts, Get-ADDefaultDomainPasswordPolicy, "
                     "login.defs, pwquality.conf, faillock.conf, PAM หรือไฟล์ตาราง system/parameter/value")


PARAM_SYNONYMS = {
    "min_length": ["minimum password length", "min length", "minlen", "ความยาวขั้นต่ำ"],
    "complexity": ["complexity", "password complexity", "ความซับซ้อน"],
    "max_age_days": ["maximum password age", "max age", "password expiry", "อายุสูงสุด"],
    "min_age_days": ["minimum password age", "min age", "อายุต่ำสุด"],
    "history": ["password history", "history", "remember", "ประวัติรหัสผ่าน"],
    "lockout_threshold": ["lockout threshold", "max failed attempts", "ล็อกเมื่อผิด"],
    "lockout_duration_min": ["lockout duration", "ระยะเวลาล็อก"],
    "lockout_window_min": ["lockout window", "reset lockout counter", "observation window"],
    "reversible_encryption": ["reversible encryption", "store passwords using reversible encryption"],
}


def parse_table(df: pd.DataFrame) -> dict[str, dict]:
    """ตาราง system, parameter, value → {system: {param: value}}"""
    df = df.rename(columns=lambda c: str(c).strip().lower())
    if not {"parameter", "value"} <= set(df.columns):
        raise AuditError("ไฟล์ตารางต้องมีคอลัมน์ parameter และ value (และ system ถ้ามีหลายระบบ)")
    if "system" not in df:
        df["system"] = "ระบบงาน"
    out: dict[str, dict] = {}
    for r in df.itertuples(index=False):
        key = str(r.parameter).strip().lower()
        p = key if key in PARAMS else next((k for k, syn in PARAM_SYNONYMS.items() if key in syn), None)
        if not p:
            continue
        v = str(r.value).strip().lower()
        if v in ("yes", "true", "enabled", "on", "เปิด", "ใช่"):
            val = 1.0
        elif v in ("no", "false", "disabled", "off", "ปิด", "ไม่"):
            val = 0.0
        else:
            n = _num(v)
            val = (INF if p == "max_age_days" else 0.0) if n is None else n
        out.setdefault(str(r.system).strip(), {})[p] = val
    return out


def load_files(files: list[tuple[str, object, str]], skipped: list | None = None) -> list[dict]:
    """files: [(system_name, src, filename)] → [{system, source, values}] (ไฟล์ของระบบเดียวกันจะถูกรวม)
    ไฟล์ที่ไม่ใช่นโยบายรหัสผ่านจะถูกข้ามและบันทึกใน skipped"""
    merged: dict[str, dict] = {}
    for system, src, fname in files:
        if str(fname).lower().endswith((".xlsx", ".csv")):
            for s, vals in parse_table(read_raw(src, fname)).items():
                e = merged.setdefault(s, {"system": s, "source": set(), "values": {}})
                e["source"].add("ตาราง"), e["values"].update(vals)
            continue
        try:
            kind, vals = parse_text(read_text(src, fname))
        except AuditError:
            if skipped is None:
                raise
            skipped.append(fname)
            continue
        e = merged.setdefault(system, {"system": system, "source": set(), "values": {}})
        e["source"].add(kind)
        e["values"].update(vals)
    for e in merged.values():
        e["source"] = ", ".join(sorted(e["source"]))
    if not merged:
        raise AuditError("ไม่พบไฟล์นโยบายรหัสผ่านที่อ่านได้")
    return list(merged.values())


def _fmt(v):
    if v is None:
        return "ไม่พบการตั้งค่า"
    if v == INF:
        return "∞ (ไม่หมดอายุ)"
    return f"{v:g}"


def evaluate(systems: list[dict], baseline: dict) -> dict:
    rows, findings = [], []
    for s in systems:
        for p, (lo, hi, sev, desc) in baseline.items():
            v = s["values"].get(p)
            if v is None:
                result = "Not found"
            else:
                ok = (lo is None or v >= lo) and (hi is None or v <= hi)
                result = "Pass" if ok else "Fail"
            rows.append({"system": s["system"], "check_id": CHECK_IDS[p], "parameter": PARAMS[p][0],
                         "actual": _fmt(v), "expected": desc, "result": result, "severity": sev})
            if result != "Pass":
                findings.append({"check_id": CHECK_IDS[p], "severity": sev if result == "Fail" else "Low",
                                 "system": s["system"], "parameter": PARAMS[p][0], "actual": _fmt(v),
                                 "expected": desc,
                                 "detail": "ไม่พบการตั้งค่าในไฟล์ที่ได้รับ ให้ขอหลักฐานเพิ่ม" if result == "Not found"
                                 else f"ตั้งค่าไว้ {_fmt(v)} {PARAMS[p][1]} ไม่เป็นไปตามเกณฑ์ ({desc})",
                                 "recommendation": f"ปรับ{PARAMS[p][0]}ให้เป็นไปตามเกณฑ์: {desc}"})
    matrix = pd.DataFrame(rows)
    pivot = matrix.pivot_table(index="parameter", columns="system", values="actual", aggfunc="first").reset_index() \
        if not matrix.empty else pd.DataFrame()
    f = pd.DataFrame(findings)
    if not f.empty:
        from .common import sort_findings
        f = sort_findings(f, ["system"])
    score = (matrix.assign(ok=matrix["result"] == "Pass").groupby("system")["ok"].mean().mul(100).round(0)
             .rename("compliance_pct").reset_index()) if not matrix.empty else pd.DataFrame()
    return {"matrix": matrix, "pivot": pivot, "findings": f, "score": score}


def checks_for(baseline: dict) -> dict:
    return {CHECK_IDS[p]: (PARAMS[p][0], sev, f"ปรับให้เป็นไปตามเกณฑ์: {desc}", desc)
            for p, (lo, hi, sev, desc) in baseline.items()}


COL_TH = {"system": "ระบบ", "parameter": "พารามิเตอร์", "actual": "ค่าที่ตั้งไว้", "expected": "เกณฑ์",
          "result": "ผล", "compliance_pct": "% ผ่านเกณฑ์"}


def write_report(res: dict, out, baseline_name: str, org: str = "(ไม่ระบุ)", baseline: dict | None = None):
    info = [("องค์กร", org), ("เกณฑ์ที่ใช้", baseline_name),
            ("ระบบที่ตรวจ", ", ".join(res["score"]["system"]) if not res["score"].empty else "-")]
    write_findings_report(out, "รายงานการตรวจสอบนโยบายรหัสผ่าน (Password Policy Review)", info,
                          checks_for(baseline or BASELINES[baseline_name]),
                          res["findings"], COL_TH, per_check_sheets=False,
                          extra_sheets={"Compliance Matrix": res["matrix"], "Settings by System": res["pivot"],
                                        "Score": res["score"]})


# ----------------------------------------------------------------------------
# ไฟล์ตัวอย่าง (หน้าตาเหมือนไฟล์จริงที่ได้จากคำสั่ง)
# ----------------------------------------------------------------------------

DEMO_FILES = {
    "AD-Domain (Get-ADDefaultDomainPasswordPolicy)": ("ad_policy.txt", """
ComplexityEnabled           : True
DistinguishedName           : DC=corp,DC=example,DC=co,DC=th
LockoutDuration             : 00:30:00
LockoutObservationWindow    : 00:30:00
LockoutThreshold            : 0
MaxPasswordAge              : 42.00:00:00
MinPasswordAge              : 1.00:00:00
MinPasswordLength           : 8
PasswordHistoryCount        : 24
ReversibleEncryptionEnabled : False
"""),
    "FileServer01 (net accounts)": ("net_accounts.txt", """
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Unlimited
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
"""),
    "WebServer01 (secedit)": ("secpol.inf", """[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
ClearTextPassword = 0
EnableGuestAccount = 0
"""),
    "AppServer-Linux (login.defs + pwquality + faillock)": ("linux_policy.txt", """
# /etc/login.defs
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
# /etc/security/pwquality.conf
minlen = 12
minclass = 3
# /etc/security/faillock.conf
deny = 3
unlock_time = 900
fail_interval = 900
# /etc/pam.d/common-password
password required pam_pwhistory.so remember=5 use_authtok
"""),
}


def demo_systems() -> list[dict]:
    return load_files([(name.split(" (")[0], content.encode(), fname)
                       for name, (fname, content) in DEMO_FILES.items()])


def demo_table() -> pd.DataFrame:
    return pd.DataFrame([("ERP-SAP", "min_length", 8), ("ERP-SAP", "complexity", "Yes"),
                         ("ERP-SAP", "max_age_days", 90), ("ERP-SAP", "lockout_threshold", 5),
                         ("ERP-SAP", "history", 5)], columns=["system", "parameter", "value"])
