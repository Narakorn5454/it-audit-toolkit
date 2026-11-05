#!/usr/bin/env python3
"""
User Access Review Tool สำหรับงาน IT Audit
=========================================
เปรียบเทียบรายชื่อพนักงานจาก HR กับรายชื่อ User ในระบบ
แล้วออกรายงาน Excel แสดงข้อตรวจพบ (Findings)

การตรวจสอบที่ทำ:
  UAR-01  User ของพนักงานที่ลาออกแล้ว แต่บัญชียังเปิดใช้งาน
  UAR-02  User ที่ไม่พบในรายชื่อ HR (Orphan account)
  UAR-03  บัญชีกลาง / บัญชีใช้ร่วมกัน (Generic / Shared account)
  UAR-04  บัญชีไม่ได้ใช้งานเกินกำหนด (Dormant account)
  UAR-05  พนักงาน 1 คนมีหลายบัญชี (Duplicate account)
  UAR-06  ผู้มีสิทธิ์ระดับสูง (Privileged access) ให้ทบทวนความเหมาะสม
  UAR-07  สิทธิ์ขัดแย้งกัน (Segregation of Duties conflict)
  UAR-08  เข้าใช้งานหลังวันที่ลาออก (Login after termination)

วิธีใช้:
  python user_access_review.py --hr hr.xlsx --users users.xlsx
  python user_access_review.py --hr hr.csv --users users.csv --sod sod_rules.csv --dormant-days 60
  python user_access_review.py --demo          (สร้างข้อมูลตัวอย่างแล้วรันให้ดู)

ต้องใช้: pandas, openpyxl
เวอร์ชันหน้าเว็บ: ดู app.py (streamlit run app.py)
"""

from __future__ import annotations

import argparse
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import pandas as pd
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

try:
    from .common import AuditError
except ImportError:  # รันไฟล์นี้เดี่ยว ๆ
    from common import AuditError

__version__ = "1.1.0"

# ----------------------------------------------------------------------------
# ค่าตั้งต้น (ปรับได้ตามนโยบายองค์กร)
# ----------------------------------------------------------------------------

HR_REQUIRED = ["employee_id", "full_name", "department", "position", "status"]
USER_REQUIRED = ["username", "employee_id", "role", "account_status", "last_login"]

ACTIVE_ACCOUNT_VALUES = {"enabled", "active", "เปิด", "ใช้งาน", "1", "true", "yes", "y"}
RESIGNED_HR_VALUES = {"resigned", "terminated", "inactive", "ลาออก", "พ้นสภาพ", "0", "false"}

GENERIC_KEYWORDS = [
    "admin", "test", "temp", "guest", "user", "shared", "service", "svc",
    "demo", "training", "support", "helpdesk", "backup", "batch", "system",
]

PRIVILEGED_KEYWORDS = [
    "admin", "administrator", "superuser", "root", "dba", "sysadmin",
    "security", "full access", "super",
]

# กฎ SoD ตั้งต้น: (สิทธิ์ A, สิทธิ์ B, ความเสี่ยง)
DEFAULT_SOD_RULES = [
    ("Create Vendor", "Approve Payment", "สร้างผู้ขายปลอมแล้วอนุมัติจ่ายเงินเองได้"),
    ("Create PO", "Approve PO", "ออกและอนุมัติใบสั่งซื้อเองได้"),
    ("Approve PO", "Goods Receipt", "อนุมัติซื้อและรับของเองได้"),
    ("Create Payment", "Approve Payment", "จ่ายเงินและอนุมัติการจ่ายเองได้"),
    ("Developer", "Production Deploy", "พัฒนาและนำโปรแกรมขึ้นระบบจริงได้เอง"),
    ("User Admin", "Approve Access", "สร้าง user และอนุมัติสิทธิ์ให้ตัวเองได้"),
    ("Journal Entry", "Approve Journal", "บันทึกและอนุมัติรายการบัญชีเองได้"),
    ("Payroll Maintain", "Payroll Approve", "แก้ไขและอนุมัติเงินเดือนเองได้"),
]

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Review": 3}

CHECKS = {
    "UAR-01": ("User ของพนักงานที่ลาออกแล้วแต่ยังเปิดใช้งาน", "High",
               "ปิดบัญชีทันที และตรวจสอบกิจกรรมหลังวันลาออก"),
    "UAR-02": ("User ที่ไม่พบในรายชื่อ HR (Orphan)", "High",
               "ระบุเจ้าของบัญชี หากไม่มีเจ้าของให้ปิดบัญชี"),
    "UAR-03": ("บัญชีกลาง / บัญชีใช้ร่วมกัน", "Medium",
               "กำหนดผู้รับผิดชอบรายบุคคล หรือเปลี่ยนเป็นบัญชีส่วนตัว"),
    "UAR-04": ("บัญชีไม่ได้ใช้งานเกินกำหนด (Dormant)", "Medium",
               "ระงับบัญชีที่ไม่ได้ใช้ และทบทวนความจำเป็น"),
    "UAR-05": ("พนักงาน 1 คนมีหลายบัญชี", "Medium",
               "ยืนยันความจำเป็น หากไม่จำเป็นให้ปิดบัญชีที่ซ้ำ"),
    "UAR-06": ("ผู้มีสิทธิ์ระดับสูง (Privileged)", "Review",
               "ให้เจ้าของระบบทบทวนและยืนยันความเหมาะสมของสิทธิ์"),
    "UAR-07": ("สิทธิ์ขัดแย้งกัน (SoD Conflict)", "High",
               "แยกสิทธิ์ออกจากกัน หรือกำหนดการควบคุมชดเชย"),
    "UAR-08": ("มีการเข้าใช้งานหลังวันลาออก", "High",
               "ตรวจสอบ log ว่าใครใช้งานและทำรายการอะไร"),
}


# ----------------------------------------------------------------------------
# อ่านและเตรียมข้อมูล
# ----------------------------------------------------------------------------

class UARError(AuditError):
    """ข้อผิดพลาดของข้อมูล input ที่ควรแจ้งผู้ใช้"""


# ชื่อคอลัมน์ที่พบบ่อยในไฟล์จริง → ชื่อมาตรฐานที่โปรแกรมใช้
COLUMN_ALIASES = {
    "employee_id": ["emp_id", "empid", "employee_no", "employee_number", "staff_id",
                    "รหัสพนักงาน", "รหัส", "employeeid", "personnel_no"],
    "full_name": ["name", "employee_name", "ชื่อ", "ชื่อ-นามสกุล", "ชื่อพนักงาน", "displayname",
                  "display_name"],
    "department": ["dept", "ฝ่าย", "แผนก", "หน่วยงาน", "division"],
    "position": ["title", "job_title", "ตำแหน่ง", "jobtitle"],
    "status": ["employee_status", "emp_status", "สถานะ", "สถานะพนักงาน"],
    "termination_date": ["resign_date", "end_date", "วันที่ลาออก", "วันลาออก", "terminated_date"],
    "username": ["user_id", "userid", "login", "login_id", "samaccountname", "account",
                 "ชื่อผู้ใช้", "user_name"],
    "role": ["roles", "permission", "permissions", "group", "groups", "สิทธิ์", "profile"],
    "account_status": ["user_status", "enabled", "สถานะบัญชี", "acct_status"],
    "last_login": ["last_logon", "lastlogondate", "last_logon_date", "last_login_date",
                   "เข้าใช้ล่าสุด", "lastlogon"],
    "created_date": ["created", "whencreated", "create_date", "วันที่สร้าง"],
}


def _standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
    rename = {}
    for std, aliases in COLUMN_ALIASES.items():
        if std in df.columns:
            continue
        for a in aliases:
            if a in df.columns and a not in rename:
                rename[a] = std
                break
    return df.rename(columns=rename)


def read_table(src, name: str | None = None) -> pd.DataFrame:
    """อ่านไฟล์ .xlsx / .csv จาก path หรือ file-like object (เช่นไฟล์ที่อัปโหลดบนเว็บ)"""
    if isinstance(src, (str, Path)):
        path = Path(src)
        if not path.exists():
            raise UARError(f"ไม่พบไฟล์: {path}")
        suffix = path.suffix.lower()
    else:
        suffix = Path(name or getattr(src, "name", "")).suffix.lower()
    try:
        if suffix in {".xlsx", ".xlsm", ".xls"}:
            df = pd.read_excel(src, dtype=str)
        elif suffix in {".csv", ".txt"}:
            df = pd.read_csv(src, dtype=str, encoding="utf-8-sig")
        else:
            raise UARError(f"รองรับเฉพาะไฟล์ .xlsx หรือ .csv ({name or src})")
    except UARError:
        raise
    except Exception as e:
        raise UARError(f"อ่านไฟล์ไม่ได้ ({name or src}): {e}") from e
    return _standardize_columns(df).fillna("")


def require_columns(df: pd.DataFrame, required: list[str], label: str) -> None:
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise UARError(
            f"ไฟล์ {label} ขาดคอลัมน์: {', '.join(missing)}\n"
            f"คอลัมน์ที่มีในไฟล์: {', '.join(df.columns)}"
        )


def to_date(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series.replace("", pd.NA), errors="coerce", dayfirst=False).dt.normalize()


def norm(s: pd.Series) -> pd.Series:
    return s.astype(str).str.strip().str.lower()


def prepare(hr: pd.DataFrame, users: pd.DataFrame):
    hr = hr.copy()
    users = users.copy()

    hr["employee_id"] = hr["employee_id"].astype(str).str.strip().str.upper()
    hr["_resigned"] = norm(hr["status"]).isin(RESIGNED_HR_VALUES)
    hr["termination_date"] = to_date(hr["termination_date"]) if "termination_date" in hr else pd.NaT

    users["employee_id"] = users["employee_id"].astype(str).str.strip().str.upper()
    users["_active"] = norm(users["account_status"]).isin(ACTIVE_ACCOUNT_VALUES)
    users["last_login"] = to_date(users["last_login"])
    if "created_date" in users:
        users["created_date"] = to_date(users["created_date"])
    if "full_name" not in users:
        users["full_name"] = ""

    # role อาจมีหลายค่า คั่นด้วย ; , |
    users["_roles"] = users["role"].astype(str).str.split(r"\s*[;,|]\s*", regex=True).apply(
        lambda xs: [x.strip() for x in xs if x.strip()]
    )

    merged = users.merge(
        hr[["employee_id", "full_name", "department", "position", "status",
            "termination_date", "_resigned"]].rename(columns={"full_name": "hr_name"}),
        on="employee_id", how="left", indicator=True,
    )
    return hr, users, merged


# ----------------------------------------------------------------------------
# การตรวจสอบแต่ละข้อ
# ----------------------------------------------------------------------------

BASE_COLS = ["username", "employee_id", "hr_name", "department", "position",
             "role", "account_status", "last_login"]


def _out(df: pd.DataFrame, check_id: str, detail) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    out = df[[c for c in BASE_COLS if c in df.columns]].copy()
    out.insert(0, "check_id", check_id)
    out.insert(1, "severity", CHECKS[check_id][1])
    out["detail"] = detail(df) if callable(detail) else detail
    out["recommendation"] = CHECKS[check_id][2]
    return out


def check_terminated_active(m):
    df = m[(m["_merge"] == "both") & m["_resigned"] & m["_active"]]
    return _out(df, "UAR-01", lambda d: d.apply(
        lambda r: f"HR สถานะ '{r['status']}'"
                  + (f" ลาออก {r['termination_date']:%Y-%m-%d}" if pd.notna(r["termination_date"]) else "")
                  + " แต่บัญชียังเปิดอยู่", axis=1))


def check_orphan(m, generic_mask):
    # ไม่นับบัญชีกลางซ้ำ เพราะแยกไปอยู่ UAR-03 แล้ว
    df = m[(m["_merge"] == "left_only") & m["_active"] & ~generic_mask]
    return _out(df, "UAR-02", lambda d: d["employee_id"].apply(
        lambda e: "ไม่มีรหัสพนักงาน" if e in ("", "NAN") else f"ไม่พบรหัส {e} ในข้อมูล HR"))


def generic_mask_for(m):
    pattern = r"(?:^|[._\-0-9])(?:" + "|".join(GENERIC_KEYWORDS) + r")(?:$|[._\-0-9])"
    by_name = norm(m["username"]).str.contains(pattern, regex=True)
    no_emp = m["employee_id"].isin(["", "NAN"])
    return (by_name | no_emp) & m["_active"]


def check_generic(m, mask):
    df = m[mask]
    return _out(df, "UAR-03", "ชื่อบัญชีมีลักษณะเป็นบัญชีกลาง หรือไม่ผูกกับรหัสพนักงาน")


def check_dormant(m, as_of, days):
    cutoff = pd.Timestamp(as_of) - pd.Timedelta(days=days)
    never = m["last_login"].isna()
    old = m["last_login"] < cutoff
    df = m[m["_active"] & (never | old)].copy()

    def d(x):
        return x["last_login"].apply(
            lambda v: "ไม่เคยเข้าใช้งาน" if pd.isna(v)
            else f"ไม่ได้ใช้งาน {(pd.Timestamp(as_of) - v).days} วัน (เกิน {days} วัน)")
    return _out(df, "UAR-04", d)


def check_duplicate(m):
    valid = m[m["_active"] & ~m["employee_id"].isin(["", "NAN"])]
    counts = valid.groupby("employee_id")["username"].transform("count")
    df = valid[counts > 1].sort_values("employee_id")
    names = df.groupby("employee_id")["username"].apply(lambda s: ", ".join(s))
    return _out(df, "UAR-05", lambda d: d["employee_id"].map(
        lambda e: f"มี {len(names[e].split(', '))} บัญชี: {names[e]}"))


def check_privileged(m):
    pattern = "|".join(PRIVILEGED_KEYWORDS)
    df = m[m["_active"] & norm(m["role"]).str.contains(pattern, regex=True)]
    return _out(df, "UAR-06", "มีสิทธิ์ระดับผู้ดูแลระบบ ต้องได้รับการทบทวนเป็นระยะ")


def check_sod(m, rules):
    rows = []
    for _, r in m[m["_active"]].iterrows():
        roles = {x.lower() for x in r["_roles"]}
        hits = [(a, b, risk) for a, b, risk in rules if a.lower() in roles and b.lower() in roles]
        for a, b, risk in hits:
            rec = r.copy()
            rec["_detail"] = f"มีทั้ง '{a}' และ '{b}' → {risk}"
            rows.append(rec)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    return _out(df, "UAR-07", lambda d: d["_detail"])


def check_login_after_term(m):
    df = m[(m["_merge"] == "both") & m["termination_date"].notna() & m["last_login"].notna()
           & (m["last_login"] > m["termination_date"])]
    return _out(df, "UAR-08", lambda d: d.apply(
        lambda r: f"ลาออก {r['termination_date']:%Y-%m-%d} แต่เข้าใช้ล่าสุด {r['last_login']:%Y-%m-%d}"
                  f" ({(r['last_login'] - r['termination_date']).days} วันหลังลาออก)", axis=1))


def load_sod_rules(src=None, name: str | None = None):
    """อ่านกฎ SoD (คอลัมน์ role_a, role_b, risk) ถ้าไม่ระบุจะใช้กฎตั้งต้น"""
    if src is None or src == "":
        return DEFAULT_SOD_RULES
    df = read_table(src, name)
    require_columns(df, ["role_a", "role_b"], "SoD rules")
    risk = df["risk"].tolist() if "risk" in df else [""] * len(df)
    return [(a, b, r) for a, b, r in zip(df["role_a"].str.strip(), df["role_b"].str.strip(), risk)
            if a and b]


def run_checks(hr, users, sod_rules=None, as_of=None, dormant_days=90):
    """รันการตรวจทั้งหมด คืนค่า (findings DataFrame, stats dict)"""
    require_columns(hr, HR_REQUIRED, "HR")
    require_columns(users, USER_REQUIRED, "Users")
    sod_rules = sod_rules or DEFAULT_SOD_RULES
    as_of = as_of or date.today()
    hr, users, m = prepare(hr, users)
    gmask = generic_mask_for(m)
    parts = [
        check_terminated_active(m),
        check_login_after_term(m),
        check_orphan(m, gmask),
        check_generic(m, gmask),
        check_dormant(m, as_of, dormant_days),
        check_duplicate(m),
        check_sod(m, sod_rules),
        check_privileged(m),
    ]
    parts = [p for p in parts if not p.empty]
    findings = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(
        columns=["check_id", "severity", *BASE_COLS, "detail", "recommendation"])
    if not findings.empty:
        findings["_s"] = findings["severity"].map(SEVERITY_ORDER)
        findings = findings.sort_values(["_s", "check_id", "username"]).drop(columns="_s")
        findings["last_login"] = findings["last_login"].dt.strftime("%Y-%m-%d").fillna("-")
        findings.insert(0, "finding_no", range(1, len(findings) + 1))
    stats = {
        "hr_total": len(hr),
        "hr_resigned": int(hr["_resigned"].sum()),
        "user_total": len(users),
        "user_active": int(users["_active"].sum()),
    }
    return findings, stats


# ----------------------------------------------------------------------------
# ออกรายงาน Excel
# ----------------------------------------------------------------------------

HEADER_FILL = PatternFill("solid", fgColor="1F3864")
HEADER_FONT = Font(bold=True, color="FFFFFF")
SEV_FILL = {
    "High": PatternFill("solid", fgColor="F8CBAD"),
    "Medium": PatternFill("solid", fgColor="FFE699"),
    "Low": PatternFill("solid", fgColor="C6EFCE"),
    "Review": PatternFill("solid", fgColor="DDEBF7"),
}
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

COL_TH = {
    "finding_no": "ลำดับ", "check_id": "รหัสการตรวจ", "severity": "ระดับความเสี่ยง",
    "username": "Username", "employee_id": "รหัสพนักงาน", "hr_name": "ชื่อ (HR)",
    "department": "ฝ่าย", "position": "ตำแหน่ง", "role": "สิทธิ์ / Role",
    "account_status": "สถานะบัญชี", "last_login": "เข้าใช้ล่าสุด",
    "detail": "รายละเอียด", "recommendation": "ข้อเสนอแนะ",
    "management_response": "คำชี้แจงจากหน่วยรับตรวจ", "owner": "ผู้รับผิดชอบ",
    "due_date": "กำหนดแล้วเสร็จ",
}


def style_table(ws, header_row=1, widths=None):
    for cell in ws[header_row]:
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = BORDER
    for row in ws.iter_rows(min_row=header_row + 1):
        for cell in row:
            cell.border = BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    if widths:
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[get_column_letter(i)].width = w
    ws.freeze_panes = ws.cell(row=header_row + 1, column=1)
    ws.auto_filter.ref = ws.dimensions


def write_report(findings, stats, out_path, system_name, as_of, dormant_days):
    summary_rows = []
    for cid, (title, sev, _) in CHECKS.items():
        n = int((findings["check_id"] == cid).sum()) if not findings.empty else 0
        summary_rows.append({"รหัสการตรวจ": cid, "รายการตรวจสอบ": title,
                             "ระดับความเสี่ยง": sev, "จำนวนที่พบ": n,
                             "ผลการตรวจ": "พบข้อสังเกต" if n else "ไม่พบ"})
    summary = pd.DataFrame(summary_rows)

    with pd.ExcelWriter(out_path, engine="openpyxl") as xw:
        # --- Summary ---
        summary.to_excel(xw, sheet_name="Summary", index=False, startrow=11)
        ws = xw.sheets["Summary"]
        ws["A1"] = "รายงานการสอบทานสิทธิ์ผู้ใช้งาน (User Access Review)"
        ws["A1"].font = Font(bold=True, size=16, color="1F3864")
        info = [
            ("ระบบที่ตรวจสอบ", system_name),
            ("ข้อมูล ณ วันที่", as_of.strftime("%Y-%m-%d")),
            ("วันที่ออกรายงาน", datetime.now().strftime("%Y-%m-%d %H:%M")),
            ("เกณฑ์บัญชีไม่ได้ใช้งาน", f"{dormant_days} วัน"),
            ("พนักงานใน HR (ทั้งหมด / ลาออก)", f"{stats['hr_total']} / {stats['hr_resigned']}"),
            ("บัญชีในระบบ (ทั้งหมด / เปิดใช้งาน)", f"{stats['user_total']} / {stats['user_active']}"),
            ("ข้อตรวจพบทั้งหมด", len(findings)),
            ("ระดับ High", int((findings["severity"] == "High").sum()) if not findings.empty else 0),
        ]
        for i, (k, v) in enumerate(info, start=3):
            ws.cell(row=i, column=1, value=k).font = Font(bold=True)
            ws.cell(row=i, column=2, value=v)
        style_table(ws, header_row=12, widths=[34, 44, 16, 13, 14])
        ws.freeze_panes = None
        for r in range(13, 13 + len(summary)):
            sev = ws.cell(row=r, column=3).value
            ws.cell(row=r, column=3).fill = SEV_FILL.get(sev, PatternFill())
            if ws.cell(row=r, column=4).value:
                ws.cell(row=r, column=5).font = Font(bold=True, color="C00000")

        # --- All findings (with columns for management response) ---
        if findings.empty:
            pd.DataFrame({"ผล": ["ไม่พบข้อตรวจพบ"]}).to_excel(xw, sheet_name="Findings", index=False)
        else:
            f = findings.copy()
            f["management_response"] = ""
            f["owner"] = ""
            f["due_date"] = ""
            f = f.rename(columns=COL_TH)
            f.to_excel(xw, sheet_name="Findings", index=False)
            ws = xw.sheets["Findings"]
            style_table(ws, widths=[7, 10, 11, 18, 12, 22, 16, 18, 26, 11, 12, 46, 40, 30, 16, 14])
            sev_col = list(f.columns).index(COL_TH["severity"]) + 1
            for r in range(2, ws.max_row + 1):
                c = ws.cell(row=r, column=sev_col)
                c.fill = SEV_FILL.get(c.value, PatternFill())

            # --- one sheet per check ---
            for cid in CHECKS:
                sub = findings[findings["check_id"] == cid]
                if sub.empty:
                    continue
                sub = sub.drop(columns=["finding_no", "check_id", "severity", "recommendation"])
                sub = sub.rename(columns=COL_TH)
                sub.to_excel(xw, sheet_name=cid, index=False)
                style_table(xw.sheets[cid], widths=[18, 12, 22, 16, 18, 26, 11, 12, 50])

        # --- Check definitions ---
        defs = pd.DataFrame(
            [{"รหัส": k, "รายการตรวจสอบ": v[0], "ระดับ": v[1], "ข้อเสนอแนะ": v[2]}
             for k, v in CHECKS.items()])
        defs.to_excel(xw, sheet_name="Methodology", index=False)
        style_table(xw.sheets["Methodology"], widths=[10, 44, 10, 60])


# ----------------------------------------------------------------------------
# ข้อมูลตัวอย่าง (โหมด --demo)
# ----------------------------------------------------------------------------

def demo_frames(as_of: date):
    """คืนค่า (hr, users, sod) DataFrame ตัวอย่าง สำหรับทดลองใช้"""
    d = lambda days: (as_of - timedelta(days=days)).strftime("%Y-%m-%d")

    hr = pd.DataFrame([
        ("E001", "สมชาย ใจดี", "บัญชี", "ผู้จัดการฝ่ายบัญชี", "Active", ""),
        ("E002", "สมหญิง รักงาน", "บัญชี", "เจ้าหน้าที่บัญชี", "Active", ""),
        ("E003", "วิชัย เก่งมาก", "จัดซื้อ", "เจ้าหน้าที่จัดซื้อ", "Resigned", d(45)),
        ("E004", "มาลี สวยงาม", "จัดซื้อ", "หัวหน้าจัดซื้อ", "Active", ""),
        ("E005", "ประเสริฐ มั่นคง", "IT", "System Administrator", "Active", ""),
        ("E006", "กมล ใฝ่รู้", "IT", "Programmer", "Active", ""),
        ("E007", "นภา ฟ้าใส", "การเงิน", "เจ้าหน้าที่การเงิน", "Resigned", d(120)),
        ("E008", "ธนา รวยทรัพย์", "การเงิน", "ผู้จัดการการเงิน", "Active", ""),
        ("E009", "อรุณ แสงทอง", "HR", "เจ้าหน้าที่บุคคล", "Active", ""),
        ("E010", "จันทร์ เพ็ญศรี", "ขาย", "พนักงานขาย", "Resigned", d(10)),
    ], columns=["employee_id", "full_name", "department", "position", "status", "termination_date"])

    users = pd.DataFrame([
        ("somchai.j", "E001", "สมชาย ใจดี", "Approve Journal; Journal Entry", "Enabled", d(1), d(900)),
        ("somying.r", "E002", "สมหญิง รักงาน", "Journal Entry", "Enabled", d(2), d(700)),
        ("wichai.k", "E003", "วิชัย เก่งมาก", "Create PO; Create Vendor", "Enabled", d(30), d(600)),
        ("malee.s", "E004", "มาลี สวยงาม", "Approve PO", "Enabled", d(3), d(800)),
        ("prasert.m", "E005", "ประเสริฐ มั่นคง", "System Administrator", "Enabled", d(0), d(1000)),
        ("prasert.adm", "E005", "ประเสริฐ มั่นคง", "Domain Admin", "Enabled", d(5), d(400)),
        ("kamol.u", "E006", "กมล ใฝ่รู้", "Developer; Production Deploy", "Enabled", d(1), d(300)),
        ("napa.f", "E007", "นภา ฟ้าใส", "Create Payment", "Enabled", d(150), d(1200)),
        ("thana.r", "E008", "ธนา รวยทรัพย์", "Create Vendor; Approve Payment", "Enabled", d(4), d(900)),
        ("arun.s", "E009", "อรุณ แสงทอง", "Payroll Maintain", "Enabled", d(200), d(500)),
        ("chan.p", "E010", "จันทร์ เพ็ญศรี", "Sales Order", "Disabled", d(12), d(350)),
        ("admin", "", "", "Administrator", "Enabled", d(2), d(2000)),
        ("test01", "", "", "Full Access", "Enabled", "", d(100)),
        ("sompong.x", "E099", "สมพงษ์ ไม่มีชื่อ", "Approve Payment", "Enabled", d(20), d(150)),
    ], columns=["username", "employee_id", "full_name", "role", "account_status",
                "last_login", "created_date"])

    sod = pd.DataFrame(DEFAULT_SOD_RULES, columns=["role_a", "role_b", "risk"])
    return hr, users, sod


def make_demo_data(folder: Path, as_of: date):
    folder.mkdir(parents=True, exist_ok=True)
    hr, users, sod = demo_frames(as_of)
    hr.to_excel(folder / "sample_hr.xlsx", index=False)
    users.to_excel(folder / "sample_users.xlsx", index=False)
    sod.to_csv(folder / "sample_sod_rules.csv", index=False, encoding="utf-8-sig")
    return folder / "sample_hr.xlsx", folder / "sample_users.xlsx", folder / "sample_sod_rules.csv"


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="User Access Review Tool สำหรับ IT Audit")
    p.add_argument("--hr", help="ไฟล์รายชื่อพนักงานจาก HR (.xlsx / .csv)")
    p.add_argument("--users", help="ไฟล์รายชื่อ User จากระบบ (.xlsx / .csv)")
    p.add_argument("--sod", help="ไฟล์กฎ SoD (คอลัมน์ role_a, role_b, risk) ไม่ใส่จะใช้ค่าตั้งต้น")
    p.add_argument("--system", default="(ไม่ระบุ)", help="ชื่อระบบที่ตรวจ เช่น SAP, Active Directory")
    p.add_argument("--as-of", help="วันที่ของข้อมูล YYYY-MM-DD (ค่าตั้งต้น = วันนี้)")
    p.add_argument("--dormant-days", type=int, default=90, help="จำนวนวันที่ถือว่าไม่ได้ใช้งาน (ค่าตั้งต้น 90)")
    p.add_argument("--out", default="UAR_Report.xlsx", help="ชื่อไฟล์รายงาน")
    p.add_argument("--demo", action="store_true", help="สร้างข้อมูลตัวอย่างแล้วรันให้ดู")
    a = p.parse_args()

    as_of = datetime.strptime(a.as_of, "%Y-%m-%d").date() if a.as_of else date.today()

    if a.demo:
        hr_p, users_p, sod_p = make_demo_data(Path("sample_data"), as_of)
        a.hr, a.users, a.sod = str(hr_p), str(users_p), str(sod_p)
        a.system = "ระบบ ERP (ข้อมูลตัวอย่าง)"
        print(f"สร้างข้อมูลตัวอย่างไว้ที่โฟลเดอร์ sample_data/")
    elif not (a.hr and a.users):
        p.error("ต้องระบุ --hr และ --users (หรือใช้ --demo)")

    try:
        hr = read_table(a.hr)
        users = read_table(a.users)
        rules = load_sod_rules(a.sod)
        findings, stats = run_checks(hr, users, rules, as_of, a.dormant_days)
        write_report(findings, stats, a.out, a.system, as_of, a.dormant_days)
    except UARError as e:
        sys.exit(f"[ERROR] {e}")
    except PermissionError:
        sys.exit(f"[ERROR] บันทึกไฟล์ {a.out} ไม่ได้ อาจเปิดค้างอยู่ใน Excel ให้ปิดไฟล์ก่อนแล้วรันใหม่")

    print(f"\nตรวจสอบเสร็จ: พนักงาน {stats['hr_total']} คน, บัญชี {stats['user_total']} บัญชี")
    print(f"พบข้อตรวจพบทั้งหมด {len(findings)} รายการ")
    if not findings.empty:
        for cid, (title, sev, _) in CHECKS.items():
            n = int((findings["check_id"] == cid).sum())
            if n:
                print(f"  [{sev:<6}] {cid} {title}: {n}")
    print(f"\nบันทึกรายงานที่: {Path(a.out).resolve()}")


if __name__ == "__main__":
    main()
