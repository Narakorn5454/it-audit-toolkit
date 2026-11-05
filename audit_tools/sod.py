"""
Segregation of Duties (SoD) Analysis — วิเคราะห์สิทธิ์ขัดแย้งข้ามหลายระบบ
=======================================================================
Input
  1. user_roles       : system, username, employee_id, full_name, department, role
  2. role_permissions : system, role, permission
  3. sod_rules        : rule_id, function_a, function_b, risk, (risk_level)
  4. mitigations (ไม่บังคับ): rule_id, employee_id หรือ username ('*' = ทุกคน), control

แนวคิด: เชื่อมตัวตนผู้ใช้ข้ามระบบด้วย employee_id (ถ้าไม่มีใช้ username) แล้วรวมสิทธิ์ทั้งหมด
ของคนนั้น ถ้ามีครบทั้ง function_a และ function_b ของกฎใด = สิทธิ์ขัดแย้ง
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import pandas as pd

from .common import (AuditError, ensure, make_findings, read_table, require, sort_findings,
                     write_findings_report)

CHECKS = {
    "SOD-01": ("ผู้ใช้มีสิทธิ์ขัดแย้งกันภายในระบบเดียว", "High",
               "ถอดสิทธิ์ด้านใดด้านหนึ่งออก หรือกำหนดการควบคุมชดเชยที่สอบทานได้",
               "ผู้ใช้คนเดียวทำรายการได้ครบวงจรโดยไม่มีผู้ตรวจทาน เสี่ยงต่อการทุจริตและข้อผิดพลาด"),
    "SOD-02": ("ผู้ใช้มีสิทธิ์ขัดแย้งกันข้ามระบบ", "High",
               "ทบทวนสิทธิ์ข้ามระบบร่วมกับเจ้าของระบบทั้งสอง และแยกหน้าที่ให้ชัดเจน",
               "ความขัดแย้งข้ามระบบมักถูกมองข้ามเพราะแต่ละระบบตรวจแยกกัน"),
    "SOD-03": ("Role ที่ออกแบบให้มีสิทธิ์ขัดแย้งในตัวเอง", "High",
               "ออกแบบ Role ใหม่ แยกสิทธิ์ที่ขัดแย้งออกเป็นคนละ Role",
               "ทุกคนที่ได้รับ Role นี้จะมีสิทธิ์ขัดแย้งทันที เป็นปัญหาเชิงโครงสร้าง"),
    "SOD-04": ("สิทธิ์ขัดแย้งที่มีการควบคุมชดเชย (ให้ทดสอบการควบคุม)", "Review",
               "ทดสอบประสิทธิผลของการควบคุมชดเชยว่าปฏิบัติจริงและสม่ำเสมอ",
               "การควบคุมชดเชยต้องได้รับการทดสอบ ไม่ใช่เพียงมีเอกสาร"),
    "SOD-05": ("ผู้ใช้มีจำนวน Role มากผิดปกติ", "Medium",
               "ทบทวนความจำเป็นตามหน้าที่งานปัจจุบัน (Least privilege)",
               "สิทธิ์สะสมจากการย้ายตำแหน่ง (Privilege creep)"),
    "SOD-06": ("Role ที่ผู้ใช้ถืออยู่แต่ไม่มีในตาราง Role-Permission", "Medium",
               "ขอรายละเอียดสิทธิ์ของ Role ดังกล่าวเพื่อวิเคราะห์ให้ครบถ้วน",
               "ไม่สามารถวิเคราะห์ SoD ได้ครบถ้วน (ข้อจำกัดของขอบเขตการตรวจ)"),
}

ALIASES = {
    "system": ["application", "app", "ระบบ"],
    "username": ["user", "user_id", "userid", "login", "ชื่อผู้ใช้"],
    "employee_id": ["emp_id", "staff_id", "รหัสพนักงาน"],
    "full_name": ["name", "ชื่อ", "ชื่อ-นามสกุล"],
    "department": ["dept", "ฝ่าย", "แผนก"],
    "role": ["role_name", "profile", "group", "responsibility", "สิทธิ์", "บทบาท"],
    "permission": ["function", "tcode", "transaction", "privilege", "action", "ฟังก์ชัน"],
    "rule_id": ["rule", "id", "รหัสกฎ"],
    "function_a": ["permission_a", "conflict_a", "ฟังก์ชัน_a"],
    "function_b": ["permission_b", "conflict_b", "ฟังก์ชัน_b"],
    "risk": ["description", "risk_description", "ความเสี่ยง"],
    "risk_level": ["level", "severity", "ระดับ"],
    "control": ["mitigating_control", "control_description", "การควบคุม"],
}

COL_TH = {"person": "ผู้ใช้ (รหัสพนักงาน)", "full_name": "ชื่อ", "department": "ฝ่าย", "rule_id": "รหัสกฎ",
          "conflict": "สิทธิ์ที่ขัดแย้ง", "path_a": "ได้สิทธิ์ A จาก", "path_b": "ได้สิทธิ์ B จาก",
          "systems": "ระบบ", "risk": "ความเสี่ยง", "control": "การควบคุมชดเชย", "role": "Role",
          "system": "ระบบ", "n_roles": "จำนวน Role", "n_conflicts": "จำนวนสิทธิ์ขัดแย้ง",
          "rules": "กฎที่ขัด", "usernames": "ชื่อผู้ใช้ในแต่ละระบบ", "holders": "ผู้ถือ Role"}

FIELDS = ["person", "full_name", "department", "rule_id", "conflict", "path_a", "path_b", "systems",
          "risk", "control"]


@dataclass
class Params:
    max_roles: int = 5


def load(user_roles, role_permissions, rules, mitigations=None, names: dict | None = None):
    names = names or {}
    ur = read_table(user_roles, names.get("user_roles"), ALIASES)
    rp = read_table(role_permissions, names.get("role_permissions"), ALIASES)
    rl = read_table(rules, names.get("rules"), ALIASES)
    mt = read_table(mitigations, names.get("mitigations"), ALIASES) if mitigations is not None else None
    return ur, rp, rl, mt


def _norm(s):
    return s.astype(str).str.strip()


def analyze(ur: pd.DataFrame, rp: pd.DataFrame, rules: pd.DataFrame,
            mitigations: pd.DataFrame | None = None, params: Params | None = None) -> dict:
    p = params or Params()
    require(ur, ["system", "username", "role"], "User-Role")
    require(rp, ["system", "role", "permission"], "Role-Permission")
    require(rules, ["function_a", "function_b"], "SoD Rules")
    ur = ensure(ur.copy(), ["employee_id", "full_name", "department"])
    for c in ["system", "username", "role", "employee_id", "full_name", "department"]:
        ur[c] = _norm(ur[c])
    rp = rp.copy()
    for c in ["system", "role", "permission"]:
        rp[c] = _norm(rp[c])
    rules = ensure(rules.copy(), ["rule_id", "risk", "risk_level"])
    rules["rule_id"] = [r if r else f"R{i + 1:02d}" for i, r in enumerate(_norm(rules["rule_id"]))]

    # ตัวตนข้ามระบบ: employee_id ถ้ามี ไม่งั้น username
    ur["person"] = ur["employee_id"].where(ur["employee_id"] != "", ur["username"])
    key = lambda s, r: (s.lower(), r.lower())
    role_perm = defaultdict(set)
    for s, r, perm in rp[["system", "role", "permission"]].itertuples(index=False):
        role_perm[key(s, r)].add(perm.lower())

    mit = {}
    if mitigations is not None and not mitigations.empty:
        mitigations = ensure(mitigations.copy(), ["employee_id", "username", "control", "rule_id"])
        for r in mitigations.itertuples(index=False):
            who = (r.employee_id or r.username or "*").strip()
            mit[(str(r.rule_id).strip(), who.lower())] = r.control

    rows = []
    # SOD-06 role ที่ไม่มีในตาราง
    undefined = ur[[key(s, r) not in role_perm for s, r in zip(ur["system"], ur["role"])]]
    for r in undefined.drop_duplicates(["system", "role", "person"]).itertuples(index=False):
        rows.append({"check_id": "SOD-06", "person": r.person, "full_name": r.full_name,
                     "department": r.department, "systems": r.system,
                     "detail": f"Role '{r.role}' ในระบบ {r.system} ไม่มีรายละเอียดสิทธิ์"})

    # SOD-03 role ที่ขัดแย้งในตัวเอง
    holders = ur.groupby([ur["system"].str.lower(), ur["role"].str.lower()])["person"].apply(
        lambda s: ", ".join(sorted(set(s))))
    role_name = {key(s, r): (s, r) for s, r in rp[["system", "role"]].itertuples(index=False)}
    inherent = []
    for rk, perms in role_perm.items():
        for rule in rules.itertuples(index=False):
            a, b = rule.function_a.strip().lower(), rule.function_b.strip().lower()
            if a in perms and b in perms:
                s, r = role_name[rk]
                inherent.append({"system": s, "role": r, "rule_id": rule.rule_id,
                                 "conflict": f"{rule.function_a} × {rule.function_b}",
                                 "holders": holders.get(rk, "")})
                rows.append({"check_id": "SOD-03", "person": f"[Role] {r}", "systems": s,
                             "rule_id": rule.rule_id, "conflict": f"{rule.function_a} × {rule.function_b}",
                             "risk": rule.risk,
                             "detail": f"Role {r} มีทั้งสองสิทธิ์ในตัว · ผู้ถือ: {holders.get(rk, '-') or '-'}"})

    # รวมสิทธิ์ของแต่ละคน: perm -> [(system, role)]
    people = []
    for person, g in ur.groupby("person"):
        perm_src = defaultdict(list)
        for s, r in g[["system", "role"]].itertuples(index=False):
            for perm in role_perm.get(key(s, r), ()):
                perm_src[perm].append((s, r))
        first = g.iloc[0]
        info = {"person": person, "full_name": first.full_name, "department": first.department}
        conflicts = []
        for rule in rules.itertuples(index=False):
            a, b = rule.function_a.strip().lower(), rule.function_b.strip().lower()
            if a not in perm_src or b not in perm_src:
                continue
            sys_a = {s for s, _ in perm_src[a]}
            sys_b = {s for s, _ in perm_src[b]}
            same_system = bool(sys_a & sys_b)
            control = mit.get((rule.rule_id, person.lower())) or mit.get((rule.rule_id, "*"))
            cid = "SOD-04" if control else ("SOD-01" if same_system else "SOD-02")
            sev = None
            if not control and rule.risk_level in ("High", "Medium", "Low"):
                sev = rule.risk_level
            fmt = lambda src: "; ".join(f"{s}:{r}" for s, r in src)
            row = {"check_id": cid, **info, "rule_id": rule.rule_id,
                   "conflict": f"{rule.function_a} × {rule.function_b}",
                   "path_a": fmt(perm_src[a]), "path_b": fmt(perm_src[b]),
                   "systems": ", ".join(sorted(sys_a | sys_b)), "risk": rule.risk,
                   "control": control or "",
                   "detail": ("ข้ามระบบ " if not same_system else "") + (rule.risk or "")}
            if sev:
                row["severity"] = sev
            rows.append(row)
            conflicts.append(rule.rule_id)
        n_roles = len(g[["system", "role"]].drop_duplicates())
        if n_roles > p.max_roles:
            rows.append({"check_id": "SOD-05", **info, "systems": ", ".join(sorted(set(g["system"]))),
                         "detail": f"มี {n_roles} Role (เกณฑ์ไม่เกิน {p.max_roles}): "
                                   + ", ".join(f"{s}:{r}" for s, r in g[["system", "role"]].itertuples(index=False))})
        people.append({**info, "usernames": ", ".join(sorted(set(g["system"] + ":" + g["username"]))),
                       "n_roles": n_roles, "n_conflicts": len(conflicts), "rules": ", ".join(conflicts)})

    findings = sort_findings(make_findings(rows, CHECKS, FIELDS), ["person"])
    users = pd.DataFrame(people).sort_values("n_conflicts", ascending=False)
    conflict_rows = findings[findings["check_id"].isin(["SOD-01", "SOD-02", "SOD-04"])]
    matrix = (pd.crosstab(conflict_rows["rule_id"], conflict_rows["department"])
              if not conflict_rows.empty else pd.DataFrame())
    if not matrix.empty:
        matrix = matrix.reset_index().rename(columns={"rule_id": "กฎ \\ ฝ่าย"})
    stats = {"systems": ur["system"].nunique(), "people": ur["person"].nunique(),
             "assignments": len(ur), "roles": len(role_perm), "rules": len(rules),
             "people_conflict": int((users["n_conflicts"] > 0).sum())}
    return {"findings": findings, "users": users, "matrix": matrix,
            "inherent": pd.DataFrame(inherent), "rules": rules, "stats": stats}


def write_report(res: dict, out, org: str = "(ไม่ระบุ)"):
    s = res["stats"]
    info = [("องค์กร", org), ("จำนวนระบบ", s["systems"]), ("จำนวนผู้ใช้ (รวมข้ามระบบ)", s["people"]),
            ("จำนวนการกำหนด Role", s["assignments"]), ("จำนวนกฎ SoD", s["rules"]),
            ("ผู้ใช้ที่มีสิทธิ์ขัดแย้ง", s["people_conflict"])]
    write_findings_report(out, "รายงานการวิเคราะห์การแบ่งแยกหน้าที่ (Segregation of Duties)", info, CHECKS,
                          res["findings"], COL_TH,
                          extra_sheets={"User Summary": res["users"], "Conflict Matrix": res["matrix"],
                                        "Role Design Issues": res["inherent"],
                                        "SoD Ruleset": res["rules"]})


# ----------------------------------------------------------------------------
# ข้อมูลตัวอย่าง: 3 ระบบ (ERP, Banking, HRMS)
# ----------------------------------------------------------------------------

DEMO_ROLE_PERMS = {
    ("ERP", "AP_Clerk"): ["Invoice Post"],
    ("ERP", "AP_Supervisor"): ["Invoice Approve", "Payment Run"],
    ("ERP", "Vendor_Admin"): ["Vendor Master Maintain"],
    ("ERP", "Purchaser"): ["PO Create"],
    ("ERP", "Purchasing_Mgr"): ["PO Approve"],
    ("ERP", "Warehouse"): ["Goods Receipt"],
    ("ERP", "GL_Accountant"): ["GL Journal Post"],
    ("ERP", "GL_Manager"): ["GL Journal Approve"],
    ("ERP", "Finance_SuperUser"): ["Vendor Master Maintain", "Payment Run", "Report View"],
    ("ERP", "IT_Admin"): ["User Admin", "Role Maintain"],
    ("ERP", "AR_Clerk"): ["Cash Receipt Post"],
    ("ERP", "Credit_Controller"): ["Customer Master Maintain"],
    ("ERP", "AR_Supervisor"): ["Credit Memo Post"],
    ("ERP", "Report_Viewer"): ["Report View"],
    ("ERP", "Budget_Planner"): ["Budget Maintain"],
    ("Banking", "Maker"): ["Bank Payment Create"],
    ("Banking", "Releaser"): ["Bank Payment Release"],
    ("HRMS", "HR_Officer"): ["Employee Master Maintain"],
    ("HRMS", "Payroll_Officer"): ["Payroll Run"],
    ("HRMS", "Employee_Self_Service"): ["Self Service"],
}

DEMO_RULES = [
    ("R01", "Vendor Master Maintain", "Payment Run", "สร้างผู้ขายปลอมแล้วสั่งจ่ายเงินเองได้", "High"),
    ("R02", "Vendor Master Maintain", "Bank Payment Release", "แก้บัญชีธนาคารผู้ขายแล้วปล่อยเงินเองได้", "High"),
    ("R03", "PO Create", "PO Approve", "ออกและอนุมัติใบสั่งซื้อเองได้", "High"),
    ("R04", "PO Create", "Goods Receipt", "สั่งซื้อและรับของเอง ปกปิดการรับของไม่ครบ", "Medium"),
    ("R05", "Invoice Post", "Payment Run", "บันทึกใบแจ้งหนี้และจ่ายเงินเองได้", "High"),
    ("R06", "Bank Payment Create", "Bank Payment Release", "สร้างและปล่อยรายการโอนเงินเองได้", "High"),
    ("R07", "GL Journal Post", "GL Journal Approve", "บันทึกและอนุมัติรายการบัญชีเองได้", "High"),
    ("R08", "Employee Master Maintain", "Payroll Run", "สร้างพนักงานผีแล้วจ่ายเงินเดือนได้", "High"),
    ("R09", "Employee Master Maintain", "Bank Payment Release", "แก้บัญชีพนักงานแล้วปล่อยเงินได้", "High"),
    ("R10", "User Admin", "Payment Run", "ให้สิทธิ์ตัวเองแล้วจ่ายเงินได้", "High"),
    ("R11", "Customer Master Maintain", "Credit Memo Post", "ลดหนี้ให้ลูกค้าที่ตัวเองสร้าง", "Medium"),
]

DEMO_PEOPLE = [  # employee_id, name, dept, [(system, username, role)]
    ("E101", "สมศรี การเงิน", "การเงิน", [("ERP", "somsri.k", "Finance_SuperUser")]),
    ("E102", "อนันต์ จัดซื้อ", "จัดซื้อ", [("ERP", "anan.j", "Purchaser"), ("ERP", "anan.j", "Purchasing_Mgr")]),
    ("E103", "มาลัย คลัง", "การเงิน", [("Banking", "MALAI01", "Maker"), ("Banking", "MALAI01", "Releaser")]),
    ("E104", "กิตติพงษ์ เจ้าหนี้", "บัญชีเจ้าหนี้", [("ERP", "kittipong.c", "Vendor_Admin"),
                                                 ("Banking", "KITTI02", "Releaser")]),
    ("E105", "นก บุคคล", "ทรัพยากรบุคคล", [("HRMS", "nok.b", "HR_Officer"), ("HRMS", "nok.b", "Payroll_Officer")]),
    ("E106", "พิม เงินเดือน", "ทรัพยากรบุคคล", [("HRMS", "pim.n", "HR_Officer"), ("Banking", "PIM03", "Releaser")]),
    ("E107", "ธีระ ไอที", "IT", [("ERP", "teera.it", "IT_Admin"), ("ERP", "teera.it", "AP_Supervisor")]),
    ("E108", "วรรณา บัญชี", "บัญชี", [("ERP", "wanna.b", r) for r in
                                     ("GL_Accountant", "AR_Clerk", "Credit_Controller", "Report_Viewer",
                                      "Budget_Planner")] + [("HRMS", "wanna.b", "Employee_Self_Service")]),
    ("E109", "ชัยวัฒน์ ชั่วคราว", "บัญชี", [("ERP", "chaiwat.t", "ZZ_TEMP_FULL")]),
    ("E110", "ปรีชา บัญชีทั่วไป", "บัญชี", [("ERP", "preecha.g", "GL_Accountant")]),
    ("E111", "นิดา ผจก.บัญชี", "บัญชี", [("ERP", "nida.m", "GL_Manager")]),
    ("E112", "สุดา เจ้าหนี้", "บัญชีเจ้าหนี้", [("ERP", "suda.a", "AP_Clerk")]),
    ("E113", "ประยุทธ คลังสินค้า", "คลังสินค้า", [("ERP", "prayut.w", "Warehouse")]),
    ("E114", "อรทัย ลูกหนี้", "บัญชีลูกหนี้", [("ERP", "orathai.r", "AR_Supervisor")]),
]


def demo_frames():
    ur = pd.DataFrame([(s, u, e, n, d, r) for e, n, d, assigns in DEMO_PEOPLE for s, u, r in assigns],
                      columns=["system", "username", "employee_id", "full_name", "department", "role"])
    rp = pd.DataFrame([(s, r, p) for (s, r), perms in DEMO_ROLE_PERMS.items() for p in perms],
                      columns=["system", "role", "permission"])
    rules = pd.DataFrame(DEMO_RULES, columns=["rule_id", "function_a", "function_b", "risk", "risk_level"])
    mit = pd.DataFrame([("R01", "E101", "", "CFO สอบทานรายงานการแก้ไข Vendor Master ทุกเดือน")],
                       columns=["rule_id", "employee_id", "username", "control"])
    return ur, rp, rules, mit
