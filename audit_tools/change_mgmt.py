"""
Change Management Review — เทียบ log การนำโปรแกรมขึ้นระบบจริง (deployment) กับใบคำขอเปลี่ยนแปลงใน ITSM
=========================================================================================================
Input
  1. deployments : deploy_id, change_id, system, deploy_datetime, deployed_by, description
  2. tickets     : change_id, change_type (Normal/Standard/Emergency), title, requested_by, developer,
                   approved_by, approval_date, uat_by, uat_date, status
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from .common import ensure, make_findings, parse_dates, read_table, require, sort_findings, write_findings_report

CHECKS = {
    "CHG-01": ("นำขึ้นระบบจริงโดยไม่อ้างอิงใบคำขอ", "High",
               "ทุกการเปลี่ยนแปลงต้องมีใบคำขอ ตรวจสอบว่าการเปลี่ยนแปลงนี้คืออะไรและได้รับอนุญาตหรือไม่",
               "การเปลี่ยนแปลงที่ไม่ผ่านกระบวนการ อาจเป็นการแก้ไขโดยไม่ได้รับอนุญาต"),
    "CHG-02": ("อ้างอิงใบคำขอที่ไม่มีอยู่ในระบบ ITSM", "High",
               "ตรวจสอบความถูกต้องของเลขที่อ้างอิง และขอหลักฐานการอนุมัติ",
               "อาจเป็นการอ้างเลขที่ปลอมเพื่อให้ดูเหมือนผ่านกระบวนการ"),
    "CHG-03": ("การเปลี่ยนแปลงไม่ได้รับการอนุมัติ", "High",
               "ขออนุมัติย้อนหลังและสอบทานว่าการเปลี่ยนแปลงไม่กระทบการทำงานของระบบ",
               "ไม่มีผู้มีอำนาจพิจารณาความเสี่ยงก่อนเปลี่ยนแปลง"),
    "CHG-04": ("อนุมัติหลังจากนำขึ้นระบบจริงแล้ว", "High",
               "กำหนดให้ระบบ deploy ตรวจสถานะอนุมัติก่อนอนุญาตให้นำขึ้น",
               "การอนุมัติย้อนหลังไม่ได้ทำหน้าที่ควบคุม"),
    "CHG-05": ("Emergency change ไม่ได้รับอนุมัติภายในกำหนด", "Medium",
               "อนุมัติย้อนหลังภายในเวลาที่นโยบายกำหนด และทบทวนเหตุผลความเร่งด่วน",
               "ช่องทางฉุกเฉินถูกใช้เพื่อหลบเลี่ยงการอนุมัติ"),
    "CHG-06": ("ผู้พัฒนานำการเปลี่ยนแปลงของตนเองขึ้นระบบจริง", "High",
               "แยกหน้าที่ผู้พัฒนาและผู้นำขึ้นระบบ ถอดสิทธิ์ production ของผู้พัฒนา",
               "ผู้พัฒนาสามารถแทรกโค้ดที่ไม่ได้รับอนุญาตเข้าระบบจริงได้"),
    "CHG-07": ("ไม่มีหลักฐานการทดสอบ (UAT) หรือทดสอบหลังขึ้นระบบ", "Medium",
               "กำหนดให้มีการลงนาม UAT ก่อน deploy ทุกครั้ง",
               "การเปลี่ยนแปลงที่ไม่ผ่านการทดสอบเสี่ยงต่อความผิดพลาดของระบบและข้อมูล"),
    "CHG-08": ("ผู้ขอ/ผู้พัฒนาเป็นผู้อนุมัติเอง", "High",
               "กำหนดให้ผู้อนุมัติต้องเป็นอิสระจากผู้ขอและผู้พัฒนา",
               "การอนุมัติตนเองไม่ถือเป็นการควบคุม"),
    "CHG-09": ("นำขึ้นระบบนอกช่วงเวลาที่กำหนด (ไม่ใช่ Emergency)", "Medium",
               "ทบทวนว่าการเปลี่ยนแปลงนอกเวลาได้รับอนุญาตและมีผู้ติดตามผล",
               "การเปลี่ยนแปลงนอกเวลาทำการมีผู้กำกับดูแลน้อย"),
    "CHG-10": ("สัดส่วน Emergency change สูงเกินเกณฑ์", "Medium",
               "วิเคราะห์สาเหตุ และปรับปรุงการวางแผนการเปลี่ยนแปลง",
               "Emergency ที่มากผิดปกติบ่งชี้ว่ากระบวนการปกติถูกหลบเลี่ยง"),
}

ALIASES = {
    "change_id": ["ticket", "ticket_id", "ticket_no", "cr", "cr_no", "rfc", "change_no", "change_number",
                  "key", "issue_key", "เลขที่คำขอ"],
    "deploy_id": ["release_id", "deployment_id", "build_id", "run_id"],
    "system": ["application", "app", "service", "ระบบ"],
    "deploy_datetime": ["deploy_date", "deployed_at", "deployment_date", "release_date", "timestamp",
                        "วันที่นำขึ้น"],
    "deployed_by": ["deployer", "released_by", "triggered_by", "ผู้นำขึ้นระบบ"],
    "change_type": ["type", "category", "ประเภท"],
    "title": ["summary", "short_description", "หัวข้อ"],
    "requested_by": ["requester", "reporter", "ผู้ขอ"],
    "developer": ["assignee", "assigned_to", "implementer", "ผู้พัฒนา"],
    "approved_by": ["approver", "cab_approver", "ผู้อนุมัติ"],
    "approval_date": ["approved_at", "approved_date", "cab_date", "วันที่อนุมัติ"],
    "uat_by": ["tested_by", "uat_signoff", "uat_signoff_by", "ผู้ทดสอบ"],
    "uat_date": ["tested_date", "test_date", "uat_signoff_date", "วันที่ทดสอบ"],
    "status": ["state", "สถานะ"],
}

COL_TH = {"change_id": "เลขที่คำขอ", "deploy_id": "Deploy ID", "system": "ระบบ",
          "deploy_datetime": "วันเวลานำขึ้น", "deployed_by": "ผู้นำขึ้นระบบ", "change_type": "ประเภท",
          "developer": "ผู้พัฒนา", "approved_by": "ผู้อนุมัติ", "approval_date": "วันที่อนุมัติ",
          "title": "เรื่อง", "month": "เดือน"}
FIELDS = ["change_id", "deploy_id", "system", "deploy_datetime", "deployed_by", "change_type", "developer",
          "approved_by", "approval_date", "title"]


@dataclass
class Params:
    work_start: int = 8
    work_end: int = 18
    emergency_days: int = 3          # อนุมัติ emergency ย้อนหลังภายใน n วัน
    emergency_ratio: float = 0.10    # เกณฑ์สัดส่วน emergency


def load(deployments, tickets, names: dict | None = None):
    names = names or {}
    return (read_table(deployments, names.get("deployments"), ALIASES),
            read_table(tickets, names.get("tickets"), ALIASES))


def analyze(dep: pd.DataFrame, tix: pd.DataFrame, params: Params | None = None) -> dict:
    p = params or Params()
    require(dep, ["change_id", "deploy_datetime", "deployed_by"], "Deployment log")
    require(tix, ["change_id", "approved_by"], "Tickets")
    dep = ensure(dep.copy(), ["deploy_id", "system", "description"])
    tix = ensure(tix.copy(), ["change_type", "title", "requested_by", "developer", "approval_date",
                              "uat_by", "uat_date", "status"])
    for df in (dep, tix):
        df["change_id"] = df["change_id"].astype(str).str.strip().str.upper()
    dep["deploy_datetime"] = parse_dates(dep["deploy_datetime"])
    tix["approval_date"] = parse_dates(tix["approval_date"])
    tix["uat_date"] = parse_dates(tix["uat_date"])
    tix["is_emergency"] = tix["change_type"].str.lower().str.contains("emerg|ฉุกเฉิน", regex=True)
    tix = tix.drop_duplicates("change_id")

    m = dep.merge(tix, on="change_id", how="left", indicator=True, suffixes=("", "_t"))
    m["is_emergency"] = m["is_emergency"].fillna(False).astype(bool)
    low = lambda c: m[c].fillna("").astype(str).str.strip().str.lower()
    rows = []

    def add(cid, mask, detail):
        for _, r in m[mask].iterrows():
            rows.append({"check_id": cid, **{c: r.get(c, "") for c in FIELDS},
                         "detail": detail(r) if callable(detail) else detail})

    no_ref = m["change_id"].isin(["", "NAN", "NONE", "-"])
    found = m["_merge"] == "both"
    add("CHG-01", no_ref, "ไม่มีเลขที่ใบคำขอใน log การ deploy")
    add("CHG-02", ~no_ref & ~found, lambda r: f"ไม่พบ {r.change_id} ในระบบ ITSM")

    unapproved = found & ((low("approved_by") == "") | low("status").str.contains("reject|cancel|ไม่อนุมัติ"))
    add("CHG-03", unapproved, lambda r: "ไม่มีผู้อนุมัติ" if not str(r.approved_by).strip()
        else f"สถานะใบคำขอ: {r.status}")

    appr_day = m["approval_date"].dt.normalize()
    dep_day = m["deploy_datetime"].dt.normalize()
    late = found & ~unapproved & appr_day.notna() & (appr_day > dep_day)
    add("CHG-04", late & ~m["is_emergency"], lambda r: f"deploy {r.deploy_datetime:%Y-%m-%d} "
        f"แต่อนุมัติ {r.approval_date:%Y-%m-%d} ({(r.approval_date.normalize() - r.deploy_datetime.normalize()).days} วันหลัง)")
    em_late = found & m["is_emergency"] & (appr_day.isna() | ((appr_day - dep_day).dt.days > p.emergency_days))
    add("CHG-05", em_late, lambda r: "ยังไม่อนุมัติ" if pd.isna(r.approval_date) else
        f"อนุมัติย้อนหลัง {(r.approval_date.normalize() - r.deploy_datetime.normalize()).days} วัน "
        f"(เกณฑ์ {p.emergency_days} วัน)")

    own = found & (low("developer") != "") & (low("developer") == low("deployed_by"))
    add("CHG-06", own, lambda r: f"{r.developer} พัฒนาและนำขึ้นระบบเอง")

    no_uat = found & (low("uat_by") == "") & m["uat_date"].isna()
    uat_after = found & m["uat_date"].notna() & (m["uat_date"].dt.normalize() > dep_day)
    add("CHG-07", no_uat & ~m["is_emergency"], "ไม่มีหลักฐานการทดสอบ/ลงนาม UAT")
    add("CHG-07", uat_after, lambda r: f"UAT วันที่ {r.uat_date:%Y-%m-%d} หลัง deploy {r.deploy_datetime:%Y-%m-%d}")

    appr = low("approved_by")
    self_appr = found & (appr != "") & ((appr == low("requested_by")) | (appr == low("developer")))
    add("CHG-08", self_appr, lambda r: f"{r.approved_by} เป็นทั้ง"
        + ("ผู้ขอ" if str(r.approved_by).lower() == str(r.requested_by).lower() else "ผู้พัฒนา") + "และผู้อนุมัติ")

    h = m["deploy_datetime"].dt.hour + m["deploy_datetime"].dt.minute / 60
    off = m["deploy_datetime"].notna() & ((m["deploy_datetime"].dt.dayofweek >= 5) | (h < p.work_start)
                                          | (h >= p.work_end))
    add("CHG-09", off & ~m["is_emergency"], lambda r: f"deploy {r.deploy_datetime:%a %Y-%m-%d %H:%M}")

    n_em, n_all = int(m["is_emergency"].sum()), len(m)
    ratio = n_em / n_all if n_all else 0
    if n_all and ratio > p.emergency_ratio:
        rows.append({"check_id": "CHG-10", "change_id": "ทั้งงวด",
                     "detail": f"Emergency {n_em} จาก {n_all} รายการ ({ratio:.1%}) เกินเกณฑ์ {p.emergency_ratio:.0%}"})

    findings = sort_findings(make_findings(rows, CHECKS, FIELDS), ["change_id"])
    m["month"] = m["deploy_datetime"].dt.to_period("M").astype(str)
    m["ประเภท"] = np.where(m["is_emergency"], "Emergency", np.where(found, "Normal/Standard", "ไม่มีใบคำขอ"))
    monthly = m.pivot_table(index="month", columns="ประเภท", values="deployed_by", aggfunc="count",
                            fill_value=0).reset_index()
    by_system = m.groupby("system").agg(deploys=("deployed_by", "size"),
                                        emergency=("is_emergency", "sum")).reset_index()
    flagged = findings["change_id"].replace("ทั้งงวด", np.nan).dropna()
    stats = {"deploys": n_all, "tickets": len(tix), "emergency": n_em, "emergency_ratio": ratio,
             "deploys_with_issue": int(m["change_id"].isin(set(flagged)).sum() + no_ref.sum()),
             "period": (f"{m['deploy_datetime'].min():%Y-%m-%d} ถึง {m['deploy_datetime'].max():%Y-%m-%d}"
                        if m["deploy_datetime"].notna().any() else "-")}
    return {"findings": findings, "monthly": monthly, "by_system": by_system, "stats": stats}


def write_report(res: dict, out, org: str = "(ไม่ระบุ)"):
    s = res["stats"]
    info = [("องค์กร", org), ("ช่วงเวลา", s["period"]), ("จำนวนการนำขึ้นระบบ", s["deploys"]),
            ("จำนวนใบคำขอใน ITSM", s["tickets"]),
            ("Emergency change", f"{s['emergency']} ({s['emergency_ratio']:.1%})")]
    write_findings_report(out, "รายงานการตรวจสอบการบริหารการเปลี่ยนแปลง (Change Management)", info,
                          CHECKS, res["findings"], COL_TH,
                          extra_sheets={"Monthly Trend": res["monthly"], "By System": res["by_system"]},
                          note="ประชากรคือ log การ deploy จากระบบจริง (ไม่ใช่รายการใบคำขอ) "
                               "เพื่อให้ครอบคลุมการเปลี่ยนแปลงที่ไม่ผ่านกระบวนการ")


# ----------------------------------------------------------------------------
# ข้อมูลตัวอย่าง
# ----------------------------------------------------------------------------

def demo_frames(seed: int = 11):
    rng = np.random.default_rng(seed)
    systems = ["ERP", "CoreBanking", "Website"]
    devs = ["dev.anon", "dev.somkiat", "dev.pailin", "dev.tawan"]
    ops = ["ops.kriangsak", "ops.mayuree"]
    approvers = ["cab.chairman", "it.manager"]
    requesters = ["biz.somchai", "biz.nida", "biz.preeya"]
    days = pd.bdate_range("2026-01-05", "2026-09-30")
    dep, tix = [], []
    for i in range(120):
        cid = f"CHG{1000 + i}"
        d = days[rng.integers(len(days))]
        dt = d + pd.Timedelta(hours=float(rng.uniform(9, 17)))
        emerg = i % 8 == 0                                    # 15 รายการ = 12.5%
        appr_dt = (dt.normalize() + pd.Timedelta(days=int(rng.integers(0, 2)))) if emerg else \
                  (dt.normalize() - pd.Timedelta(days=int(rng.integers(2, 10))))
        tix.append(dict(change_id=cid, change_type="Emergency" if emerg else "Normal",
                        title=f"ปรับปรุง {systems[i % 3]} รอบที่ {i}", requested_by=requesters[i % 3],
                        developer=devs[i % 4], approved_by=approvers[i % 2],
                        approval_date=appr_dt.strftime("%Y-%m-%d"),
                        uat_by="" if emerg else requesters[i % 3],
                        uat_date="" if emerg else (dt.normalize() - pd.Timedelta(days=1)).strftime("%Y-%m-%d"),
                        status="Closed"))
        dep.append(dict(deploy_id=f"D{5000 + i}", change_id=cid, system=systems[i % 3],
                        deploy_datetime=dt.strftime("%Y-%m-%d %H:%M"), deployed_by=ops[i % 2],
                        description=f"release {cid}"))
    t = {r["change_id"]: r for r in tix}
    d = {r["change_id"]: r for r in dep}
    # --- ฝังความผิดปกติ ---
    for i in (5, 41, 77):                                    # CHG-01 ไม่มีเลขที่คำขอ
        d[f"CHG{1000 + i}"]["change_id"] = ""
    for i, fake in ((13, "CHG9001"), (59, "CHG9002")):       # CHG-02 อ้างเลขที่ไม่มีจริง
        d[f"CHG{1000 + i}"]["change_id"] = fake
    for i in (21, 66, 95):                                   # CHG-03 ไม่อนุมัติ
        t[f"CHG{1000 + i}"]["approved_by"] = ""
    t["CHG1066"]["status"] = "Rejected"
    t["CHG1066"]["approved_by"] = "it.manager"
    for i in (29, 51, 103):                                  # CHG-04 อนุมัติหลัง deploy
        dd = pd.Timestamp(d[f"CHG{1000 + i}"]["deploy_datetime"])
        t[f"CHG{1000 + i}"]["approval_date"] = (dd + pd.Timedelta(days=4)).strftime("%Y-%m-%d")
    for i in (16, 88):                                       # CHG-05 emergency อนุมัติช้า
        dd = pd.Timestamp(d[f"CHG{1000 + i}"]["deploy_datetime"])
        t[f"CHG{1000 + i}"]["approval_date"] = (dd + pd.Timedelta(days=12)).strftime("%Y-%m-%d")
    for i in (33, 70, 110):                                  # CHG-06 dev deploy เอง
        d[f"CHG{1000 + i}"]["deployed_by"] = t[f"CHG{1000 + i}"]["developer"]
    for i in (37, 62, 99, 115):                              # CHG-07 ไม่มี UAT
        t[f"CHG{1000 + i}"].update(uat_by="", uat_date="")
    for i in (45, 82):                                       # CHG-07 UAT หลัง deploy
        dd = pd.Timestamp(d[f"CHG{1000 + i}"]["deploy_datetime"])
        t[f"CHG{1000 + i}"]["uat_date"] = (dd + pd.Timedelta(days=2)).strftime("%Y-%m-%d")
    t["CHG1053"]["approved_by"] = t["CHG1053"]["requested_by"]     # CHG-08
    t["CHG1091"]["approved_by"] = t["CHG1091"]["developer"]
    for i, ts in ((27, "2026-03-14 10:30"), (58, "2026-05-20 22:15"),     # CHG-09 นอกเวลา
                  (85, "2026-07-11 14:00"), (113, "2026-09-02 02:40")):
        d[f"CHG{1000 + i}"]["deploy_datetime"] = ts
        t[f"CHG{1000 + i}"]["approval_date"] = "2026-01-02"
        t[f"CHG{1000 + i}"]["uat_date"] = "2026-01-02"
    return pd.DataFrame(list(d.values())), pd.DataFrame(list(t.values()))
