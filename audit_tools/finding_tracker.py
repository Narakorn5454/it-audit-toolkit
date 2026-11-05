"""
Audit Finding Tracker — ติดตามข้อตรวจพบและแผนแก้ไข พร้อมรายงานต่อคณะกรรมการตรวจสอบ
==================================================================================
คอลัมน์: finding_id, audit_name, title, area, risk, owner, department, issue_date, due_date,
         revised_due_date, status, closed_date, action_plan, latest_update
สถานะ: Open, In Progress, Closed, Risk Accepted
"""

from __future__ import annotations

import re
from datetime import date

import numpy as np
import pandas as pd

from .common import AuditError, ensure, parse_dates, read_raw, standardize_columns, write_df

COLUMNS = ["finding_id", "audit_name", "title", "area", "risk", "owner", "department", "issue_date",
           "due_date", "revised_due_date", "status", "closed_date", "action_plan", "latest_update"]
STATUSES = ["Open", "In Progress", "Closed", "Risk Accepted"]
RISKS = ["High", "Medium", "Low"]
DONE = {"closed", "risk accepted"}
BUCKETS = ["ยังไม่ถึงกำหนด", "เกิน 1–30 วัน", "เกิน 31–60 วัน", "เกิน 61–90 วัน", "เกิน 90 วัน"]

ALIASES = {
    "finding_id": ["id", "ref", "reference", "เลขที่", "รหัส"],
    "audit_name": ["audit", "engagement", "งานตรวจ", "ชื่องานตรวจ"],
    "title": ["finding", "issue", "ข้อตรวจพบ", "หัวข้อ"],
    "area": ["category", "process", "หมวด", "กระบวนการ"],
    "risk": ["rating", "severity", "risk_rating", "ระดับความเสี่ยง", "ความเสี่ยง"],
    "owner": ["responsible", "action_owner", "ผู้รับผิดชอบ"],
    "department": ["dept", "unit", "ฝ่าย", "หน่วยงาน"],
    "issue_date": ["reported_date", "report_date", "วันที่รายงาน"],
    "due_date": ["target_date", "กำหนดแล้วเสร็จ"],
    "revised_due_date": ["revised_date", "new_due_date", "กำหนดใหม่"],
    "status": ["สถานะ"],
    "closed_date": ["completion_date", "วันที่ปิด"],
    "action_plan": ["management_action", "management_response", "แผนแก้ไข", "คำชี้แจงจากหน่วยรับตรวจ"],
    "latest_update": ["update", "comment", "ความคืบหน้า"],
}

COL_TH = {"finding_id": "เลขที่", "audit_name": "งานตรวจ", "title": "ข้อตรวจพบ", "area": "หมวด", "risk": "ระดับความเสี่ยง",
          "owner": "ผู้รับผิดชอบ", "department": "ฝ่าย", "issue_date": "วันที่รายงาน", "due_date": "กำหนดเดิม",
          "revised_due_date": "กำหนดใหม่", "status": "สถานะ", "closed_date": "วันที่ปิด", "action_plan": "แผนแก้ไข",
          "latest_update": "ความคืบหน้าล่าสุด", "effective_due": "กำหนดที่ใช้", "days_overdue": "เกินกำหนด (วัน)",
          "aging": "อายุเกินกำหนด", "extended": "เลื่อนกำหนด", "repeat": "พบซ้ำ", "open": "ค้าง", "overdue": "เกินกำหนด",
          "total": "ทั้งหมด", "closed": "ปิดแล้ว"}


def load(src, name=None) -> pd.DataFrame:
    df = standardize_columns(read_raw(src, name), ALIASES)
    if "title" not in df:
        raise AuditError("ไฟล์ต้องมีคอลัมน์ title (ข้อตรวจพบ) — ดาวน์โหลดแบบฟอร์มจากหน้านี้")
    df = ensure(df, COLUMNS)
    return df[COLUMNS]


def _norm_title(s: str) -> str:
    return re.sub(r"[\W_]+", "", str(s).lower())


def analyze(df: pd.DataFrame, as_of: date | None = None) -> dict:
    today = pd.Timestamp(as_of or date.today())
    d = ensure(df.copy(), COLUMNS)
    d = d[d["title"].astype(str).str.strip() != ""].reset_index(drop=True)
    if d.empty:
        raise AuditError("ไม่มีข้อตรวจพบในไฟล์")
    for c in ("issue_date", "due_date", "revised_due_date", "closed_date"):
        d[c] = parse_dates(d[c])
    d["status"] = d["status"].astype(str).str.strip().replace({"": "Open", "nan": "Open"})
    d["risk"] = d["risk"].astype(str).str.strip().str.capitalize().replace({"": "Medium", "Nan": "Medium"})
    d["finding_id"] = [fid if str(fid).strip() not in ("", "nan") else f"F-{i + 1:03d}"
                       for i, fid in enumerate(d["finding_id"])]
    d["effective_due"] = d["revised_due_date"].fillna(d["due_date"])
    d["extended"] = d["revised_due_date"].notna() & (d["revised_due_date"] != d["due_date"])
    is_open = ~d["status"].str.lower().isin(DONE)
    d["days_overdue"] = np.where(is_open & d["effective_due"].notna(),
                                 (today - d["effective_due"]).dt.days.clip(lower=0), 0).astype(int)
    d["overdue"] = is_open & (d["days_overdue"] > 0)

    def bucket(r):
        if not r.overdue:
            return BUCKETS[0]
        x = r.days_overdue
        return BUCKETS[1] if x <= 30 else BUCKETS[2] if x <= 60 else BUCKETS[3] if x <= 90 else BUCKETS[4]

    d["aging"] = [bucket(r) if o else "" for r, o in zip(d.itertuples(), is_open)]
    key = d["title"].map(_norm_title)
    d["repeat"] = key.map(key.value_counts()) > 1
    d["closed_late"] = ~is_open & d["closed_date"].notna() & d["effective_due"].notna() & \
        (d["closed_date"] > d["effective_due"])

    open_ = d[is_open]
    kpi = {"total": len(d), "open": int(is_open.sum()), "overdue": int(d["overdue"].sum()),
           "overdue_high": int((d["overdue"] & (d["risk"] == "High")).sum()),
           "extended": int(d["extended"].sum()), "repeat": int(d["repeat"].sum()),
           "closed": int((~is_open).sum()),
           "on_time_rate": (float(round((~d.loc[~is_open, "closed_late"]).mean() * 100, 0))
                            if (~is_open).any() else None),
           "avg_days_overdue": round(float(d.loc[d["overdue"], "days_overdue"].mean()), 0) if d["overdue"].any() else 0}
    by_status = pd.crosstab(d["risk"], d["status"]).reindex(index=[r for r in RISKS if r in set(d["risk"])]).reset_index()
    aging = pd.crosstab(open_["aging"], open_["risk"]).reindex(BUCKETS, fill_value=0).reset_index() \
        if not open_.empty else pd.DataFrame()
    by_dept = d.groupby("department").agg(total=("finding_id", "size"), open=("overdue", lambda s: int(is_open[s.index].sum())),
                                          overdue=("overdue", "sum")).reset_index().sort_values("overdue", ascending=False)
    upcoming = open_[(open_["effective_due"] >= today) & (open_["effective_due"] <= today + pd.Timedelta(days=30))]
    return {"data": d, "kpi": kpi, "by_status": by_status, "aging": aging, "by_dept": by_dept,
            "overdue": d[d["overdue"]].sort_values(["risk", "days_overdue"], key=lambda s: s.map({"High": 0, "Medium": 1, "Low": 2})
                                                     if s.name == "risk" else -s),
            "upcoming": upcoming, "as_of": today}


def followup_emails(res: dict) -> pd.DataFrame:
    """ร่างอีเมลติดตามรายผู้รับผิดชอบ (เกินกำหนด + ใกล้ครบกำหนดใน 30 วัน)"""
    d = res["data"]
    today = res["as_of"]
    items = pd.concat([res["overdue"].assign(_k="overdue"), res["upcoming"].assign(_k="upcoming")])
    out = []
    for owner, g in items.groupby(items["owner"].replace("", "(ไม่ระบุผู้รับผิดชอบ)")):
        greet = owner if str(owner).startswith(("คุณ", "Khun", "Mr", "Ms", "(")) else f"คุณ{owner}"
        lines = [f"เรียน {greet}", "",
                 f"ฝ่ายตรวจสอบขอติดตามความคืบหน้าการแก้ไขข้อตรวจพบ ณ วันที่ {today:%d/%m/%Y} ดังนี้", ""]
        od = g[g["_k"] == "overdue"]
        if len(od):
            lines.append(f"รายการที่เกินกำหนด ({len(od)} รายการ)")
            for r in od.itertuples():
                lines.append(f"  • [{r.finding_id}] {r.title} (ความเสี่ยง {r.risk}) — กำหนด "
                             f"{r.effective_due:%d/%m/%Y} เกินมา {r.days_overdue} วัน")
            lines.append("")
        up = g[g["_k"] == "upcoming"]
        if len(up):
            lines.append(f"รายการที่จะครบกำหนดภายใน 30 วัน ({len(up)} รายการ)")
            for r in up.itertuples():
                lines.append(f"  • [{r.finding_id}] {r.title} — กำหนด {r.effective_due:%d/%m/%Y}")
            lines.append("")
        lines += ["ขอความกรุณาแจ้งความคืบหน้าพร้อมหลักฐานการแก้ไข หรือหากต้องการขอเลื่อนกำหนด "
                  "กรุณาแจ้งเหตุผลและกำหนดใหม่ที่ได้รับอนุมัติจากผู้บังคับบัญชา", "", "ขอบคุณครับ/ค่ะ", "ฝ่ายตรวจสอบภายใน"]
        out.append({"owner": owner, "department": g["department"].iloc[0], "overdue": len(od), "upcoming": len(up),
                    "subject": f"ติดตามการแก้ไขข้อตรวจพบ: เกินกำหนด {len(od)} รายการ / ใกล้ครบกำหนด {len(up)} รายการ",
                    "body": "\n".join(lines)})
    return pd.DataFrame(out)


def import_toolkit_report(src, name=None, audit_name: str = "", owner: str = "", department: str = "") -> pd.DataFrame:
    """นำเข้าชีต Findings จากรายงานของเครื่องมืออื่นในชุดนี้ → 1 ข้อตรวจพบต่อ 1 รหัสการตรวจ"""
    try:
        xl = pd.ExcelFile(src)
        f = pd.read_excel(xl, "Findings", dtype=str).fillna("")
        meth = pd.read_excel(xl, "Methodology", dtype=str).fillna("") if "Methodology" in xl.sheet_names else None
    except Exception as e:  # noqa: BLE001
        raise AuditError(f"อ่านรายงานไม่ได้ (ต้องเป็นไฟล์ Excel จากเครื่องมือในชุดนี้ที่มีชีต Findings): {e}") from e
    cid = next((c for c in f.columns if c in ("รหัสการตรวจ", "check_id")), None)
    sev = next((c for c in f.columns if c in ("ระดับความเสี่ยง", "severity")), None)
    det = next((c for c in f.columns if c in ("รายละเอียด", "detail")), None)
    rec = next((c for c in f.columns if c in ("ข้อเสนอแนะ", "recommendation")), None)
    if not cid:
        raise AuditError("ไม่พบคอลัมน์รหัสการตรวจในชีต Findings")
    titles = dict(zip(meth.iloc[:, 0], meth.iloc[:, 1])) if meth is not None else {}
    today = pd.Timestamp.today().normalize()
    due_days = {"High": 30, "Medium": 60, "Low": 90, "Review": 90}
    rows = []
    for k, g in f.groupby(cid, sort=False):
        risk = g[sev].iloc[0] if sev else "Medium"
        risk = "Medium" if risk == "Review" else risk
        sample = "; ".join(g[det].head(3)) if det else ""
        rows.append({"finding_id": "", "audit_name": audit_name, "title": f"{k} {titles.get(k, '')} ({len(g)} รายการ)",
                     "area": k.split("-")[0], "risk": risk, "owner": owner, "department": department,
                     "issue_date": today.strftime("%Y-%m-%d"),
                     "due_date": (today + pd.Timedelta(days=due_days.get(risk, 60))).strftime("%Y-%m-%d"),
                     "revised_due_date": "", "status": "Open", "closed_date": "",
                     "action_plan": g[rec].iloc[0] if rec else "", "latest_update": f"ตัวอย่าง: {sample}"[:500]})
    return pd.DataFrame(rows, columns=COLUMNS)


def write_report(res: dict, out, org: str = "(ไม่ระบุ)"):
    k = res["kpi"]
    with pd.ExcelWriter(out, engine="openpyxl") as xw:
        info = pd.DataFrame([("องค์กร", org), ("ข้อมูล ณ วันที่", f"{res['as_of']:%Y-%m-%d}"),
                             ("ข้อตรวจพบทั้งหมด", k["total"]), ("ปิดแล้ว", k["closed"]), ("ยังค้าง", k["open"]),
                             ("เกินกำหนด", k["overdue"]), ("เกินกำหนด (ความเสี่ยงสูง)", k["overdue_high"]),
                             ("ค่าเฉลี่ยวันเกินกำหนด", k["avg_days_overdue"]), ("เคยเลื่อนกำหนด", k["extended"]),
                             ("ข้อตรวจพบที่พบซ้ำ", k["repeat"]),
                             ("ปิดได้ตามกำหนด (%)", k["on_time_rate"] if k["on_time_rate"] is not None else "-")],
                            columns=["ตัวชี้วัด", "ค่า"])
        write_df(xw, info, "Summary", widths=[34, 20])
        write_df(xw, res["by_status"], "Risk x Status", COL_TH)
        if not res["aging"].empty:
            write_df(xw, res["aging"].rename(columns={"aging": "อายุเกินกำหนด"}), "Aging", COL_TH)
        write_df(xw, res["by_dept"], "By Department", COL_TH)
        cols = ["finding_id", "audit_name", "title", "risk", "owner", "department", "effective_due", "days_overdue",
                "status", "latest_update"]
        if not res["overdue"].empty:
            write_df(xw, res["overdue"][cols], "Overdue", COL_TH, sev_names=("risk",))
        data = res["data"].drop(columns=["overdue", "closed_late"])
        write_df(xw, data, "All Findings", COL_TH, sev_names=("risk",))
        em = followup_emails(res)
        if not em.empty:
            write_df(xw, em, "Follow-up Emails", {"owner": "ผู้รับผิดชอบ", "department": "ฝ่าย", "subject": "หัวเรื่อง",
                                                    "body": "เนื้อหา", "overdue": "เกินกำหนด", "upcoming": "ใกล้ครบกำหนด"},
                     widths=[18, 16, 10, 10, 50, 100])


def demo_frame(as_of: date | None = None) -> pd.DataFrame:
    t = pd.Timestamp(as_of or date.today()).normalize()
    d = lambda n: (t + pd.Timedelta(days=n)).strftime("%Y-%m-%d")
    rows = [
        ("IA-25-01", "ITGC 2025", "บัญชีผู้ใช้ของพนักงานลาออกยังเปิดใช้งาน", "Access", "High", "คุณวิชัย", "IT", d(-300), d(-240), "", "Closed", d(-250), "ปิดบัญชีและเชื่อม HR กับ AD", "ปิดแล้ว"),
        ("IA-25-02", "ITGC 2025", "ไม่มีการทบทวนสิทธิ์ผู้ใช้ประจำปี", "Access", "Medium", "คุณวิชัย", "IT", d(-300), d(-200), d(-100), "In Progress", "", "จัดทำกระบวนการทบทวนสิทธิ์", "รอผู้บริหารลงนาม"),
        ("IA-25-03", "ITGC 2025", "ผู้พัฒนามีสิทธิ์นำโปรแกรมขึ้นระบบจริง", "Change", "High", "คุณสมเกียรติ", "IT", d(-300), d(-210), "", "Open", "", "แยกสิทธิ์ผ่าน CI/CD", ""),
        ("IA-25-04", "ITGC 2025", "ไม่ได้ทดสอบการกู้คืนข้อมูลสำรอง", "Operations", "Medium", "คุณเกรียงศักดิ์", "IT Operations", d(-300), d(-150), "", "Closed", d(-120), "ทดสอบกู้คืนรายไตรมาส", "ปิดล่าช้า"),
        ("IA-25-05", "PDPA 2025", "ยังไม่มีบันทึกรายการกิจกรรมการประมวลผล (ROPA)", "Privacy", "High", "คุณนภา", "Legal", d(-200), d(-110), d(-40), "In Progress", "", "จ้างที่ปรึกษาจัดทำ ROPA", "เสร็จ 70%"),
        ("IA-25-06", "PDPA 2025", "Privacy Notice บนเว็บไซต์ไม่ครบตามมาตรา 23", "Privacy", "Medium", "คุณนภา", "Legal", d(-200), d(-140), "", "Closed", d(-145), "ปรับปรุง Privacy Notice", "ปิดแล้ว"),
        ("IA-25-07", "PDPA 2025", "ไม่มีสัญญาประมวลผลข้อมูลกับผู้ให้บริการ Cloud", "Privacy", "High", "คุณประภา", "Procurement", d(-200), d(-80), "", "Open", "", "เจรจา DPA กับผู้ให้บริการ", "รอผู้ให้บริการตอบกลับ"),
        ("IA-26-01", "ITGC 2026", "ผู้พัฒนามีสิทธิ์นำโปรแกรมขึ้นระบบจริง", "Change", "High", "คุณสมเกียรติ", "IT", d(-60), d(-5), "", "Open", "", "แยกสิทธิ์ผ่าน CI/CD", "พบซ้ำจากปี 2025"),
        ("IA-26-02", "ITGC 2026", "Security group เปิด SSH สู่อินเทอร์เน็ต", "Cloud", "High", "คุณธีระ", "Cloud", d(-60), d(-30), "", "Closed", d(-35), "จำกัด IP ต้นทาง", "ปิดแล้ว"),
        ("IA-26-03", "ITGC 2026", "Root account AWS ไม่มี MFA", "Cloud", "High", "คุณธีระ", "Cloud", d(-60), d(-45), "", "Closed", d(-50), "เปิด hardware MFA", "ปิดแล้ว"),
        ("IA-26-04", "ITGC 2026", "Access key ไม่ได้หมุนเวียนเกิน 1 ปี", "Cloud", "Medium", "คุณธีระ", "Cloud", d(-60), d(20), "", "In Progress", "", "เปลี่ยนเป็น IAM role", "เสร็จ 2 จาก 3 ระบบ"),
        ("IA-26-05", "ITGC 2026", "นโยบายรหัสผ่าน AD ไม่ล็อกบัญชีเมื่อใส่ผิด", "Access", "Medium", "คุณวิชัย", "IT", d(-60), d(15), "", "Open", "", "ตั้ง lockout 5 ครั้ง", ""),
        ("IA-26-06", "JE Testing 2026", "ผู้บันทึกบัญชีอนุมัติรายการของตนเองได้", "Finance", "High", "คุณสมศรี", "Accounting", d(-45), d(-10), "", "In Progress", "", "ตั้ง workflow อนุมัติในระบบ", "รอ IT ปรับระบบ"),
        ("IA-26-07", "JE Testing 2026", "รายการบันทึกบัญชีนอกเวลาทำการโดยบัญชี IT", "Finance", "High", "คุณธีระ", "IT", d(-45), d(-15), "", "Open", "", "ถอดสิทธิ์บันทึกบัญชีของ IT", ""),
        ("IA-26-08", "Vendor Review 2026", "ผู้ให้บริการไม่ได้ทดสอบ DR ประจำปี", "Third Party", "Medium", "คุณประภา", "Procurement", d(-30), d(60), "", "Open", "", "กำหนดในสัญญาฉบับใหม่", ""),
        ("IA-26-09", "AI Governance 2026", "ไม่มีทะเบียนระบบ AI ขององค์กร", "AI", "Medium", "คุณอรุณ", "Digital", d(-20), d(70), "", "Open", "", "สำรวจระบบ AI ทุกฝ่าย", ""),
        ("IA-26-10", "AI Governance 2026", "ไม่มีนโยบายการใช้ GenAI ของพนักงาน", "AI", "High", "คุณอรุณ", "Digital", d(-20), d(25), "", "In Progress", "", "ร่างนโยบาย Acceptable Use", "ร่างแล้วรอ Legal"),
        ("IA-24-09", "ITGC 2024", "ไม่มีการบันทึก log การเข้าถึงฐานข้อมูล", "Logging", "Medium", "คุณเกรียงศักดิ์", "IT Operations", d(-500), d(-400), d(-200), "Risk Accepted", d(-180), "ผู้บริหารยอมรับความเสี่ยง", "ยอมรับความเสี่ยงถึงสิ้นปี"),
    ]
    return pd.DataFrame(rows, columns=COLUMNS)
