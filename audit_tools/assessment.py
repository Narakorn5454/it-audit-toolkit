"""
Assessment Engine — แบบประเมินพร้อมให้คะแนนอัตโนมัติ (ใช้กับ PDPA, Vendor Risk, AI Governance)
==============================================================================================
คำตอบ: Yes = 1, Partial = 0.5, No = 0, N/A = ไม่นับ, ว่าง = ยังไม่ตอบ (ไม่นับคะแนน แต่ลด % ความครบถ้วน)
คะแนนหมวด = Σ(น้ำหนัก × คะแนน) / Σ(น้ำหนัก) ของข้อที่ตอบและเกี่ยวข้อง
"""

from __future__ import annotations

import io
from datetime import datetime

import pandas as pd
from openpyxl import load_workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.styles import Font
from openpyxl.worksheet.datavalidation import DataValidation

from .common import AuditError, read_raw, style_sheet, write_df

ANSWER_SCORE = {"yes": 1.0, "partial": 0.5, "no": 0.0}
ANSWER_TH = {"yes": "Yes", "ใช่": "Yes", "มี": "Yes", "partial": "Partial", "บางส่วน": "Partial",
             "no": "No", "ไม่": "No", "ไม่มี": "No", "n/a": "N/A", "na": "N/A", "ไม่เกี่ยวข้อง": "N/A"}
ANSWERS = ["Yes", "Partial", "No", "N/A"]
BANK_COLS = ["qid", "domain", "question", "reference", "weight", "evidence", "recommendation"]


def rating(score: float | None) -> str:
    if score is None or pd.isna(score):
        return "-"
    return ("ดี (Strong)" if score >= 80 else "พอใช้ (Moderate)" if score >= 60
            else "ต้องปรับปรุง (Weak)" if score >= 40 else "วิกฤต (Critical)")


def bank_df(bank: list[tuple]) -> pd.DataFrame:
    return pd.DataFrame(bank, columns=BANK_COLS)


def normalize_answer(a) -> str:
    a = str(a).strip()
    return ANSWER_TH.get(a.lower(), a if a in ANSWERS else "")


def score(bank: pd.DataFrame, answers: pd.DataFrame) -> dict:
    """answers: qid, answer, note"""
    df = bank.merge(answers[["qid", "answer", "note"]], on="qid", how="left")
    df["answer"] = df["answer"].fillna("").map(normalize_answer)
    df["note"] = df["note"].fillna("")
    df["weight"] = pd.to_numeric(df["weight"], errors="coerce").fillna(1)
    df["score"] = df["answer"].str.lower().map(ANSWER_SCORE)
    applicable = df["answer"] != "N/A"
    answered = df["score"].notna()
    df["points"] = df["score"] * df["weight"]

    def agg(g):
        a = g[g["score"].notna()]
        w = a["weight"].sum()
        return pd.Series({"questions": len(g), "answered": int(g["score"].notna().sum() + (g["answer"] == "N/A").sum()),
                          "score_pct": round(a["points"].sum() / w * 100, 1) if w else None,
                          "gaps": int((g["answer"].isin(["No", "Partial"])).sum())})

    domains = df.groupby("domain", sort=False).apply(agg, include_groups=False).reset_index()
    domains["rating"] = domains["score_pct"].map(rating)
    a = df[answered]
    overall = round(a["points"].sum() / a["weight"].sum() * 100, 1) if a["weight"].sum() else None
    completeness = round((answered | ~applicable).mean() * 100, 1)

    gaps = df[df["answer"].isin(["No", "Partial"])].copy()
    gaps["priority"] = gaps.apply(
        lambda r: "High" if r["weight"] >= 3 and r["answer"] == "No"
        else "Medium" if (r["weight"] >= 3) or (r["weight"] >= 2 and r["answer"] == "No") else "Low", axis=1)
    gaps["_p"] = gaps["priority"].map({"High": 0, "Medium": 1, "Low": 2})
    gaps = gaps.sort_values(["_p", "domain", "qid"]).drop(columns=["_p", "score", "points"])
    gaps = gaps[["priority", "qid", "domain", "question", "answer", "note", "reference", "recommendation"]]
    unanswered = df[~answered & applicable][["qid", "domain", "question"]]
    return {"responses": df.drop(columns=["points"]), "domains": domains, "overall": overall,
            "rating": rating(overall), "completeness": completeness, "gaps": gaps, "unanswered": unanswered}


# ----------------------------------------------------------------------------
# แบบฟอร์ม Excel (ส่งให้ผู้ตอบ → รับกลับมาให้คะแนน)
# ----------------------------------------------------------------------------

def template_bytes(bank: pd.DataFrame, title: str, answers: pd.DataFrame | None = None) -> bytes:
    df = bank[["qid", "domain", "question", "reference", "evidence"]].copy()
    if answers is not None:
        df = df.merge(answers[["qid", "answer", "note"]], on="qid", how="left").fillna("")
    else:
        df["answer"], df["note"] = "", ""
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        out = df.rename(columns={"qid": "qid", "domain": "หมวด", "question": "คำถาม", "reference": "อ้างอิง",
                                 "evidence": "หลักฐานที่คาดหวัง", "answer": "answer", "note": "note"})
        out.to_excel(xw, sheet_name="Questionnaire", index=False, startrow=3)
        ws = xw.sheets["Questionnaire"]
        ws["A1"] = title
        ws["A1"].font = Font(bold=True, size=14, color="1F3864")
        ws["A2"] = ("คำตอบในคอลัมน์ answer: Yes / Partial / No / N/A — ใส่รายละเอียดหรือชื่อเอกสารหลักฐานในคอลัมน์ note "
                    "(ห้ามแก้คอลัมน์ qid)")
        ws["A2"].font = Font(italic=True, color="C00000")
        style_sheet(ws, header_row=4, widths=[8, 24, 60, 22, 40, 12, 45])
        dv = DataValidation(type="list", formula1='"Yes,Partial,No,N/A"', allow_blank=True)
        ws.add_data_validation(dv)
        dv.add(f"F5:F{4 + len(out)}")
    return buf.getvalue()


def read_answers(src, name: str | None = None) -> pd.DataFrame:
    raw = read_raw(src, name)
    cols = [str(c).strip().lower() for c in raw.columns]
    if "qid" not in cols:          # แบบฟอร์มของเรามีหัวตารางที่แถว 4
        if hasattr(src, "seek"):
            src.seek(0)
        try:
            raw = pd.read_excel(src, dtype=str, header=3).fillna("")
        except Exception as e:  # noqa: BLE001
            raise AuditError(f"อ่านแบบฟอร์มไม่ได้: {e}") from e
        cols = [str(c).strip().lower() for c in raw.columns]
    raw.columns = cols
    if not {"qid", "answer"} <= set(cols):
        raise AuditError("แบบฟอร์มต้องมีคอลัมน์ qid และ answer (ใช้แบบฟอร์มที่ดาวน์โหลดจากหน้านี้)")
    if "note" not in raw:
        raw["note"] = ""
    raw["answer"] = raw["answer"].map(normalize_answer)
    return raw[["qid", "answer", "note"]]


# ----------------------------------------------------------------------------
# รายงาน
# ----------------------------------------------------------------------------

COL_TH = {"qid": "รหัส", "domain": "หมวด", "question": "คำถาม", "reference": "อ้างอิง", "weight": "น้ำหนัก",
          "evidence": "หลักฐานที่คาดหวัง", "recommendation": "ข้อเสนอแนะ", "answer": "คำตอบ", "note": "หมายเหตุ/หลักฐาน",
          "score": "คะแนน", "priority": "ลำดับความสำคัญ", "questions": "จำนวนข้อ", "answered": "ตอบแล้ว",
          "score_pct": "คะแนน (%)", "gaps": "ช่องว่าง", "rating": "ระดับ"}


def write_report(res: dict, out, title: str, info: list[tuple[str, object]], extra: dict | None = None):
    with pd.ExcelWriter(out, engine="openpyxl") as xw:
        d = res["domains"]
        d.to_excel(xw, sheet_name="Summary", index=False, startrow=len(info) + 8)
        ws = xw.sheets["Summary"]
        ws["A1"] = title
        ws["A1"].font = Font(bold=True, size=16, color="1F3864")
        rows = list(info) + [("วันที่ออกรายงาน", datetime.now().strftime("%Y-%m-%d %H:%M")),
                             ("คะแนนรวม", f"{res['overall']}%" if res["overall"] is not None else "-"),
                             ("ระดับ", res["rating"]), ("ความครบถ้วนของคำตอบ", f"{res['completeness']}%"),
                             ("ช่องว่างที่พบ", len(res["gaps"]))]
        for i, (k, v) in enumerate(rows, 3):
            ws.cell(row=i, column=1, value=k).font = Font(bold=True)
            ws.cell(row=i, column=2, value=v)
        hdr = len(info) + 9
        for j, c in enumerate(d.columns, 1):
            ws.cell(row=hdr, column=j, value=COL_TH.get(c, c))
        style_sheet(ws, header_row=hdr, widths=[36, 12, 12, 12, 12, 22], freeze=False)
        if len(d):
            ch = BarChart()
            ch.type, ch.title, ch.y_axis.title = "bar", "คะแนนรายหมวด (%)", "%"
            ch.add_data(Reference(ws, min_col=4, min_row=hdr, max_row=hdr + len(d)), titles_from_data=True)
            ch.set_categories(Reference(ws, min_col=1, min_row=hdr + 1, max_row=hdr + len(d)))
            ch.y_axis.scaling.min, ch.y_axis.scaling.max = 0, 100
            ch.height, ch.width, ch.legend = 9, 18, None
            ws.add_chart(ch, "H3")
        g = res["gaps"].copy()
        g["owner"], g["due_date"] = "", ""
        write_df(xw, g if len(g) else pd.DataFrame({"ผล": ["ไม่พบช่องว่าง"]}), "Gaps", COL_TH,
                 sev_names=("priority",))
        write_df(xw, res["responses"], "Responses", COL_TH)
        if len(res["unanswered"]):
            write_df(xw, res["unanswered"], "Unanswered", COL_TH)
        for name, df in (extra or {}).items():
            write_df(xw, df, name, COL_TH)


# ----------------------------------------------------------------------------
# Vendor risk: ความเสี่ยงตั้งต้น (inherent) × ผลประเมินการควบคุม → ความเสี่ยงคงเหลือ (residual)
# ----------------------------------------------------------------------------

VENDOR_PROFILE = {
    "data_access": ("ข้อมูลที่ผู้ให้บริการเข้าถึง", [("ไม่เข้าถึงข้อมูล", 0), ("ข้อมูลภายในทั่วไป", 1),
                                                   ("ข้อมูลลับ / ข้อมูลทางการเงิน", 2),
                                                   ("ข้อมูลส่วนบุคคล / ข้อมูลอ่อนไหว", 3)]),
    "criticality": ("ความสำคัญของบริการต่อธุรกิจ", [("ต่ำ", 0), ("ปานกลาง", 1), ("สูง: กระทบลูกค้าหากหยุด", 2),
                                                   ("วิกฤต: ธุรกิจหยุดหากหยุด", 3)]),
    "system_access": ("การเชื่อมต่อกับระบบขององค์กร", [("ไม่มี", 0), ("เข้าถึงระยะไกลแบบจำกัด", 1),
                                                       ("สิทธิ์ผู้ดูแลระบบ / เชื่อมเครือข่าย", 2)]),
    "volume": ("ปริมาณข้อมูล", [("น้อยกว่า 1,000 รายการ", 0), ("1,000–100,000 รายการ", 1),
                                ("มากกว่า 100,000 รายการ", 2)]),
    "substitutability": ("การหาผู้ให้บริการทดแทน", [("หาทดแทนได้ง่าย", 0), ("หาทดแทนได้ยาก", 1)]),
}

RESIDUAL = {  # inherent → [score≥80, 60–79, 40–59, <40]
    "Critical": ["Medium", "High", "Critical", "Critical"],
    "High": ["Low", "Medium", "High", "Critical"],
    "Medium": ["Low", "Low", "Medium", "High"],
    "Low": ["Low", "Low", "Low", "Medium"],
}
REVIEW_FREQ = {"Critical": "ทุก 6 เดือน + ตรวจเยี่ยม/ขอรายงาน SOC 2", "High": "ทุกปี + ขอหลักฐานประกอบ",
               "Medium": "ทุกปี (แบบสอบถาม)", "Low": "ทุก 2 ปี"}


def inherent_tier(profile: dict[str, int]) -> tuple[str, int]:
    pts = sum(profile.values())
    tier = "Critical" if pts >= 8 else "High" if pts >= 5 else "Medium" if pts >= 3 else "Low"
    return tier, pts


def residual_risk(tier: str, control_score: float | None) -> str:
    if control_score is None:
        return tier
    band = 0 if control_score >= 80 else 1 if control_score >= 60 else 2 if control_score >= 40 else 3
    return RESIDUAL[tier][band]
