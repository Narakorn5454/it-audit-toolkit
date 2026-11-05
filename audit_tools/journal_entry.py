#!/usr/bin/env python3
"""
Journal Entry Testing Tool สำหรับงาน IT Audit / Financial Audit
================================================================
วิเคราะห์รายการบันทึกบัญชี (General Ledger) ทั้งหมด 100% แทนการสุ่มตัวอย่าง
เพื่อหารายการที่มีความเสี่ยงต่อการตกแต่งบัญชีหรือการทุจริต
(อ้างอิงแนวทาง ISA 240 / TSA 240 และ PCAOB AS 2401)

การทดสอบรายเอกสาร (ให้คะแนนความเสี่ยงรวม):
  JE-01  เดบิตไม่เท่ากับเครดิต
  JE-02  ผู้บันทึกอนุมัติรายการเอง
  JE-03  บันทึกในวันเสาร์-อาทิตย์
  JE-04  บันทึกในวันหยุดนักขัตฤกษ์
  JE-05  บันทึกนอกเวลาทำการ
  JE-06  บันทึกหลังปิดงวดบัญชี (ย้อนหลังข้ามงวด)
  JE-07  บันทึกช่วงสิ้นงวด
  JE-08  ยอดเงินกลม
  JE-09  ยอดเงินต่ำกว่าวงเงินอนุมัติเล็กน้อย
  JE-10  ยอดเงินสูงผิดปกติ
  JE-11  คำอธิบายมีคำที่น่าสงสัย
  JE-12  ไม่มีคำอธิบายรายการ
  JE-13  ผู้บันทึกที่บันทึกรายการน้อยผิดปกติ
  JE-14  รายการซ้ำ

การทดสอบระดับประชากร:
  P-01   เลขที่เอกสารขาดหาย (Sequence gap)
  P-02   Benford's Law (ตัวเลขหลักแรก)

วิธีใช้:
  python journal_entry_testing.py --demo
  python journal_entry_testing.py --gl gl.xlsx --holidays holidays.xlsx --company "ABC" --period "FY2026"

ต้องใช้: pandas, openpyxl
"""

from __future__ import annotations

import argparse
import calendar
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

import numpy as np
import pandas as pd
from openpyxl.chart import BarChart, Reference
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

try:
    from .common import AuditError
except ImportError:  # รันไฟล์นี้เดี่ยว ๆ
    from common import AuditError

__version__ = "1.0.0"


class JEError(AuditError):
    """ข้อผิดพลาดของข้อมูล input ที่ควรแจ้งผู้ใช้"""


# ----------------------------------------------------------------------------
# พารามิเตอร์ (ปรับได้ตามความเสี่ยงของแต่ละองค์กร)
# ----------------------------------------------------------------------------

DEFAULT_KEYWORDS = [
    "adjust", "correction", "reverse", "reversal", "plug", "error", "misc",
    "suspense", "write off", "write-off", "per ceo", "per cfo", "per md", "manual",
    "ปรับปรุง", "แก้ไข", "กลับรายการ", "ล้างบัญชี", "ตามคำสั่ง", "พักบัญชี",
    "ผิดพลาด", "ปรับยอด", "ตัดจำหน่าย",
]


@dataclass
class Params:
    approval_thresholds: list[float] = field(default_factory=lambda: [50_000, 100_000, 500_000, 1_000_000])
    below_threshold_pct: float = 0.05      # ต่ำกว่าวงเงินไม่เกิน 5%
    work_start: int = 8                    # เวลาทำการ (ชั่วโมง)
    work_end: int = 18
    period_end_days: int = 3               # n วันสุดท้ายของเดือน
    close_days: int = 5                    # ปิดงวดภายใน n วันหลังสิ้นเดือน
    round_unit: float = 1_000              # ยอดหารด้วยค่านี้ลงตัว
    round_min: float = 10_000              # และไม่ต่ำกว่าค่านี้
    rare_user_max: int = 3                 # ผู้บันทึกที่มีรายการไม่เกิน n เอกสาร
    large_amount: float | None = None      # None = ใช้ percentile ที่ 99
    large_percentile: float = 99.0
    keywords: list[str] = field(default_factory=lambda: list(DEFAULT_KEYWORDS))
    holidays: set = field(default_factory=set)


# (ชื่อการทดสอบ, คะแนนความเสี่ยง, เหตุผล / ความเสี่ยง)
TESTS = {
    "JE-01": ("เดบิตไม่เท่ากับเครดิต", 5, "เอกสารไม่สมดุล อาจเกิดจากการแก้ไขข้อมูลโดยตรงหรือระบบควบคุมบกพร่อง"),
    "JE-02": ("ผู้บันทึกอนุมัติรายการเอง", 4, "ขาดการแบ่งแยกหน้าที่ ผู้บันทึกสามารถผ่านรายการได้โดยไม่มีผู้สอบทาน"),
    "JE-03": ("บันทึกในวันเสาร์-อาทิตย์", 2, "รายการนอกวันทำการ มีโอกาสหลบเลี่ยงการกำกับดูแล"),
    "JE-04": ("บันทึกในวันหยุดนักขัตฤกษ์", 2, "รายการในวันหยุด มีโอกาสหลบเลี่ยงการกำกับดูแล"),
    "JE-05": ("บันทึกนอกเวลาทำการ", 2, "รายการนอกเวลาทำการ อาจไม่มีผู้สอบทาน"),
    "JE-06": ("บันทึกหลังปิดงวดบัญชี", 3, "รายการย้อนหลังเข้างวดที่ปิดแล้ว เสี่ยงต่อการตกแต่งงบการเงิน"),
    "JE-07": ("บันทึกช่วงสิ้นงวด", 1, "รายการปรับปรุงช่วงสิ้นงวดมักเป็นจุดที่ใช้ตกแต่งผลประกอบการ"),
    "JE-08": ("ยอดเงินกลม", 1, "ยอดกลมมักเป็นการประมาณการหรือรายการที่สร้างขึ้นเอง"),
    "JE-09": ("ยอดเงินต่ำกว่าวงเงินอนุมัติเล็กน้อย", 3, "อาจเป็นการจงใจหลบเลี่ยงลำดับขั้นการอนุมัติ"),
    "JE-10": ("ยอดเงินสูงผิดปกติ", 2, "รายการมูลค่าสูงมีผลกระทบต่องบการเงินอย่างมีสาระสำคัญ"),
    "JE-11": ("คำอธิบายมีคำที่น่าสงสัย", 2, "คำเช่น ปรับปรุง แก้ไข plug มักเกี่ยวข้องกับรายการผิดปกติ"),
    "JE-12": ("ไม่มีคำอธิบายรายการ", 1, "ไม่มีหลักฐานหรือเหตุผลประกอบการบันทึก"),
    "JE-13": ("ผู้บันทึกที่บันทึกรายการน้อยผิดปกติ", 2, "ผู้ที่ปกติไม่ได้บันทึกบัญชี เช่น ผู้บริหารหรือ IT เข้ามาบันทึกเอง"),
    "JE-14": ("รายการซ้ำ", 3, "อาจเป็นการบันทึกซ้ำหรือจ่ายเงินซ้ำ"),
}

POP_TESTS = {
    "P-01": ("เลขที่เอกสารขาดหาย (Sequence gap)", "เอกสารที่ขาดหายอาจถูกลบหรือบันทึกนอกระบบ ข้อมูลอาจไม่ครบถ้วน"),
    "P-02": ("Benford's Law (ตัวเลขหลักแรก)", "การกระจายตัวเลขที่ผิดธรรมชาติ อาจบ่งชี้ถึงตัวเลขที่ถูกสร้างขึ้น"),
}


def severity_of(weight: int) -> str:
    return "High" if weight >= 4 else "Medium" if weight >= 2 else "Low"


def risk_level(score: int) -> str:
    return "High" if score >= 8 else "Medium" if score >= 4 else "Low"


# ----------------------------------------------------------------------------
# อ่านไฟล์และแปลงชื่อคอลัมน์
# ----------------------------------------------------------------------------

COLUMN_ALIASES = {
    "je_number": ["belnr", "document_no", "doc_no", "document_number", "journal_no", "journal_id",
                  "je_no", "jv_no", "voucher_no", "เลขที่เอกสาร", "เลขที่ใบสำคัญ", "เลขที่"],
    "line_no": ["buzei", "line", "line_number", "ลำดับ", "ลำดับที่"],
    "posting_date": ["budat", "post_date", "gl_date", "effective_date", "วันที่ลงบัญชี",
                     "วันที่บันทึกบัญชี", "วันที่เอกสาร", "date", "วันที่"],
    "entry_date": ["cpudt", "created_date", "creation_date", "entered_date", "system_date",
                   "วันที่บันทึก", "วันที่สร้าง", "วันที่บันทึกระบบ"],
    "entry_time": ["cputm", "created_time", "entry_time", "time", "เวลา", "เวลาบันทึก"],
    "account": ["hkont", "gl_account", "account_no", "account_code", "acct", "เลขที่บัญชี",
                "รหัสบัญชี"],
    "account_name": ["account_description", "txt50", "ชื่อบัญชี"],
    "description": ["sgtxt", "bktxt", "narration", "text", "memo", "line_description",
                    "คำอธิบาย", "รายละเอียด", "คำอธิบายรายการ"],
    "debit": ["dr", "debit_amount", "เดบิต"],
    "credit": ["cr", "credit_amount", "เครดิต"],
    "amount": ["dmbtr", "amount_lc", "จำนวนเงิน", "ยอดเงิน"],
    "dc_indicator": ["shkzg", "dr_cr", "debit_credit", "dc"],
    "created_by": ["usnam", "user", "user_id", "entered_by", "preparer", "posted_by",
                   "ผู้บันทึก", "ผู้จัดทำ"],
    "approved_by": ["approver", "reviewed_by", "ผู้อนุมัติ"],
    "source": ["blart", "doc_type", "document_type", "journal_source", "ประเภทเอกสาร"],
}

REQUIRED = ["je_number", "posting_date", "account", "created_by"]


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


def _read_raw(src, name=None) -> pd.DataFrame:
    if isinstance(src, (str, Path)):
        path = Path(src)
        if not path.exists():
            raise JEError(f"ไม่พบไฟล์: {path}")
        suffix = path.suffix.lower()
    else:
        suffix = Path(name or getattr(src, "name", "")).suffix.lower()
    try:
        if suffix in {".xlsx", ".xlsm", ".xls"}:
            return pd.read_excel(src, dtype=str)
        if suffix in {".csv", ".txt"}:
            return pd.read_csv(src, dtype=str, encoding="utf-8-sig")
    except Exception as e:
        raise JEError(f"อ่านไฟล์ไม่ได้ ({name or src}): {e}") from e
    raise JEError(f"รองรับเฉพาะไฟล์ .xlsx หรือ .csv ({name or src})")


def read_gl(src, name: str | None = None) -> pd.DataFrame:
    """อ่านไฟล์ General Ledger จาก path หรือไฟล์ที่อัปโหลด"""
    return _standardize_columns(_read_raw(src, name)).fillna("")


def read_holidays(src, name: str | None = None) -> set:
    """อ่านไฟล์วันหยุด: ใช้คอลัมน์ date (หรือคอลัมน์แรก)"""
    df = _read_raw(src, name).fillna("")
    cols = [str(c).strip().lower() for c in df.columns]
    col = df.columns[cols.index("date")] if "date" in cols else df.columns[0]
    return set(parse_dates(df[col]).dropna().dt.date)


# ----------------------------------------------------------------------------
# แปลงข้อมูล
# ----------------------------------------------------------------------------

_BE_YEAR = re.compile(r"\b(25[0-9]{2})\b")


def parse_dates(s: pd.Series) -> pd.Series:
    """รองรับ ค.ศ./พ.ศ., dd/mm/yyyy และ yyyy-mm-dd"""
    s = s.astype(str).str.strip().replace({"": None, "nan": None, "NaT": None, "None": None})
    s = s.str.replace(_BE_YEAR, lambda m: str(int(m.group(1)) - 543), regex=True)
    iso = s.str.match(r"^\d{4}-\d{2}-\d{2}", na=False)
    out = pd.Series(pd.NaT, index=s.index, dtype="datetime64[ns]")
    if iso.any():
        out[iso] = pd.to_datetime(s[iso], errors="coerce", format="mixed")
    if (~iso).any():
        out[~iso] = pd.to_datetime(s[~iso], errors="coerce", format="mixed", dayfirst=True)
    return out


def parse_times(s: pd.Series) -> pd.Series:
    """คืนค่าชั่วโมงทศนิยม (14:30 → 14.5); รองรับ 14:30, 14:30:15, 143015 (SAP)"""
    s = s.astype(str).str.strip()
    s = s.where(~s.str.fullmatch(r"\d{6}"), s.str[:2] + ":" + s.str[2:4] + ":" + s.str[4:])
    m = s.str.extract(r"(\d{1,2}):(\d{2})")
    return m[0].astype(float) + m[1].astype(float) / 60


def to_num(s: pd.Series) -> pd.Series:
    s = s.astype(str).str.strip().str.replace(",", "", regex=False)
    neg = s.str.startswith("(") & s.str.endswith(")")
    s = s.str.strip("()").str.replace(r"^-$", "", regex=True)
    trailing_minus = s.str.endswith("-")          # SAP: 1000.00-
    s = s.str.rstrip("-").where(trailing_minus, s)
    v = pd.to_numeric(s, errors="coerce").fillna(0.0)
    return v.where(~(neg | trailing_minus), -v)


def prepare(gl: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """แปลงข้อมูลระดับบรรทัด และบอกว่ามีข้อมูลอะไรให้ทดสอบบ้าง"""
    missing = [c for c in REQUIRED if c not in gl.columns]
    if missing:
        raise JEError(f"ไฟล์ GL ขาดคอลัมน์: {', '.join(missing)}\n"
                      f"คอลัมน์ที่มีในไฟล์: {', '.join(gl.columns)}")
    df = gl.copy()
    for c in ["approved_by", "description", "source", "account_name", "entry_date", "entry_time"]:
        if c not in df:
            df[c] = ""

    # จำนวนเงิน: แยก debit/credit, หรือ amount + ตัวบ่งชี้ S/H (SAP), หรือ amount มีเครื่องหมาย
    if "debit" in df and "credit" in df:
        df["debit"], df["credit"] = to_num(df["debit"]).abs(), to_num(df["credit"]).abs()
    elif "amount" in df:
        amt = to_num(df["amount"])
        if "dc_indicator" in df:
            ind = df["dc_indicator"].astype(str).str.strip().str.upper()
            is_dr = ind.isin(["S", "D", "DR", "DEBIT", "เดบิต"])
            df["debit"] = amt.abs().where(is_dr, 0.0)
            df["credit"] = amt.abs().where(~is_dr, 0.0)
        else:
            df["debit"], df["credit"] = amt.clip(lower=0), (-amt).clip(lower=0)
    else:
        raise JEError("ไฟล์ GL ต้องมีคอลัมน์ debit และ credit หรือคอลัมน์ amount")

    df["je_number"] = df["je_number"].astype(str).str.strip()
    df["created_by"] = df["created_by"].astype(str).str.strip()
    df["approved_by"] = df["approved_by"].astype(str).str.strip()
    df["account"] = df["account"].astype(str).str.strip()
    df["description"] = df["description"].astype(str).str.strip()
    df["posting_date"] = parse_dates(df["posting_date"])
    df["entry_dt"] = parse_dates(df["entry_date"])

    hours = parse_times(df["entry_time"])
    has_time_col = hours.notna().any()
    if not has_time_col:   # เวลาอาจอยู่ในคอลัมน์ entry_date
        t = df["entry_dt"]
        if t.notna().any() and ((t.dt.hour + t.dt.minute) > 0).any():
            hours = t.dt.hour + t.dt.minute / 60
    df["entry_hour"] = hours

    bad = df["posting_date"].isna().sum()
    if bad == len(df):
        raise JEError("อ่านวันที่ในคอลัมน์ posting_date ไม่ได้เลย กรุณาตรวจรูปแบบวันที่")

    avail = {
        "approver": (df["approved_by"] != "").any(),
        "entry_date": df["entry_dt"].notna().any(),
        "time": df["entry_hour"].notna().any(),
        "description": (df["description"] != "").any(),
        "bad_dates": int(bad),
    }
    return df, avail


def aggregate_je(df: pd.DataFrame) -> pd.DataFrame:
    """รวมบรรทัดเป็นระดับเอกสาร"""
    def join_unique(s):
        return " | ".join(dict.fromkeys(x for x in s if x))[:250]

    je = df.groupby("je_number", sort=False).agg(
        posting_date=("posting_date", "min"),
        entry_dt=("entry_dt", "min"),
        entry_hour=("entry_hour", "first"),
        created_by=("created_by", "first"),
        approved_by=("approved_by", "first"),
        source=("source", "first"),
        description=("description", join_unique),
        accounts=("account", lambda s: ", ".join(sorted(set(s)))),
        lines=("account", "size"),
        debit=("debit", "sum"),
        credit=("credit", "sum"),
    )
    je["debit"], je["credit"] = je["debit"].round(2), je["credit"].round(2)
    je["amount"] = je[["debit", "credit"]].max(axis=1)
    return je


# ----------------------------------------------------------------------------
# การทดสอบรายเอกสาร: แต่ละฟังก์ชันคืน Series(detail) โดย index = je_number
# ----------------------------------------------------------------------------

def _fmt(x: float) -> str:
    return f"{x:,.2f}"


def t_unbalanced(je, p, avail):
    d = je[(je["debit"] - je["credit"]).abs() > 0.01]
    return d.apply(lambda r: f"เดบิต {_fmt(r.debit)} เครดิต {_fmt(r.credit)} ต่างกัน {_fmt(r.debit - r.credit)}", axis=1)


def t_self_approved(je, p, avail):
    if not avail["approver"]:
        return None
    m = (je["approved_by"] != "") & (je["approved_by"].str.lower() == je["created_by"].str.lower())
    return je[m].apply(lambda r: f"บันทึกและอนุมัติโดย {r.created_by}", axis=1)


def _when(je, avail):
    """ใช้วันที่บันทึกจริง (entry date) ถ้ามี ไม่งั้นใช้วันที่ลงบัญชี"""
    if avail["entry_date"]:
        return je["entry_dt"].fillna(je["posting_date"]), "วันที่บันทึก"
    return je["posting_date"], "วันที่ลงบัญชี"


TH_DAY = ["จันทร์", "อังคาร", "พุธ", "พฤหัสบดี", "ศุกร์", "เสาร์", "อาทิตย์"]


def t_weekend(je, p, avail):
    when, label = _when(je, avail)
    m = when.dt.dayofweek >= 5
    return when[m].apply(lambda d: f"{label} {d:%Y-%m-%d} วัน{TH_DAY[d.dayofweek]}")


def t_holiday(je, p, avail):
    if not p.holidays:
        return None
    when, label = _when(je, avail)
    m = when.dt.date.isin(p.holidays)
    return when[m].apply(lambda d: f"{label} {d:%Y-%m-%d} เป็นวันหยุด")


def t_after_hours(je, p, avail):
    if not avail["time"]:
        return None
    h = je["entry_hour"]
    m = h.notna() & ((h < p.work_start) | (h >= p.work_end))
    return h[m].apply(lambda x: f"บันทึกเวลา {int(x):02d}:{int(round((x % 1) * 60)) % 60:02d} น. "
                                f"(เวลาทำการ {p.work_start:02d}:00–{p.work_end:02d}:00)")


def t_post_close(je, p, avail):
    if not avail["entry_date"]:
        return None
    month_end = je["posting_date"] + pd.offsets.MonthEnd(0)
    cutoff = month_end + pd.Timedelta(days=p.close_days)
    m = je["entry_dt"].notna() & (je["entry_dt"].dt.normalize() > cutoff)
    d = je[m]
    return d.apply(lambda r: f"ลงบัญชีงวด {r.posting_date:%Y-%m} แต่บันทึกเมื่อ {r.entry_dt:%Y-%m-%d} "
                             f"({(r.entry_dt.normalize() - (r.posting_date + pd.offsets.MonthEnd(0))).days} วันหลังสิ้นงวด)", axis=1)


def t_period_end(je, p, avail):
    pdt = je["posting_date"]
    dim = pdt.dt.days_in_month
    m = pdt.notna() & (pdt.dt.day > dim - p.period_end_days)
    return pdt[m].apply(lambda d: f"ลงบัญชีวันที่ {d:%Y-%m-%d} ({p.period_end_days} วันสุดท้ายของเดือน)")


def t_round(je, p, avail):
    a = je["amount"]
    m = (a >= p.round_min) & (np.isclose(a % p.round_unit, 0) | np.isclose(a % p.round_unit, p.round_unit))
    return a[m].apply(lambda x: f"ยอด {_fmt(x)} เป็นตัวเลขกลม")


def t_below_threshold(je, p, avail):
    a = je["amount"]
    out = pd.Series(dtype=str)
    for t in sorted(p.approval_thresholds):
        m = (a >= t * (1 - p.below_threshold_pct)) & (a < t)
        out = pd.concat([out, a[m].apply(lambda x, t=t: f"ยอด {_fmt(x)} ต่ำกว่าวงเงินอนุมัติ {_fmt(t)} "
                                                         f"อยู่ {(t - x) / t:.1%}")])
    return out[~out.index.duplicated()]


def t_large(je, p, avail):
    a = je["amount"]
    if p.large_amount:
        limit, how = p.large_amount, f"เกณฑ์ {_fmt(p.large_amount)}"
    else:
        if len(a) < 50:
            return None
        limit = float(np.percentile(a, p.large_percentile))
        how = f"สูงกว่า percentile ที่ {p.large_percentile:g} ({_fmt(limit)})"
    return a[a >= limit].apply(lambda x: f"ยอด {_fmt(x)} {how}")


def t_keywords(je, p, avail):
    if not avail["description"] or not p.keywords:
        return None
    low = je["description"].str.lower()
    found = low.apply(lambda s: [k for k in p.keywords if k.lower() in s])
    m = found.str.len() > 0
    return found[m].apply(lambda ks: "พบคำ: " + ", ".join(ks))


def t_blank_desc(je, p, avail):
    if not avail["description"]:
        return None
    m = je["description"].str.len() < 3
    return je[m]["description"].apply(lambda _: "ไม่มีคำอธิบายรายการ")


def t_rare_user(je, p, avail):
    counts = je["created_by"].value_counts()
    if len(counts) < 2:
        return None
    rare = counts[counts <= p.rare_user_max]
    m = je["created_by"].isin(rare.index)
    return je[m]["created_by"].apply(lambda u: f"{u} บันทึกเพียง {counts[u]} เอกสารทั้งงวด")


def t_duplicate(je, p, avail):
    key = je["posting_date"].astype(str) + "|" + je["accounts"] + "|" + je["amount"].astype(str)
    grp = je.groupby(key).apply(lambda g: list(g.index), include_groups=False)
    dup = {i: ids for ids in grp if len(ids) > 1 for i in ids}
    return pd.Series({i: "ซ้ำกับเอกสาร " + ", ".join(x for x in ids if x != i)
                      for i, ids in dup.items()}, dtype=str)


TEST_FUNCS = {
    "JE-01": (t_unbalanced, None),
    "JE-02": (t_self_approved, "ต้องมีคอลัมน์ approved_by"),
    "JE-03": (t_weekend, None),
    "JE-04": (t_holiday, "ต้องอัปโหลดไฟล์วันหยุด"),
    "JE-05": (t_after_hours, "ต้องมีเวลาบันทึก (entry_time)"),
    "JE-06": (t_post_close, "ต้องมีวันที่บันทึกในระบบ (entry_date)"),
    "JE-07": (t_period_end, None),
    "JE-08": (t_round, None),
    "JE-09": (t_below_threshold, None),
    "JE-10": (t_large, "ข้อมูลน้อยกว่า 50 เอกสาร ให้กำหนดเกณฑ์ยอดเงินเอง"),
    "JE-11": (t_keywords, "ไม่มีคอลัมน์ description"),
    "JE-12": (t_blank_desc, "ไม่มีคอลัมน์ description"),
    "JE-13": (t_rare_user, "มีผู้บันทึกเพียงคนเดียว"),
    "JE-14": (t_duplicate, None),
}


# ----------------------------------------------------------------------------
# การทดสอบระดับประชากร
# ----------------------------------------------------------------------------

BENFORD_P = {d: math.log10(1 + 1 / d) for d in range(1, 10)}
CHI2_CRIT_8DF_95 = 15.507


def benford(lines: pd.DataFrame, min_amount: float = 10.0) -> tuple[pd.DataFrame, dict]:
    amt = pd.concat([lines["debit"], lines["credit"]])
    amt = amt[amt >= min_amount]
    n = len(amt)
    if n < 100:
        return pd.DataFrame(), {"n": n, "performed": False,
                                "conclusion": "ข้อมูลน้อยกว่า 100 รายการ ไม่เพียงพอสำหรับ Benford"}
    first = amt.apply(lambda x: int(f"{x:e}"[0]))
    counts = first.value_counts().reindex(range(1, 10), fill_value=0)
    rows, chi2, mad = [], 0.0, 0.0
    for d in range(1, 10):
        pe, po = BENFORD_P[d], counts[d] / n
        z = max(abs(po - pe) - 1 / (2 * n), 0) / math.sqrt(pe * (1 - pe) / n)
        chi2 += (counts[d] - n * pe) ** 2 / (n * pe)
        mad += abs(po - pe) / 9
        rows.append({"digit": d, "count": int(counts[d]), "expected_count": round(n * pe, 1),
                     "actual_pct": po, "expected_pct": pe, "difference": po - pe, "z_stat": round(z, 2),
                     "significant": "ใช่" if z > 1.96 else ""})
    # เกณฑ์ MAD ของ Nigrini สำหรับตัวเลขหลักแรก
    if mad <= 0.006:
        level = "Close conformity (สอดคล้องมาก)"
    elif mad <= 0.012:
        level = "Acceptable conformity (สอดคล้องยอมรับได้)"
    elif mad <= 0.015:
        level = "Marginally acceptable (สอดคล้องเล็กน้อย)"
    else:
        level = "Nonconformity (ไม่สอดคล้อง ควรตรวจเพิ่มเติม)"
    over = [r["digit"] for r in rows if r["significant"] and r["difference"] > 0]
    concl = level + (f" — ตัวเลขหลักแรก {', '.join(map(str, over))} ปรากฏมากกว่าที่ควรอย่างมีนัยสำคัญ"
                     if over else "")
    return pd.DataFrame(rows), {"n": n, "mad": mad, "chi2": chi2, "level": level, "performed": True,
                                "over_digits": over, "conclusion": concl}


def sequence_gaps(je_numbers: pd.Index, max_rows: int = 500) -> pd.DataFrame:
    s = pd.Series(je_numbers.astype(str))
    parts = s.str.extract(r"^(.*?)(\d+)$")
    parts.columns = ["prefix", "num"]
    parts = parts.dropna()
    rows = []
    for prefix, g in parts.groupby("prefix"):
        width = g["num"].str.len().max()
        nums = np.sort(g["num"].astype(np.int64).unique())
        if len(nums) < 2:
            continue
        diffs = np.diff(nums)
        for i in np.where(diffs > 1)[0]:
            a, b = nums[i] + 1, nums[i + 1] - 1
            rows.append({"prefix": prefix,
                         "missing_from": f"{prefix}{str(a).zfill(width)}",
                         "missing_to": f"{prefix}{str(b).zfill(width)}",
                         "count_missing": int(b - a + 1)})
            if len(rows) >= max_rows:
                break
    return pd.DataFrame(rows, columns=["prefix", "missing_from", "missing_to", "count_missing"])


# ----------------------------------------------------------------------------
# รันทั้งหมด
# ----------------------------------------------------------------------------

def run_tests(gl: pd.DataFrame, params: Params | None = None) -> dict:
    p = params or Params()
    lines, avail = prepare(gl)
    je = aggregate_je(lines)

    flags: dict[str, list[tuple[str, str]]] = {}
    status = {}
    for tid, (fn, need) in TEST_FUNCS.items():
        res = fn(je, p, avail)
        if res is None:
            status[tid] = ("ไม่ได้ทดสอบ", need or "")
            continue
        status[tid] = ("ทดสอบแล้ว", "")
        for je_no, detail in res.items():
            flags.setdefault(je_no, []).append((tid, detail))

    # ตารางข้อตรวจพบแบบยาว
    rows = []
    for je_no, items in flags.items():
        r = je.loc[je_no]
        for tid, detail in items:
            name, w, _ = TESTS[tid]
            rows.append({"test_id": tid, "test_name": name, "severity": severity_of(w), "je_number": je_no,
                         "posting_date": r.posting_date, "created_by": r.created_by,
                         "approved_by": r.approved_by, "amount": r.amount,
                         "description": r.description, "detail": detail})
    findings = pd.DataFrame(rows, columns=["test_id", "test_name", "severity", "je_number", "posting_date",
                                           "created_by", "approved_by", "amount", "description", "detail"])
    if not findings.empty:
        findings = findings.sort_values(["test_id", "posting_date", "je_number"]).reset_index(drop=True)

    # คะแนนความเสี่ยงรายเอกสาร
    rank = []
    for je_no, items in flags.items():
        r = je.loc[je_no]
        score = sum(TESTS[t][1] for t, _ in items)
        rank.append({"je_number": je_no, "risk_score": score, "risk_level": risk_level(score),
                     "tests_hit": ", ".join(t for t, _ in items), "posting_date": r.posting_date,
                     "entry_date": r.entry_dt, "created_by": r.created_by, "approved_by": r.approved_by,
                     "amount": r.amount, "accounts": r.accounts, "description": r.description,
                     "details": " ; ".join(f"[{t}] {d}" for t, d in items)})
    ranking = pd.DataFrame(rank)
    if not ranking.empty:
        ranking = ranking.sort_values(["risk_score", "amount"], ascending=[False, False]).reset_index(drop=True)
        ranking.insert(0, "rank", range(1, len(ranking) + 1))

    bf_table, bf_info = benford(lines)
    gaps = sequence_gaps(je.index)

    stats = {
        "lines": len(lines), "je_count": len(je),
        "total_debit": float(lines["debit"].sum()), "total_credit": float(lines["credit"].sum()),
        "users": int(je["created_by"].nunique()),
        "date_from": je["posting_date"].min(), "date_to": je["posting_date"].max(),
        "flagged_je": len(ranking),
        "high_je": int((ranking["risk_level"] == "High").sum()) if not ranking.empty else 0,
        "bad_dates": avail["bad_dates"],
    }
    return {"findings": findings, "ranking": ranking, "benford": bf_table, "benford_info": bf_info,
            "gaps": gaps, "status": status, "stats": stats, "params": p, "je": je}


# ----------------------------------------------------------------------------
# รายงาน Excel
# ----------------------------------------------------------------------------

HEADER_FILL = PatternFill("solid", fgColor="1F3864")
HEADER_FONT = Font(bold=True, color="FFFFFF")
LEVEL_FILL = {
    "High": PatternFill("solid", fgColor="F8CBAD"),
    "Medium": PatternFill("solid", fgColor="FFE699"),
    "Low": PatternFill("solid", fgColor="C6EFCE"),
}
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
NUM_FMT = "#,##0.00"

COL_TH = {
    "rank": "ลำดับ", "je_number": "เลขที่เอกสาร", "risk_score": "คะแนนความเสี่ยง",
    "risk_level": "ระดับความเสี่ยง", "tests_hit": "การทดสอบที่พบ", "posting_date": "วันที่ลงบัญชี",
    "entry_date": "วันที่บันทึก", "created_by": "ผู้บันทึก", "approved_by": "ผู้อนุมัติ",
    "amount": "จำนวนเงิน", "accounts": "บัญชี", "description": "คำอธิบาย", "details": "รายละเอียด",
    "test_id": "รหัสการทดสอบ", "test_name": "การทดสอบ", "severity": "ระดับ", "detail": "รายละเอียด",
    "selected": "เลือกทดสอบ (Y/N)", "result": "ผลการตรวจหลักฐาน", "wp_ref": "อ้างอิงกระดาษทำการ",
}


def _style(ws, header_row=1, widths=None, money_cols=(), date_cols=(), level_col=None, freeze=True):
    for c in ws[header_row]:
        c.fill, c.font, c.border = HEADER_FILL, HEADER_FONT, BORDER
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    for row in ws.iter_rows(min_row=header_row + 1):
        for c in row:
            c.border = BORDER
            c.alignment = Alignment(vertical="top", wrap_text=True)
            if c.column in money_cols:
                c.number_format = NUM_FMT
            if c.column in date_cols:
                c.number_format = "yyyy-mm-dd"
            if level_col and c.column == level_col and c.value in LEVEL_FILL:
                c.fill = LEVEL_FILL[c.value]
    for i, w in enumerate(widths or [], 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    if freeze:
        ws.freeze_panes = ws.cell(row=header_row + 1, column=1)
    ws.auto_filter.ref = f"A{header_row}:{get_column_letter(ws.max_column)}{ws.max_row}"


def _col(df, name):
    return list(df.columns).index(name) + 1


def _naive_dates(df):
    df = df.copy()
    for c in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[c]):
            df[c] = df[c].dt.normalize()
    return df


def write_report(res: dict, out, company: str = "(ไม่ระบุ)", period: str = "(ไม่ระบุ)") -> None:
    st, p, bi = res["stats"], res["params"], res["benford_info"]
    findings, ranking, gaps, bf = res["findings"], res["ranking"], res["gaps"], res["benford"]

    with pd.ExcelWriter(out, engine="openpyxl") as xw:
        # ---------------- Summary ----------------
        summary_rows = []
        for tid, (name, w, _) in TESTS.items():
            stt, note = res["status"][tid]
            n = int((findings["test_id"] == tid).sum()) if not findings.empty else 0
            summary_rows.append({"รหัส": tid, "การทดสอบ": name, "ระดับ": severity_of(w), "คะแนน": w,
                                 "สถานะ": stt, "จำนวนเอกสารที่พบ": n if stt == "ทดสอบแล้ว" else "-",
                                 "หมายเหตุ": note})
        summary_rows.append({"รหัส": "P-01", "การทดสอบ": POP_TESTS["P-01"][0], "ระดับ": "Medium", "คะแนน": "-",
                             "สถานะ": "ทดสอบแล้ว",
                             "จำนวนเอกสารที่พบ": int(gaps["count_missing"].sum()) if not gaps.empty else 0,
                             "หมายเหตุ": f"{len(gaps)} ช่วงที่ขาด" if not gaps.empty else ""})
        summary_rows.append({"รหัส": "P-02", "การทดสอบ": POP_TESTS["P-02"][0], "ระดับ": "Medium", "คะแนน": "-",
                             "สถานะ": "ทดสอบแล้ว" if bi["performed"] else "ไม่ได้ทดสอบ",
                             "จำนวนเอกสารที่พบ": "-", "หมายเหตุ": bi["conclusion"]})
        summary = pd.DataFrame(summary_rows)
        start = 18
        summary.to_excel(xw, sheet_name="Summary", index=False, startrow=start - 1)
        ws = xw.sheets["Summary"]
        ws["A1"] = "รายงานการทดสอบรายการบันทึกบัญชี (Journal Entry Testing)"
        ws["A1"].font = Font(bold=True, size=16, color="1F3864")
        info = [
            ("บริษัท", company), ("งวดบัญชี", period),
            ("ช่วงวันที่ลงบัญชีในข้อมูล",
             f"{st['date_from']:%Y-%m-%d} ถึง {st['date_to']:%Y-%m-%d}" if pd.notna(st["date_from"]) else "-"),
            ("วันที่ออกรายงาน", datetime.now().strftime("%Y-%m-%d %H:%M")),
            ("จำนวนบรรทัด / จำนวนเอกสาร", f"{st['lines']:,} / {st['je_count']:,}"),
            ("ยอดรวมเดบิต", st["total_debit"]), ("ยอดรวมเครดิต", st["total_credit"]),
            ("จำนวนผู้บันทึก", st["users"]),
            ("เอกสารที่ถูกระบุว่ามีความเสี่ยง", f"{st['flagged_je']:,} ({st['flagged_je'] / max(st['je_count'], 1):.1%})"),
            ("เอกสารความเสี่ยงสูง (คะแนน ≥ 8)", st["high_je"]),
            ("Benford's Law", bi["conclusion"]),
            ("บรรทัดที่อ่านวันที่ไม่ได้", st["bad_dates"]),
        ]
        for i, (k, v) in enumerate(info, start=3):
            ws.cell(row=i, column=1, value=k).font = Font(bold=True)
            c = ws.cell(row=i, column=2, value=v)
            if isinstance(v, float):
                c.number_format = NUM_FMT
        ws.cell(row=16, column=1, value="⚠ ก่อนสรุปผล ให้กระทบยอดรวมเดบิต/เครดิตกับงบทดลอง (Trial Balance) "
                                        "เพื่อยืนยันความครบถ้วนของข้อมูล").font = Font(italic=True, color="C00000")
        _style(ws, header_row=start, widths=[28, 38, 10, 8, 13, 14, 60], freeze=False)
        for r in range(start + 1, start + 1 + len(summary)):
            c = ws.cell(row=r, column=3)
            c.fill = LEVEL_FILL.get(c.value, PatternFill())

        # ---------------- Risk Ranking ----------------
        if ranking.empty:
            pd.DataFrame({"ผล": ["ไม่พบรายการที่มีความเสี่ยง"]}).to_excel(xw, sheet_name="Risk Ranking", index=False)
        else:
            rk = _naive_dates(ranking)
            rk["selected"], rk["result"], rk["wp_ref"] = "", "", ""
            rk = rk.rename(columns=COL_TH)
            rk.to_excel(xw, sheet_name="Risk Ranking", index=False)
            _style(xw.sheets["Risk Ranking"],
                   widths=[7, 14, 10, 11, 20, 12, 12, 13, 13, 15, 18, 36, 60, 12, 24, 14],
                   money_cols=(_col(rk, COL_TH["amount"]),),
                   date_cols=(_col(rk, COL_TH["posting_date"]), _col(rk, COL_TH["entry_date"])),
                   level_col=_col(rk, COL_TH["risk_level"]))

        # ---------------- Findings ----------------
        if not findings.empty:
            f = _naive_dates(findings).rename(columns=COL_TH)
            f.to_excel(xw, sheet_name="Findings", index=False)
            _style(xw.sheets["Findings"], widths=[10, 30, 9, 14, 12, 13, 13, 15, 36, 55],
                   money_cols=(_col(f, COL_TH["amount"]),), date_cols=(_col(f, COL_TH["posting_date"]),),
                   level_col=_col(f, COL_TH["severity"]))

        # ---------------- Benford ----------------
        if bi["performed"]:
            b = bf.rename(columns={"digit": "ตัวเลขหลักแรก", "count": "จำนวนจริง",
                                   "expected_count": "จำนวนที่คาดหมาย", "actual_pct": "สัดส่วนจริง",
                                   "expected_pct": "สัดส่วนตาม Benford", "difference": "ส่วนต่าง",
                                   "z_stat": "Z-statistic", "significant": "แตกต่างมีนัยสำคัญ"})
            b.to_excel(xw, sheet_name="Benford", index=False, startrow=7)
            ws = xw.sheets["Benford"]
            ws["A1"] = "Benford's Law — ตัวเลขหลักแรก (First Digit Test)"
            ws["A1"].font = Font(bold=True, size=14, color="1F3864")
            for i, (k, v) in enumerate([
                ("จำนวนรายการที่ทดสอบ (≥ 10 บาท)", f"{bi['n']:,}"),
                ("Mean Absolute Deviation (MAD)", round(bi["mad"], 4)),
                ("Chi-square (df=8, ค่าวิกฤต 15.507)", round(bi["chi2"], 2)),
                ("สรุป", bi["conclusion"]),
            ], start=3):
                ws.cell(row=i, column=1, value=k).font = Font(bold=True)
                ws.cell(row=i, column=2, value=v)
            _style(ws, header_row=8, widths=[34, 12, 16, 12, 18, 11, 12, 16], freeze=False)
            for r in range(9, 18):
                for c in (4, 5, 6):
                    ws.cell(row=r, column=c).number_format = "0.0%"
                if ws.cell(row=r, column=8).value:
                    ws.cell(row=r, column=8).font = Font(bold=True, color="C00000")
            ch = BarChart()
            ch.title, ch.y_axis.title, ch.x_axis.title = "Actual vs Benford", "สัดส่วน", "ตัวเลขหลักแรก"
            ch.add_data(Reference(ws, min_col=4, max_col=5, min_row=8, max_row=17), titles_from_data=True)
            ch.set_categories(Reference(ws, min_col=1, min_row=9, max_row=17))
            ch.y_axis.numFmt = "0%"
            ch.height, ch.width = 8, 18
            ws.add_chart(ch, "J3")

        # ---------------- Sequence gaps ----------------
        g = gaps.rename(columns={"prefix": "Prefix", "missing_from": "เลขที่ขาดตั้งแต่",
                                 "missing_to": "ถึง", "count_missing": "จำนวนที่ขาด"})
        if g.empty:
            g = pd.DataFrame({"ผล": ["ไม่พบเลขที่เอกสารขาดหาย หรือเลขที่เอกสารไม่ใช่ตัวเลขต่อเนื่อง"]})
        g.to_excel(xw, sheet_name="Sequence Gaps", index=False)
        _style(xw.sheets["Sequence Gaps"], widths=[14, 20, 20, 14])

        # ---------------- Methodology ----------------
        m = pd.DataFrame([{"รหัส": k, "การทดสอบ": v[0], "คะแนน": v[1], "ความเสี่ยงที่ตอบสนอง": v[2]}
                          for k, v in TESTS.items()] +
                         [{"รหัส": k, "การทดสอบ": v[0], "คะแนน": "-", "ความเสี่ยงที่ตอบสนอง": v[1]}
                          for k, v in POP_TESTS.items()])
        m.to_excel(xw, sheet_name="Methodology", index=False)
        ws = xw.sheets["Methodology"]
        _style(ws, widths=[8, 36, 8, 75])
        r0 = len(m) + 3
        ws.cell(row=r0, column=1, value="พารามิเตอร์ที่ใช้").font = Font(bold=True)
        params = [
            ("วงเงินอนุมัติ", ", ".join(_fmt(t) for t in p.approval_thresholds)),
            ("ต่ำกว่าวงเงินไม่เกิน", f"{p.below_threshold_pct:.0%}"),
            ("เวลาทำการ", f"{p.work_start:02d}:00–{p.work_end:02d}:00"),
            ("ช่วงสิ้นงวด", f"{p.period_end_days} วันสุดท้ายของเดือน"),
            ("ระยะเวลาปิดงวด", f"{p.close_days} วันหลังสิ้นเดือน"),
            ("ยอดเงินกลม", f"หารด้วย {_fmt(p.round_unit)} ลงตัว และไม่ต่ำกว่า {_fmt(p.round_min)}"),
            ("ผู้บันทึกน้อยผิดปกติ", f"ไม่เกิน {p.rare_user_max} เอกสาร"),
            ("ยอดเงินสูง", _fmt(p.large_amount) if p.large_amount else f"percentile ที่ {p.large_percentile:g}"),
            ("จำนวนวันหยุดที่ใช้", f"{len(p.holidays)} วัน"),
            ("คำที่น่าสงสัย", ", ".join(p.keywords)),
            ("ระดับความเสี่ยงรายเอกสาร", "High ≥ 8 คะแนน, Medium 4–7, Low 1–3"),
        ]
        for i, (k, v) in enumerate(params, start=r0 + 1):
            ws.cell(row=i, column=2, value=k).font = Font(bold=True)
            ws.cell(row=i, column=4, value=v).alignment = Alignment(wrap_text=True)


# ----------------------------------------------------------------------------
# ข้อมูลตัวอย่าง (มีความผิดปกติฝังไว้ให้ระบบตรวจเจอ)
# ----------------------------------------------------------------------------

SAMPLE_HOLIDAYS_2026 = [
    ("2026-01-01", "วันขึ้นปีใหม่"), ("2026-04-06", "วันจักรี"), ("2026-04-13", "วันสงกรานต์"),
    ("2026-04-14", "วันสงกรานต์"), ("2026-04-15", "วันสงกรานต์"), ("2026-05-01", "วันแรงงาน"),
    ("2026-05-04", "วันฉัตรมงคล"), ("2026-06-03", "วันเฉลิมพระชนมพรรษาพระราชินี"),
    ("2026-07-28", "วันเฉลิมพระชนมพรรษา ร.10"), ("2026-08-12", "วันแม่แห่งชาติ"),
    ("2026-10-13", "วันคล้ายวันสวรรคต ร.9"), ("2026-10-23", "วันปิยมหาราช"),
    ("2026-12-05", "วันพ่อแห่งชาติ"), ("2026-12-10", "วันรัฐธรรมนูญ"), ("2026-12-31", "วันสิ้นปี"),
]

_ACCTS = {
    "1101": "เงินสด", "1102": "เงินฝากธนาคาร", "1201": "ลูกหนี้การค้า", "1301": "สินค้าคงเหลือ",
    "2101": "เจ้าหนี้การค้า", "2201": "ค่าใช้จ่ายค้างจ่าย", "4101": "รายได้จากการขาย",
    "5101": "ต้นทุนขาย", "5201": "เงินเดือน", "5301": "ค่าเช่า", "5401": "ค่าที่ปรึกษา", "5901": "ค่าใช้จ่ายอื่น",
}
_PAIRS = [("1201", "4101", "บันทึกขายเชื่อ"), ("5101", "1301", "ต้นทุนขาย"), ("2101", "1102", "จ่ายชำระเจ้าหนี้"),
          ("1102", "1201", "รับชำระจากลูกหนี้"), ("5301", "2201", "ค่าเช่าค้างจ่าย"), ("1301", "2101", "ซื้อสินค้า"),
          ("5201", "1102", "จ่ายเงินเดือน"), ("5901", "1101", "ค่าใช้จ่ายเบ็ดเตล็ด")]


def demo_gl(year: int = 2026, n_je: int = 900, seed: int = 7) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    users = ["acc.somying", "acc.wanna", "acc.preecha", "acc.kanya", "ap.malee", "ar.chai"]
    approvers = ["mgr.somchai", "mgr.nida"]
    biz_days = pd.bdate_range(f"{year}-01-02", f"{year}-09-30")
    hol = {pd.Timestamp(d) for d, _ in SAMPLE_HOLIDAYS_2026}
    biz_days = [d for d in biz_days if d not in hol]

    rows, je_objs = [], []
    for i in range(n_je):
        d = biz_days[rng.integers(len(biz_days))]
        dr, cr, desc = _PAIRS[rng.integers(len(_PAIRS))]
        amt = round(float(10 ** rng.uniform(2.3, 6.2)), 2)            # log-uniform ≈ Benford
        je_objs.append(dict(posting=d, entry=d, hour=float(rng.uniform(8.5, 17.5)), user=users[rng.integers(len(users))],
                            appr=approvers[rng.integers(2)], dr=dr, cr=cr, amt=amt, cr_amt=amt,
                            desc=f"{desc} #{rng.integers(1000, 9999)}"))

    def at(i, **kw):
        je_objs[i].update(kw)

    # ผู้ใช้ 1 คนบันทึกยอด 4x,xxx จำนวนมาก (ทำให้ Benford ผิดปกติที่เลข 4) — ทำก่อนเพื่อไม่ทับรายการด้านล่าง
    for i in range(301, 900, 7):
        a = round(float(rng.uniform(40_000, 49_900)), 2)
        at(i, amt=a, cr_amt=a, user="acc.kanya")

    # --- ฝังความผิดปกติ ---
    for i, a in zip((10, 220, 640), (85_430.50, 12_760.00, 233_118.25)):   # JE-01 ไม่สมดุล
        at(i, amt=a, cr_amt=a - 1_500)
    for i in (35, 300, 512, 777):                                      # JE-02 อนุมัติเอง
        at(i, appr=je_objs[i]["user"])
    for i, d in zip((50, 150, 450, 700), ("2026-02-14", "2026-03-22", "2026-06-20", "2026-08-30")):
        at(i, posting=pd.Timestamp(d), entry=pd.Timestamp(d))          # JE-03 เสาร์-อาทิตย์
    for i, d in zip((80, 380, 680), ("2026-04-14", "2026-05-01", "2026-08-12")):
        at(i, posting=pd.Timestamp(d), entry=pd.Timestamp(d))          # JE-04 วันหยุด
    for i, h in zip((120, 260, 520, 810), (22.4, 1.75, 6.5, 20.1)):   # JE-05 นอกเวลา
        at(i, hour=h)
    for i, (pd_, ed) in zip((90, 333, 600), (("2026-03-31", "2026-04-20"), ("2026-06-30", "2026-07-28"),
                                              ("2026-08-31", "2026-09-25"))):
        at(i, posting=pd.Timestamp(pd_), entry=pd.Timestamp(ed))       # JE-06 หลังปิดงวด
    for i, a in zip((140, 280, 430, 590), (49_200.00, 99_500.00, 485_000.00, 98_750.00)):
        at(i, amt=a, cr_amt=a)                                         # JE-09 ต่ำกว่าวงเงิน
    for i, a in zip((160, 360, 560, 760, 860), (50_000, 120_000, 300_000, 2_000_000, 75_000)):
        at(i, amt=float(a), cr_amt=float(a))                           # JE-08 ยอดกลม
    for i, t in zip((170, 370, 570, 770, 870),
                    ("ปรับปรุงยอดตามคำสั่ง MD", "Adjustment per CFO", "plug difference",
                     "แก้ไขยอดลูกหนี้", "reverse duplicate entry")):
        at(i, desc=t)                                                  # JE-11 คำน่าสงสัย
    for i in (180, 480, 780):                                          # JE-12 ไม่มีคำอธิบาย
        at(i, desc="")
    at(190, user="it.admin", appr="it.admin", hour=23.2, dr="5401", cr="1102",
       amt=450_000.0, cr_amt=450_000.0, desc="")                       # JE-13 + หลายข้อ: เคสเด่น
    at(195, user="it.admin", appr="mgr.somchai", hour=22.9, dr="5401", cr="1102",
       amt=480_000.0, cr_amt=480_000.0, desc="ค่าที่ปรึกษา")
    for src, dst in ((240, 241), (620, 621)):                          # JE-14 รายการซ้ำ
        je_objs[dst].update({k: je_objs[src][k] for k in ("posting", "entry", "dr", "cr", "amt", "cr_amt")})

    # --- เขียนเป็นบรรทัด GL พร้อมเลขที่เอกสารที่ขาดบางเลข ---
    skip = {101, 102, 455, 803}
    no = 0
    for i, j in enumerate(sorted(je_objs, key=lambda x: (x["posting"], x["hour"]))):
        no += 1
        while no in skip:
            no += 1
        doc = f"JV{year}{no:05d}"
        hh, mm = int(j["hour"]), int((j["hour"] % 1) * 60)
        base = dict(je_number=doc, posting_date=j["posting"].strftime("%Y-%m-%d"),
                    entry_date=j["entry"].strftime("%Y-%m-%d"), entry_time=f"{hh:02d}:{mm:02d}:00",
                    created_by=j["user"], approved_by=j["appr"], description=j["desc"], source="Manual")
        rows.append({**base, "line_no": 1, "account": j["dr"], "account_name": _ACCTS[j["dr"]],
                     "debit": j["amt"], "credit": 0.0})
        rows.append({**base, "line_no": 2, "account": j["cr"], "account_name": _ACCTS[j["cr"]],
                     "debit": 0.0, "credit": j["cr_amt"]})
    cols = ["je_number", "line_no", "posting_date", "entry_date", "entry_time", "account", "account_name",
            "description", "debit", "credit", "created_by", "approved_by", "source"]
    return pd.DataFrame(rows)[cols]


def demo_holidays() -> pd.DataFrame:
    return pd.DataFrame(SAMPLE_HOLIDAYS_2026, columns=["date", "name"])


def make_demo_files(folder: Path) -> tuple[Path, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    gl_p, hol_p = folder / "sample_gl.xlsx", folder / "sample_holidays_2026.xlsx"
    demo_gl().to_excel(gl_p, index=False)
    demo_holidays().to_excel(hol_p, index=False)
    return gl_p, hol_p


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Journal Entry Testing Tool")
    ap.add_argument("--gl", help="ไฟล์ General Ledger (.xlsx / .csv)")
    ap.add_argument("--holidays", help="ไฟล์วันหยุด (คอลัมน์ date)")
    ap.add_argument("--company", default="(ไม่ระบุ)")
    ap.add_argument("--period", default="(ไม่ระบุ)", help="เช่น FY2026 หรือ ม.ค.–ก.ย. 2569")
    ap.add_argument("--thresholds", default="50000,100000,500000,1000000", help="วงเงินอนุมัติ คั่นด้วย ,")
    ap.add_argument("--work-start", type=int, default=8)
    ap.add_argument("--work-end", type=int, default=18)
    ap.add_argument("--period-end-days", type=int, default=3)
    ap.add_argument("--close-days", type=int, default=5)
    ap.add_argument("--round-unit", type=float, default=1000)
    ap.add_argument("--round-min", type=float, default=10000)
    ap.add_argument("--rare-user", type=int, default=3)
    ap.add_argument("--large-amount", type=float, help="เกณฑ์ยอดเงินสูง (ไม่ใส่ = percentile 99)")
    ap.add_argument("--out", default="JE_Testing_Report.xlsx")
    ap.add_argument("--demo", action="store_true", help="สร้างข้อมูลตัวอย่างแล้วรันให้ดู")
    a = ap.parse_args()

    if a.demo:
        gl_p, hol_p = make_demo_files(Path("sample_data"))
        a.gl, a.holidays = str(gl_p), str(hol_p)
        a.company, a.period = "บริษัทตัวอย่าง จำกัด", "ม.ค.–ก.ย. 2026"
        print("สร้างข้อมูลตัวอย่างไว้ที่โฟลเดอร์ sample_data/")
    elif not a.gl:
        ap.error("ต้องระบุ --gl (หรือใช้ --demo)")

    try:
        p = Params(
            approval_thresholds=[float(x) for x in a.thresholds.split(",") if x.strip()],
            work_start=a.work_start, work_end=a.work_end, period_end_days=a.period_end_days,
            close_days=a.close_days, round_unit=a.round_unit, round_min=a.round_min,
            rare_user_max=a.rare_user, large_amount=a.large_amount,
            holidays=read_holidays(a.holidays) if a.holidays else set(),
        )
        res = run_tests(read_gl(a.gl), p)
        write_report(res, a.out, a.company, a.period)
    except JEError as e:
        sys.exit(f"[ERROR] {e}")
    except PermissionError:
        sys.exit(f"[ERROR] บันทึกไฟล์ {a.out} ไม่ได้ อาจเปิดค้างอยู่ใน Excel ให้ปิดไฟล์ก่อนแล้วรันใหม่")
    except ValueError as e:
        sys.exit(f"[ERROR] ค่าพารามิเตอร์ไม่ถูกต้อง: {e}")

    st = res["stats"]
    print(f"\nทดสอบเสร็จ: {st['je_count']:,} เอกสาร ({st['lines']:,} บรรทัด), ผู้บันทึก {st['users']} คน")
    print(f"เอกสารที่มีความเสี่ยง {st['flagged_je']:,} รายการ (High {st['high_je']})")
    for tid, (name, w, _) in TESTS.items():
        stt, note = res["status"][tid]
        n = int((res["findings"]["test_id"] == tid).sum()) if not res["findings"].empty else 0
        print(f"  {tid} {name}: " + (str(n) if stt == "ทดสอบแล้ว" else f"ไม่ได้ทดสอบ ({note})"))
    print(f"  P-01 เลขที่เอกสารขาด: {int(res['gaps']['count_missing'].sum()) if not res['gaps'].empty else 0}")
    print(f"  P-02 Benford: {res['benford_info']['conclusion']}")
    print(f"\nบันทึกรายงานที่: {Path(a.out).resolve()}")


if __name__ == "__main__":
    main()
