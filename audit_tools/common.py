"""
ฟังก์ชันกลางที่ทุกเครื่องมือใช้ร่วมกัน: อ่านไฟล์, แปลงชื่อคอลัมน์, แปลงวันที่/ตัวเลข, ออกรายงาน Excel
"""

from __future__ import annotations

import io
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

import pandas as pd
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter


class AuditError(Exception):
    """ข้อผิดพลาดของข้อมูล input ที่ควรแจ้งผู้ใช้ (ไม่ใช่ bug ของโปรแกรม)"""


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Review": 3}

# ----------------------------------------------------------------------------
# อ่านไฟล์
# ----------------------------------------------------------------------------


def _suffix(src, name):
    if isinstance(src, (str, Path)):
        return Path(src).suffix.lower()
    return Path(name or getattr(src, "name", "")).suffix.lower()


def read_raw(src, name: str | None = None) -> pd.DataFrame:
    """อ่าน .xlsx / .csv จาก path หรือไฟล์ที่อัปโหลด (file-like) เป็นข้อความทั้งหมด"""
    if isinstance(src, (str, Path)) and not Path(src).exists():
        raise AuditError(f"ไม่พบไฟล์: {src}")
    suffix = _suffix(src, name)
    if isinstance(src, (bytes, bytearray)):
        src = io.BytesIO(src)
    try:
        if suffix in {".xlsx", ".xlsm", ".xls"}:
            return pd.read_excel(src, dtype=str).fillna("")
        if suffix in {".csv", ".txt"}:
            return pd.read_csv(src, dtype=str, encoding="utf-8-sig").fillna("")
    except Exception as e:  # noqa: BLE001
        raise AuditError(f"อ่านไฟล์ไม่ได้ ({name or src}): {e}") from e
    raise AuditError(f"รองรับเฉพาะไฟล์ .xlsx หรือ .csv ({name or src})")


def read_text(src, name: str | None = None) -> str:
    """อ่านไฟล์ข้อความ รองรับ UTF-8, UTF-16 (เช่นไฟล์จาก secedit) และ TIS-620"""
    if isinstance(src, (str, Path)):
        if not Path(src).exists():
            raise AuditError(f"ไม่พบไฟล์: {src}")
        data = Path(src).read_bytes()
    else:
        data = src.read() if hasattr(src, "read") else bytes(src)
        if hasattr(src, "seek"):
            src.seek(0)
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    for enc in ("utf-8-sig", "cp874"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def standardize_columns(df: pd.DataFrame, aliases: dict[str, list[str]]) -> pd.DataFrame:
    """ทำชื่อคอลัมน์เป็นตัวเล็ก/ขีดล่าง แล้วจับคู่ชื่อที่พบบ่อยเข้ากับชื่อมาตรฐาน"""
    df = df.copy()
    df.columns = [re.sub(r"\s+", "_", str(c).strip().lower()) for c in df.columns]
    rename = {}
    for std, alts in aliases.items():
        if std in df.columns:
            continue
        for a in alts:
            a = re.sub(r"\s+", "_", a.lower())
            if a in df.columns and a not in rename and a not in aliases:
                rename[a] = std
                break
    return df.rename(columns=rename)


def read_table(src, name: str | None = None, aliases: dict | None = None) -> pd.DataFrame:
    df = read_raw(src, name)
    return standardize_columns(df, aliases or {})


def require(df: pd.DataFrame, cols: Iterable[str], label: str) -> None:
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise AuditError(f"ไฟล์ {label} ขาดคอลัมน์: {', '.join(missing)}\n"
                         f"คอลัมน์ที่มีในไฟล์: {', '.join(map(str, df.columns))}")


def ensure(df: pd.DataFrame, cols: Iterable[str], default="") -> pd.DataFrame:
    for c in cols:
        if c not in df.columns:
            df[c] = default
    return df


# ----------------------------------------------------------------------------
# แปลงข้อมูล
# ----------------------------------------------------------------------------

_BE_YEAR = re.compile(r"\b(25[0-9]{2})\b")


def parse_dates(s: pd.Series) -> pd.Series:
    """แปลงวันที่/เวลา รองรับ ค.ศ./พ.ศ., yyyy-mm-dd, dd/mm/yyyy และ ISO 8601 ที่มี timezone"""
    s = pd.Series(s).astype(str).str.strip()
    s = s.mask(s.isin(["", "nan", "NaT", "None", "N/A", "n/a", "-", "no_information", "not_supported"]))
    s = s.str.replace(_BE_YEAR, lambda m: str(int(m.group(1)) - 543), regex=True)
    s = s.str.replace(r"(\+00:00|Z)$", "", regex=True)
    iso = s.str.match(r"^\d{4}-\d{2}-\d{2}", na=False)
    out = pd.Series(pd.NaT, index=s.index, dtype="datetime64[ns]")
    if iso.any():
        out[iso] = pd.to_datetime(s[iso], errors="coerce", format="mixed")
    rest = ~iso & s.notna()
    if rest.any():
        out[rest] = pd.to_datetime(s[rest], errors="coerce", format="mixed", dayfirst=True)
    return out


def to_num(s: pd.Series) -> pd.Series:
    s = pd.Series(s).astype(str).str.strip().str.replace(",", "", regex=False)
    neg = s.str.startswith("(") & s.str.endswith(")")
    s = s.str.strip("()")
    trailing = s.str.endswith("-") & (s.str.len() > 1)
    s = s.where(~trailing, s.str.rstrip("-"))
    v = pd.to_numeric(s, errors="coerce")
    return v.where(~(neg | trailing), -v)


def yes(s: pd.Series) -> pd.Series:
    """แปลงค่า Yes/No หลายรูปแบบ (Y, true, 1, ใช่, มี) เป็น True/False"""
    return pd.Series(s).astype(str).str.strip().str.lower().isin(
        {"y", "yes", "true", "1", "ใช่", "มี", "enabled", "active", "approved", "pass", "passed"})


def sort_findings(f: pd.DataFrame, by_extra: list[str] | None = None) -> pd.DataFrame:
    if f.empty:
        return f
    f = f.copy()
    f["_s"] = f["severity"].map(SEVERITY_ORDER).fillna(9)
    f = f.sort_values(["_s", "check_id", *(by_extra or [])]).drop(columns="_s").reset_index(drop=True)
    f.insert(0, "finding_no", range(1, len(f) + 1))
    return f


def make_findings(rows: list[dict], checks: dict, columns: list[str]) -> pd.DataFrame:
    """rows: dict ที่มี check_id + คอลัมน์อื่น ๆ → เติม severity / recommendation จากตาราง checks"""
    out = []
    for r in rows:
        title, sev, rec = checks[r["check_id"]][:3]
        out.append({"check_id": r["check_id"], "severity": r.get("severity", sev),
                    **{c: r.get(c, "") for c in columns}, "detail": r.get("detail", ""),
                    "recommendation": r.get("recommendation", rec)})
    cols = ["check_id", "severity", *columns, "detail", "recommendation"]
    return pd.DataFrame(out, columns=cols)


def count_by_check(findings: pd.DataFrame, checks: dict) -> pd.DataFrame:
    rows = []
    for cid, spec in checks.items():
        n = int((findings["check_id"] == cid).sum()) if not findings.empty else 0
        rows.append({"check_id": cid, "title": spec[0], "severity": spec[1], "count": n})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------
# รายงาน Excel
# ----------------------------------------------------------------------------

HEADER_FILL = PatternFill("solid", fgColor="1F3864")
HEADER_FONT = Font(bold=True, color="FFFFFF")
SEV_FILL = {
    "High": PatternFill("solid", fgColor="F8CBAD"),
    "Medium": PatternFill("solid", fgColor="FFE699"),
    "Low": PatternFill("solid", fgColor="C6EFCE"),
    "Review": PatternFill("solid", fgColor="DDEBF7"),
    "Critical": PatternFill("solid", fgColor="E06666"),
    "Pass": PatternFill("solid", fgColor="C6EFCE"),
    "Fail": PatternFill("solid", fgColor="F8CBAD"),
}
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

COMMON_TH = {
    "finding_no": "ลำดับ", "check_id": "รหัสการตรวจ", "severity": "ระดับความเสี่ยง",
    "detail": "รายละเอียด", "recommendation": "ข้อเสนอแนะ",
    "management_response": "คำชี้แจงจากหน่วยรับตรวจ", "owner": "ผู้รับผิดชอบ", "due_date": "กำหนดแล้วเสร็จ",
    "title": "รายการตรวจสอบ", "count": "จำนวนที่พบ",
}


def style_sheet(ws, header_row: int = 1, widths: list[int] | None = None, sev_cols: Iterable[int] = (),
                freeze: bool = True, default_width: int = 18):
    for c in ws[header_row]:
        c.fill, c.font, c.border = HEADER_FILL, HEADER_FONT, BORDER
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    for row in ws.iter_rows(min_row=header_row + 1):
        for c in row:
            c.border = BORDER
            c.alignment = Alignment(vertical="top", wrap_text=True)
            if c.column in sev_cols and c.value in SEV_FILL:
                c.fill = SEV_FILL[c.value]
            if isinstance(c.value, datetime):
                c.number_format = "yyyy-mm-dd hh:mm" if (c.value.hour or c.value.minute) else "yyyy-mm-dd"
    for i in range(1, ws.max_column + 1):
        w = widths[i - 1] if widths and i <= len(widths) else default_width
        ws.column_dimensions[get_column_letter(i)].width = w
    if freeze:
        ws.freeze_panes = ws.cell(row=header_row + 1, column=1)
    if ws.max_row > header_row:
        ws.auto_filter.ref = f"A{header_row}:{get_column_letter(ws.max_column)}{ws.max_row}"


def _auto_widths(df: pd.DataFrame) -> list[int]:
    out = []
    for c in df.columns:
        sample = [str(x) for x in df[c].head(200).tolist()]
        longest = max([len(str(c))] + [len(x) for x in sample])
        out.append(int(min(max(longest * 1.1, 9), 60)))
    return out


def write_df(xw, df: pd.DataFrame, sheet: str, col_th: dict | None = None, startrow: int = 0,
             widths: list[int] | None = None, sev_names: Iterable[str] = ("severity", "status", "result",
                                                                        "risk_level", "rating")):
    """เขียน DataFrame ลงชีตพร้อมจัดรูปแบบ; แปลงชื่อคอลัมน์เป็นภาษาไทยตาม col_th"""
    df = df.copy()
    for c in df.columns:
        if isinstance(df[c].dtype, pd.DatetimeTZDtype):
            df[c] = df[c].dt.tz_localize(None)
    sev_idx = [i + 1 for i, c in enumerate(df.columns) if c in sev_names]
    th = {**COMMON_TH, **(col_th or {})}
    out = df.rename(columns={c: th.get(c, c) for c in df.columns})
    out.to_excel(xw, sheet_name=sheet[:31], index=False, startrow=startrow)
    style_sheet(xw.sheets[sheet[:31]], header_row=startrow + 1, widths=widths or _auto_widths(out),
                sev_cols=sev_idx, freeze=startrow == 0)


def write_findings_report(out, title: str, info: list[tuple[str, object]], checks: dict,
                          findings: pd.DataFrame, col_th: dict | None = None,
                          extra_sheets: dict[str, pd.DataFrame] | None = None,
                          status: dict[str, str] | None = None, per_check_sheets: bool = True,
                          note: str | None = None) -> None:
    """
    รายงานมาตรฐานของทุกเครื่องมือ:
      Summary (ข้อมูลทั่วไป + ผลแต่ละรายการตรวจ) / Findings (+ คอลัมน์ให้หน่วยรับตรวจตอบ)
      / ชีตแยกรายการตรวจ / ชีตเพิ่มเติม / Methodology
    checks: {id: (title, severity, recommendation[, rationale])}
    status: {id: "ไม่ได้ตรวจ: เหตุผล"} สำหรับรายการที่ข้อมูลไม่พอ
    """
    status = status or {}
    with pd.ExcelWriter(out, engine="openpyxl") as xw:
        # Summary
        rows = []
        for cid, spec in checks.items():
            n = int((findings["check_id"] == cid).sum()) if not findings.empty else 0
            skipped = status.get(cid)
            rows.append({"รหัสการตรวจ": cid, "รายการตรวจสอบ": spec[0], "ระดับความเสี่ยง": spec[1],
                         "จำนวนที่พบ": "-" if skipped else n,
                         "ผลการตรวจ": skipped or ("พบข้อสังเกต" if n else "ไม่พบ")})
        summary = pd.DataFrame(rows)
        info = list(info) + [("วันที่ออกรายงาน", datetime.now().strftime("%Y-%m-%d %H:%M")),
                             ("ข้อตรวจพบทั้งหมด", len(findings))]
        start = len(info) + 4                       # แถวหัวตารางสรุป (1-based)
        summary.to_excel(xw, sheet_name="Summary", index=False, startrow=start - 1)
        ws = xw.sheets["Summary"]
        ws["A1"] = title
        ws["A1"].font = Font(bold=True, size=16, color="1F3864")
        for i, (k, v) in enumerate(info, start=3):
            ws.cell(row=i, column=1, value=k).font = Font(bold=True)
            c = ws.cell(row=i, column=2, value=v)
            if isinstance(v, float):
                c.number_format = "#,##0.00"
        style_sheet(ws, header_row=start, widths=[30, 50, 15, 12, 40], sev_cols=(3,), freeze=False)
        for r in range(start + 1, start + 1 + len(summary)):
            c = ws.cell(row=r, column=5)
            if c.value == "พบข้อสังเกต":
                c.font = Font(bold=True, color="C00000")
        if note:
            ws.cell(row=start + len(summary) + 2, column=1, value=note).font = Font(italic=True, color="C00000")

        # Findings
        if findings.empty:
            pd.DataFrame({"ผล": ["ไม่พบข้อตรวจพบ"]}).to_excel(xw, sheet_name="Findings", index=False)
        else:
            f = findings.copy()
            f["management_response"], f["owner"], f["due_date"] = "", "", ""
            write_df(xw, f, "Findings", col_th)
            if per_check_sheets:
                for cid in checks:
                    sub = findings[findings["check_id"] == cid]
                    if not sub.empty:
                        write_df(xw, sub.drop(columns=[c for c in ("finding_no", "recommendation")
                                                       if c in sub.columns]), cid, col_th)

        for name, df in (extra_sheets or {}).items():
            if df is not None and not df.empty:
                write_df(xw, df, name, col_th)

        meth = pd.DataFrame([{"รหัส": k, "รายการตรวจสอบ": v[0], "ระดับ": v[1], "ข้อเสนอแนะ": v[2],
                              "เกณฑ์ / ความเสี่ยง": v[3] if len(v) > 3 else ""} for k, v in checks.items()])
        write_df(xw, meth, "Methodology", widths=[10, 44, 10, 55, 55])


def df_to_xlsx_bytes(sheets: dict[str, pd.DataFrame]) -> bytes:
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as xw:
        for name, df in sheets.items():
            write_df(xw, df, name)
    return buf.getvalue()
