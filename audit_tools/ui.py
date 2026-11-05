"""ส่วนประกอบหน้าเว็บที่ทุกหน้าใช้ร่วมกัน (Streamlit)"""

from __future__ import annotations

import io
from contextlib import contextmanager

import pandas as pd
import streamlit as st

from . import config
from .common import COMMON_TH, SEVERITY_ORDER, AuditError

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
SEV_EMOJI = {"High": "🔴", "Medium": "🟠", "Low": "🟢", "Review": "🔵", "Critical": "⛔"}


def page(title: str, icon: str, intro: str, frameworks: str | None = None):
    st.set_page_config(page_title=title, page_icon=icon, layout="wide")
    st.title(f"{icon} {title}")
    st.write(intro)
    if frameworks:
        st.caption(f"อ้างอิง: {frameworks}")


def demo_toggle(label: str = "ทดลองด้วยข้อมูลตัวอย่าง") -> bool:
    return st.toggle(label, value=False)


def template_buttons(templates: dict[str, tuple[str, bytes]]):
    """templates: {label: (filename, bytes)}"""
    with st.sidebar:
        st.subheader("📄 แบบฟอร์ม / ตัวอย่างไฟล์")
        for label, (fname, data) in templates.items():
            mime = XLSX if fname.endswith(".xlsx") else "text/plain"
            st.download_button(label, data, fname, mime, key=f"tpl_{fname}")


def xlsx_bytes(df: pd.DataFrame) -> bytes:
    b = io.BytesIO()
    df.to_excel(b, index=False)
    return b.getvalue()


@contextmanager
def guard():
    """แสดงข้อผิดพลาดของข้อมูลเป็นข้อความที่อ่านเข้าใจ แล้วหยุดหน้า"""
    try:
        yield
    except AuditError as e:
        st.error(str(e))
        st.stop()


def metrics(findings: pd.DataFrame, extra: list[tuple[str, object]] | None = None):
    sev = findings["severity"].value_counts() if not findings.empty else pd.Series(dtype=int)
    items = list(extra or []) + [("ข้อตรวจพบทั้งหมด", len(findings)),
                                 ("🔴 High", int(sev.get("High", 0))),
                                 ("🟠 Medium", int(sev.get("Medium", 0)))]
    cols = st.columns(len(items))
    for c, (k, v) in zip(cols, items):
        c.metric(k, f"{v:,}" if isinstance(v, int) else v)


def check_summary(checks: dict, findings: pd.DataFrame, status: dict | None = None):
    status = status or {}
    rows = []
    for cid, spec in checks.items():
        n = int((findings["check_id"] == cid).sum()) if not findings.empty else 0
        rows.append({"รหัส": cid, "รายการตรวจสอบ": spec[0],
                     "ระดับ": f"{SEV_EMOJI.get(spec[1], '')} {spec[1]}",
                     "ผล": f"⏭️ {status[cid]}" if cid in status else (f"⚠️ พบ {n}" if n else "✅ ไม่พบ")})
    st.dataframe(pd.DataFrame(rows), hide_index=True)


def findings_table(findings: pd.DataFrame, checks: dict, col_th: dict | None = None, key: str = "f"):
    if findings.empty:
        st.success("ไม่พบข้อตรวจพบ 🎉")
        return
    c1, c2 = st.columns(2)
    sevs = [s for s in SEVERITY_ORDER if s in set(findings["severity"])]
    sp = c1.multiselect("ระดับความเสี่ยง", sevs, default=sevs, key=f"{key}_sev")
    ids = [c for c in checks if c in set(findings["check_id"])]
    cp = c2.multiselect("รายการตรวจ", ids, default=ids, key=f"{key}_chk",
                        format_func=lambda c: f"{c} {checks[c][0]}")
    v = findings[findings["severity"].isin(sp) & findings["check_id"].isin(cp)].copy()
    v["severity"] = v["severity"].map(lambda s: f"{SEV_EMOJI.get(s, '')} {s}")
    th = {**COMMON_TH, **(col_th or {})}
    st.dataframe(v.rename(columns={c: th.get(c, c) for c in v.columns}), hide_index=True)
    st.caption(f"แสดง {len(v):,} จาก {len(findings):,} รายการ")


def download(data: bytes, filename: str, label: str = "⬇️ ดาวน์โหลดรายงาน Excel"):
    st.download_button(label, data, filename, XLSX, type="primary")


def footer():
    st.divider()
    st.caption(f"🔒 ไฟล์ที่อัปโหลดใช้ประมวลผลชั่วคราวในหน่วยความจำเท่านั้น ไม่มีการบันทึกเก็บไว้ · "
               f"ผลลัพธ์ใช้ประกอบดุลยพินิจของผู้ตรวจสอบ · พัฒนาโดย {config.AUTHOR} ({config.CONTACT})")
