"""หน้าเว็บแบบประเมิน (ใช้ร่วมกันทั้ง PDPA / Vendor Risk / AI Governance)"""

from __future__ import annotations

import io
from typing import Callable

import pandas as pd
import streamlit as st

from . import assessment as A
from . import assessment_banks as B
from . import ui


def render(key: str, page_title: str, icon: str, intro: str, frameworks: str,
           profile: Callable[[], tuple[list, dict, list]] | None = None,
           after: Callable[[dict], list] | None = None):
    """profile(): คืน (info_rows เพิ่มเติม, extra_sheets, metrics เพิ่มเติม) — แสดงก่อนแบบประเมิน
    after(res): แสดงผลเพิ่มหลังคะแนน และคืน info_rows เพิ่มลงรายงาน — ใช้กับ Vendor Risk"""
    ui.page(page_title, icon, intro, frameworks)
    spec = B.BANKS[key]
    bank = A.bank_df(spec["bank"])

    with st.sidebar:
        st.subheader("⚙️ ข้อมูลการประเมิน")
        org = st.text_input("ผู้ถูกประเมิน (องค์กร/ผู้ให้บริการ)")
        assessor = st.text_input("ผู้ประเมิน")
        st.download_button("📄 แบบสอบถามเปล่า (Excel)", A.template_bytes(bank, spec["title"]),
                           f"{key}_questionnaire.xlsx", ui.XLSX)
        st.caption(f"{len(bank)} ข้อ · {bank['domain'].nunique()} หมวด · ส่งให้ผู้ตอบกรอกในคอลัมน์ answer แล้วอัปโหลดกลับ")

    extra_info, extra_sheets, extra_metrics = ([], {}, []) if profile is None else profile()

    demo = ui.demo_toggle("ทดลองด้วยคำตอบตัวอย่าง")
    mode = st.radio("วิธีตอบแบบประเมิน", ["ตอบในหน้าเว็บ", "อัปโหลดแบบสอบถามที่กรอกแล้ว"], horizontal=True)

    with ui.guard():
        if mode.startswith("อัปโหลด"):
            up = st.file_uploader("แบบสอบถามที่กรอกแล้ว (.xlsx)", type=["xlsx", "csv"])
            if up is None and not demo:
                st.info("อัปโหลดแบบสอบถามที่ได้รับกลับมา หรือเปิดคำตอบตัวอย่าง")
                ui.footer()
                st.stop()
            answers = B.demo_answers(key) if up is None else A.read_answers(up, up.name)
        else:
            base = bank[["qid", "domain", "question"]].copy()
            init = B.demo_answers(key) if demo else pd.DataFrame({"qid": bank["qid"], "answer": "", "note": ""})
            base = base.merge(init, on="qid", how="left").fillna("")
            edited = st.data_editor(
                base, hide_index=True, key=f"ed_{key}_{demo}", height=420,
                disabled=["qid", "domain", "question"],
                column_config={
                    "qid": st.column_config.TextColumn("รหัส", width="small"),
                    "domain": st.column_config.TextColumn("หมวด", width="medium"),
                    "question": st.column_config.TextColumn("คำถาม", width="large"),
                    "answer": st.column_config.SelectboxColumn("คำตอบ", options=A.ANSWERS, width="small"),
                    "note": st.column_config.TextColumn("หมายเหตุ / หลักฐาน", width="medium")})
            answers = edited[["qid", "answer", "note"]]
            with st.expander("ดูหลักฐานที่คาดหวังและอ้างอิงของแต่ละข้อ"):
                st.dataframe(bank[["qid", "reference", "evidence", "weight"]].rename(columns=A.COL_TH),
                             hide_index=True)
        res = A.score(bank, answers)

    if res["overall"] is None:
        st.info("ยังไม่มีคำตอบ — เลือกคำตอบในตารางด้านบนเพื่อดูผลคะแนน")
        ui.footer()
        st.stop()

    st.divider()
    cols = st.columns(4 + len(extra_metrics))
    cols[0].metric("คะแนนรวม", f"{res['overall']:.0f}%")
    cols[1].metric("ระดับ", res["rating"])
    cols[2].metric("ตอบครบ", f"{res['completeness']:.0f}%")
    cols[3].metric("ช่องว่าง (High)", f"{len(res['gaps'])} ({int((res['gaps']['priority'] == 'High').sum())})")
    for c, (k, v) in zip(cols[4:], extra_metrics):
        c.metric(k, v)

    if after is not None:
        extra_info = extra_info + (after(res) or [])
    buf = io.BytesIO()
    A.write_report(res, buf, spec["title"],
                   [("ผู้ถูกประเมิน", org or "(ไม่ระบุ)"), ("ผู้ประเมิน", assessor or "(ไม่ระบุ)")] + extra_info,
                   extra_sheets)
    c1, c2 = st.columns(2)
    with c1:
        ui.download(buf.getvalue(), f"{key}_assessment_report.xlsx")
    with c2:
        st.download_button("💾 บันทึกคำตอบ (ไว้แก้ไขต่อภายหลัง)", A.template_bytes(bank, spec["title"], answers),
                           f"{key}_answers.xlsx", ui.XLSX)

    t = st.tabs(["คะแนนรายหมวด", "ช่องว่างและข้อเสนอแนะ", "ข้อที่ยังไม่ตอบ"])
    with t[0]:
        d = res["domains"].dropna(subset=["score_pct"])
        st.bar_chart(d.set_index("domain")["score_pct"], horizontal=True)
        st.dataframe(res["domains"].rename(columns=A.COL_TH), hide_index=True)
    with t[1]:
        g = res["gaps"].copy()
        g["priority"] = g["priority"].map(lambda p: f"{ui.SEV_EMOJI.get(p, '')} {p}")
        st.dataframe(g.rename(columns=A.COL_TH), hide_index=True)
    with t[2]:
        if res["unanswered"].empty:
            st.success("ตอบครบทุกข้อ")
        else:
            st.dataframe(res["unanswered"].rename(columns=A.COL_TH), hide_index=True)
    ui.footer()
    return res
