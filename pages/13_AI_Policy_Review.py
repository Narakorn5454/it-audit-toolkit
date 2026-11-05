import io
import os

import streamlit as st

from audit_tools import policy_review as pr
from audit_tools import ui

ui.page("AI Policy Review", "📑",
        "สอบทานเอกสารนโยบาย/ระเบียบขององค์กรว่าครอบคลุมข้อกำหนดตามมาตรฐานหรือไม่ (AI for Audit) "
        "เลือกได้ 2 โหมด: Keyword (ออฟไลน์ ฟรี) หรือ AI (Claude) ที่อ่านทั้งฉบับและอ้างข้อความหลักฐานให้",
        "ISO/IEC 27001:2022 Annex A · พ.ร.บ.คุ้มครองข้อมูลส่วนบุคคล มาตรา 37")

with st.sidebar:
    st.subheader("⚙️ ตั้งค่า")
    org = st.text_input("ชื่อองค์กร")
    mode = st.radio("โหมดการสอบทาน", ["Keyword (ออฟไลน์)", "AI (Claude API)"])
    api_key, model = None, pr.DEFAULT_MODEL
    if mode.startswith("AI"):
        secret = None
        try:
            secret = st.secrets.get("ANTHROPIC_API_KEY")
        except Exception:  # noqa: BLE001 - ไม่มีไฟล์ secrets
            pass
        api_key = st.text_input("Claude API key", type="password",
                                value="" if (secret or os.environ.get("ANTHROPIC_API_KEY")) else "",
                                help="สร้างได้ที่ Claude Console · ถ้าตั้งไว้ใน secrets หรือ environment แล้วเว้นว่างได้") \
            or secret or os.environ.get("ANTHROPIC_API_KEY")
        model = st.text_input("Model", pr.DEFAULT_MODEL)
        st.warning("โหมด AI จะส่งข้อความของนโยบายไปประมวลผลที่ Claude API — ใช้กับเอกสารที่ได้รับอนุญาตเท่านั้น")
ui.template_buttons({"ตัวอย่างนโยบาย (txt)": ("sample_access_policy.txt", pr.DEMO_POLICY.encode())})

areas = st.multiselect("เลือกหมวดข้อกำหนดที่จะเทียบ", list(pr.REQUIREMENTS),
                       default=["Access Control Policy", "Password / Authentication", "Backup"])
demo = ui.demo_toggle("ทดลองด้วยนโยบายตัวอย่าง")

with ui.guard():
    if demo:
        text, doc_name = pr.DEMO_POLICY, "นโยบายการควบคุมการเข้าถึง (ตัวอย่าง)"
        org = org or "บริษัทตัวอย่าง จำกัด"
    else:
        up = st.file_uploader("อัปโหลดเอกสารนโยบาย (.docx / .pdf / .txt / .md)", type=["docx", "pdf", "txt", "md"])
        if up is None:
            st.info("อัปโหลดเอกสารนโยบาย หรือเปิดนโยบายตัวอย่าง")
            ui.footer()
            st.stop()
        text, doc_name = pr.extract_text(up, up.name), up.name
    if not areas:
        st.info("เลือกหมวดข้อกำหนดอย่างน้อย 1 หมวด")
        st.stop()
    with st.expander(f"ข้อความที่อ่านได้จากเอกสาร ({len(text):,} ตัวอักษร)"):
        st.text(text[:5000] + ("\n..." if len(text) > 5000 else ""))
    if mode.startswith("AI"):
        if not st.button("🤖 เริ่มสอบทานด้วย AI", type="primary"):
            st.stop()
        with st.spinner("AI กำลังอ่านนโยบายและประเมินทีละข้อ..."):
            res = pr.review_ai(text, areas, api_key, model)
    else:
        res = pr.review_keywords(text, areas)
    buf = io.BytesIO()
    pr.write_report(res, buf, doc_name, org or "(ไม่ระบุ)")

st.divider()
t = res.table
c = st.columns(4)
c[0].metric("ความครอบคลุม", f"{res.coverage:.0f}%")
c[1].metric("✅ ครอบคลุม", int((t["status"] == "Covered").sum()))
c[2].metric("🟠 บางส่วน", int((t["status"] == "Partial").sum()))
c[3].metric("🔴 ไม่พบ", int((t["status"] == "Missing").sum()))
ui.download(buf.getvalue(), "Policy_Review_Report.xlsx")
if res.mode.startswith("Keyword"):
    st.caption("โหมด Keyword เป็นการคัดกรองเบื้องต้นจากคำสำคัญ — ใช้โหมด AI เพื่อประเมินเนื้อหาเชิงลึก "
               "และผู้ตรวจต้องทบทวนผลก่อนสรุปทุกครั้ง")

tabs = st.tabs(["ช่องว่างที่ต้องแก้ไข", "ความครอบคลุมรายนโยบาย", "ทุกข้อกำหนด"])
icon = {"Covered": "✅ Covered", "Partial": "🟠 Partial", "Missing": "🔴 Missing"}
with tabs[0]:
    g = t[t["status"] != "Covered"].assign(status=lambda d: d["status"].map(icon))
    st.dataframe(g.drop(columns=["keywords_found"]).rename(columns=pr.COL_TH), hide_index=True)
with tabs[1]:
    st.bar_chart(res.summary.set_index("area")["coverage_pct"])
    st.dataframe(res.summary.rename(columns=pr.COL_TH), hide_index=True)
with tabs[2]:
    st.dataframe(t.assign(status=t["status"].map(icon)).rename(columns=pr.COL_TH), hide_index=True)
ui.footer()
