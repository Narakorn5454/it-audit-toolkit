import pandas as pd
import streamlit as st

from audit_tools import __version__, config

st.set_page_config(page_title="IT Audit Toolkit", page_icon="🧰", layout="wide")

st.title("🧰 IT Audit Toolkit")
st.write("ชุดเครื่องมือช่วยงานตรวจสอบด้านเทคโนโลยีสารสนเทศ 13 เครื่องมือ ครอบคลุม ITGC, Cybersecurity & IAM, Cloud, "
         "Data Analytics, Third-party risk และ AI Governance — ทดสอบข้อมูลทั้งประชากร (100%) แทนการสุ่มตัวอย่าง "
         "และออกรายงาน Excel พร้อมใช้เป็นกระดาษทำการ")
st.caption(f"พัฒนาโดย {config.AUTHOR} · {config.TITLE} · v{__version__}")

c = st.columns(4)
c[0].metric("เครื่องมือ", "13")
c[1].metric("รายการตรวจ/คำถาม", "200+")
c[2].metric("มาตรฐานที่อ้างอิง", "10+")
c[3].metric("ทุกหน้ามีข้อมูลตัวอย่าง", "✓")

GROUPS = [
    ("🔐 Access, Identity & Security (ITGC / IAM / Cyber)", [
        ("pages/01_User_Access_Review.py", "User Access Review", "🔍", "เทียบ HR กับ user ในระบบ: คนลาออก บัญชีกำพร้า dormant SoD"),
        ("pages/02_SoD_Analysis.py", "SoD Analysis", "⚖️", "สิทธิ์ขัดแย้งข้ามหลายระบบ + Role ที่ออกแบบผิด"),
        ("pages/04_Login_Anomaly.py", "Login Anomaly Detection", "🕵️", "Brute force, password spraying, impossible travel"),
        ("pages/05_Password_Policy.py", "Password Policy Review", "🔑", "Windows / AD / Linux / ระบบงาน เทียบเกณฑ์"),
        ("pages/06_System_Hardening.py", "System Hardening Review", "🛡️", "Windows + Linux แนว CIS Benchmark"),
    ]),
    ("🔄 IT Operations & Change", [
        ("pages/03_Change_Management.py", "Change Management Review", "🔄", "Deployment log เทียบใบคำขอ ITSM"),
    ]),
    ("☁️ Cloud & Third-party", [
        ("pages/07_Cloud_AWS_Review.py", "AWS Cloud Configuration Review", "☁️", "IAM, MFA, Security group, S3, CloudTrail"),
        ("pages/10_Vendor_Risk.py", "Vendor Risk Assessment", "🤝", "Inherent → Residual risk + แบบสอบถาม Excel"),
    ]),
    ("📊 Data Analytics & Continuous Auditing", [
        ("pages/08_Journal_Entry_Testing.py", "Journal Entry Testing", "📒", "16 การทดสอบ + Benford's Law + Risk scoring"),
    ]),
    ("🤖 AI for Audit & Audit of AI · Privacy", [
        ("pages/11_AI_Governance.py", "AI Governance Assessment", "🤖", "ISO/IEC 42001 · NIST AI RMF · GenAI"),
        ("pages/13_AI_Policy_Review.py", "AI Policy Review", "📑", "ให้ AI สอบทานนโยบายเทียบมาตรฐาน"),
        ("pages/09_PDPA_Assessment.py", "PDPA Readiness Assessment", "🇹🇭", "พ.ร.บ.คุ้มครองข้อมูลส่วนบุคคล 10 หมวด"),
    ]),
    ("📌 Reporting to Management", [
        ("pages/12_Finding_Tracker.py", "Audit Finding Tracker", "📌", "ติดตามแผนแก้ไข aging อีเมลติดตาม รายงานกรรมการตรวจสอบ"),
    ]),
]

st.divider()
for title, tools in GROUPS:
    st.subheader(title)
    cols = st.columns(3)
    for i, (path, label, icon, desc) in enumerate(tools):
        with cols[i % 3].container(border=True):
            st.page_link(path, label=f"**{label}**", icon=icon)
            st.caption(desc)

st.divider()
st.subheader("🧭 แนวทางการใช้งาน")
st.markdown("""
1. **เริ่มจากข้อมูลตัวอย่าง** — ทุกหน้ามีสวิตช์ *ทดลองด้วยข้อมูลตัวอย่าง* ที่ฝังความผิดปกติไว้ให้เห็นผลทันที
2. **ขอข้อมูลจากหน่วยรับตรวจ** — ดาวน์โหลดแบบฟอร์มหรือสคริปต์เก็บข้อมูลแบบอ่านอย่างเดียวจากแถบด้านซ้ายของแต่ละหน้า
3. **อัปโหลดและตรวจ** — ปรับเกณฑ์ให้ตรงกับนโยบายองค์กร แล้วดาวน์โหลดรายงาน Excel
4. **ติดตามผล** — นำเข้ารายงานไปที่ *Audit Finding Tracker* เพื่อติดตามการแก้ไขและรายงานคณะกรรมการตรวจสอบ
""")

st.subheader("📚 มาตรฐานที่อ้างอิง")
st.dataframe(pd.DataFrame([
    ("ITGC / COBIT 2019", "Logical access, Change management, IT operations"),
    ("ISO/IEC 27001:2022", "Annex A: 5.15–5.18, 5.19–5.23, 5.24–5.28, 8.2, 8.5, 8.9, 8.13, 8.15–8.16, 8.32"),
    ("CIS Benchmarks", "Windows, Linux, AWS Foundations"),
    ("ISA 240 / TSA 240", "Journal entry testing — management override of controls"),
    ("พ.ร.บ.คุ้มครองข้อมูลส่วนบุคคล พ.ศ. 2562", "มาตรา 19–42 และประกาศมาตรการรักษาความมั่นคงปลอดภัย พ.ศ. 2565"),
    ("ISO/IEC 42001:2023 · NIST AI RMF 1.0 · NIST AI 600-1", "AI management system และ Generative AI"),
    ("IIA Global Internal Audit Standards", "การติดตามผลการแก้ไขข้อตรวจพบ"),
], columns=["มาตรฐาน / กรอบ", "ส่วนที่ใช้"]), hide_index=True)

st.info("🔒 ข้อมูลที่อัปโหลดใช้ประมวลผลในหน่วยความจำเท่านั้น ไม่มีการบันทึกเก็บ · สำหรับข้อมูลจริงของลูกค้า "
        "แนะนำให้รันในเครื่องของผู้ตรวจสอบเอง (ดู README) · ผลลัพธ์ใช้ประกอบดุลยพินิจของผู้ตรวจสอบ")
st.caption(f"💼 [LinkedIn]({config.LINKEDIN}) · 💻 [GitHub]({config.GITHUB}) · ✉️ {config.CONTACT}")
