import io
from datetime import date
from pathlib import Path

import streamlit as st

from audit_tools import cloud_aws as aw
from audit_tools import ui

ui.page("AWS Cloud Configuration Review", "☁️",
        "ตรวจการตั้งค่าความปลอดภัยบัญชี AWS: IAM, MFA, access key, security group, S3, CloudTrail "
        "จากไฟล์ที่หน่วยรับตรวจ export ด้วยสคริปต์แบบอ่านอย่างเดียว ผู้ตรวจไม่ต้องเข้าบัญชี AWS เอง",
        "CIS Amazon Web Services Foundations Benchmark · ISO/IEC 27001:2022 A.5.23 Cloud services · CSA CCM")

with st.sidebar:
    st.subheader("⚙️ ตั้งค่า")
    account = st.text_input("AWS Account / ชื่อระบบ")
    as_of = st.date_input("วันที่ของข้อมูล", date.today())
    with st.expander("เกณฑ์"):
        rot = st.number_input("หมุนเวียน access key ทุก (วัน)", 1, 3650, 90)
        unused = st.number_input("credential ไม่ใช้งานเกิน (วัน)", 1, 3650, 45)
        min_len = st.number_input("ความยาวรหัสผ่านขั้นต่ำ", 6, 128, 14)
        reuse = st.number_input("ป้องกันใช้รหัสเดิม (รหัส)", 0, 24, 24)
ui.template_buttons({"สคริปต์เก็บข้อมูล AWS (bash)": ("collect_aws.sh", Path("scripts/collect_aws.sh").read_bytes()),
                     **{f"ตัวอย่าง: {n}": (n, c) for c, n in aw.demo_files(as_of)}})

with st.expander("📋 วิธีเก็บข้อมูลจากหน่วยรับตรวจ"):
    st.markdown("""
1. ขอให้หน่วยรับตรวจสร้าง IAM user/role สำหรับผู้ตรวจที่มีเฉพาะ policy **SecurityAudit** (อ่านอย่างเดียว)
2. ให้รัน `bash collect_aws.sh` ใน AWS CloudShell หรือเครื่องที่ติดตั้ง AWS CLI v2
3. ได้ไฟล์ zip แตกไฟล์แล้วอัปโหลดทั้งหมดที่นี่
""")

demo = ui.demo_toggle()
with ui.guard():
    if demo:
        files = [(c, n) for c, n in aw.demo_files(as_of)]
        account = account or "111122223333 (ตัวอย่าง)"
    else:
        ups = st.file_uploader("อัปโหลดไฟล์จากสคริปต์ (เลือกได้หลายไฟล์)", accept_multiple_files=True,
                               type=["csv", "json"])
        if not ups:
            st.info("อัปโหลดไฟล์ที่ได้จากสคริปต์ หรือเปิดข้อมูลตัวอย่างด้านบน")
            ui.footer()
            st.stop()
        files = [(f, f.name) for f in ups]
    data = aw.load_files(files)
    res = aw.analyze(data, aw.Params(as_of=as_of, key_rotation_days=int(rot), unused_days=int(unused),
                                     min_password_length=int(min_len), password_reuse=int(reuse)))
    buf = io.BytesIO()
    aw.write_report(res, buf, account or "(ไม่ระบุ)")

if res["stats"]["skipped"]:
    st.warning("ข้ามไฟล์ที่ไม่รู้จัก: " + ", ".join(res["stats"]["skipped"]))
s = res["stats"]
ui.metrics(res["findings"], [("IAM users", s["users"]), ("Security groups", s["security_groups"]),
                             ("S3 buckets", s["buckets"])])
ui.download(buf.getvalue(), "AWS_Configuration_Report.xlsx")
t = st.tabs(["สรุปผล", "ข้อตรวจพบ", "ผู้ถือสิทธิ์ Admin", "Credential report"])
with t[0]:
    ui.check_summary(aw.CHECKS, res["findings"], res["status"])
with t[1]:
    ui.findings_table(res["findings"], aw.CHECKS, aw.COL_TH)
with t[2]:
    st.dataframe(res["admins"], hide_index=True)
with t[3]:
    if res["credential_report"] is not None:
        st.dataframe(res["credential_report"], hide_index=True)
ui.footer()
