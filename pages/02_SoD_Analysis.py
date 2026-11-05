import io

import streamlit as st

from audit_tools import sod, ui

ui.page("SoD Analysis", "⚖️",
        "วิเคราะห์สิทธิ์ขัดแย้ง (Segregation of Duties) ข้ามหลายระบบ เช่น ERP + Banking + HR "
        "โดยเชื่อมตัวตนผู้ใช้ด้วยรหัสพนักงาน และตรวจหา Role ที่ออกแบบให้ขัดแย้งในตัวเอง",
        "ITGC Logical Access · COBIT 2019 DSS05.04 / APO01 · ISO/IEC 27001:2022 A.5.3 Segregation of duties")

ur_d, rp_d, rules_d, mit_d = sod.demo_frames()
ui.template_buttons({"ตัวอย่าง User-Role": ("sod_user_roles.xlsx", ui.xlsx_bytes(ur_d)),
                     "ตัวอย่าง Role-Permission": ("sod_role_permissions.xlsx", ui.xlsx_bytes(rp_d)),
                     "ชุดกฎ SoD ตั้งต้น (11 กฎ)": ("sod_rules.xlsx", ui.xlsx_bytes(rules_d)),
                     "ตัวอย่างการควบคุมชดเชย": ("sod_mitigations.xlsx", ui.xlsx_bytes(mit_d))})
with st.sidebar:
    st.subheader("⚙️ ตั้งค่า")
    org = st.text_input("ชื่อองค์กร")
    max_roles = st.number_input("จำนวน Role สูงสุดที่ยอมรับได้ต่อคน", 1, 50, 5)

demo = ui.demo_toggle()
with ui.guard():
    if demo:
        ur, rp, rules, mit = ur_d, rp_d, rules_d, mit_d
        org = org or "บริษัทตัวอย่าง จำกัด"
    else:
        c = st.columns(4)
        f1 = c[0].file_uploader("1. User-Role (ทุกระบบ)", type=["xlsx", "csv"])
        f2 = c[1].file_uploader("2. Role-Permission", type=["xlsx", "csv"])
        f3 = c[2].file_uploader("3. กฎ SoD (ไม่ใส่ = ใช้กฎตั้งต้น)", type=["xlsx", "csv"])
        f4 = c[3].file_uploader("4. การควบคุมชดเชย (ไม่บังคับ)", type=["xlsx", "csv"])
        if not (f1 and f2):
            st.info("อัปโหลดไฟล์ 1 และ 2 เพื่อเริ่มวิเคราะห์ หรือเปิดข้อมูลตัวอย่างด้านบน")
            ui.footer()
            st.stop()
        ur, rp, rules, mit = sod.load(f1, f2, f3 if f3 else io.BytesIO(ui.xlsx_bytes(rules_d)), f4,
                                      {"user_roles": f1.name, "role_permissions": f2.name,
                                       "rules": f3.name if f3 else "rules.xlsx",
                                       "mitigations": f4.name if f4 else None})
    res = sod.analyze(ur, rp, rules, mit, sod.Params(max_roles=int(max_roles)))
    buf = io.BytesIO()
    sod.write_report(res, buf, org or "(ไม่ระบุ)")

s = res["stats"]
ui.metrics(res["findings"], [("ระบบ", s["systems"]), ("ผู้ใช้", s["people"]),
                             ("ผู้ใช้ที่มีสิทธิ์ขัดแย้ง", s["people_conflict"])])
ui.download(buf.getvalue(), "SoD_Report.xlsx")

t = st.tabs(["สรุปผล", "ข้อตรวจพบ", "ผู้ใช้", "Matrix กฎ × ฝ่าย", "Role ที่ออกแบบผิด"])
with t[0]:
    ui.check_summary(sod.CHECKS, res["findings"])
with t[1]:
    ui.findings_table(res["findings"], sod.CHECKS, sod.COL_TH)
with t[2]:
    st.dataframe(res["users"].rename(columns=sod.COL_TH), hide_index=True)
with t[3]:
    if res["matrix"].empty:
        st.success("ไม่พบสิทธิ์ขัดแย้ง")
    else:
        st.dataframe(res["matrix"], hide_index=True)
        st.caption("ช่วยให้เห็นว่าฝ่ายไหนมีปัญหาการแบ่งแยกหน้าที่มากที่สุด")
with t[4]:
    if res["inherent"].empty:
        st.success("ไม่พบ Role ที่ขัดแย้งในตัวเอง")
    else:
        st.dataframe(res["inherent"].rename(columns=sod.COL_TH), hide_index=True)
ui.footer()
