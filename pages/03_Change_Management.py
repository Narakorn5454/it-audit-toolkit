import io

import streamlit as st

from audit_tools import change_mgmt as cm
from audit_tools import ui

ui.page("Change Management Review", "🔄",
        "เทียบ log การนำโปรแกรมขึ้นระบบจริง (deployment) กับใบคำขอใน ITSM เช่น Jira / ServiceNow "
        "ใช้ log การ deploy เป็นประชากร จึงจับการเปลี่ยนแปลงที่ไม่ผ่านกระบวนการได้",
        "ITGC Change Management · COBIT 2019 BAI06 · ISO/IEC 27001:2022 A.8.32 Change management, A.8.31")

dep_d, tix_d = cm.demo_frames()
ui.template_buttons({"ตัวอย่าง Deployment log": ("chg_deployments.xlsx", ui.xlsx_bytes(dep_d)),
                     "ตัวอย่าง Tickets จาก ITSM": ("chg_tickets.xlsx", ui.xlsx_bytes(tix_d))})
with st.sidebar:
    st.subheader("⚙️ ตั้งค่า")
    org = st.text_input("ชื่อองค์กร")
    work = st.slider("ช่วงเวลาที่อนุญาตให้ deploy", 0, 24, (8, 18))
    em_days = st.number_input("Emergency ต้องอนุมัติย้อนหลังภายใน (วัน)", 0, 30, 3)
    em_ratio = st.slider("เกณฑ์สัดส่วน Emergency (%)", 1, 50, 10)

demo = ui.demo_toggle()
with ui.guard():
    if demo:
        dep, tix = dep_d, tix_d
        org = org or "ธนาคารตัวอย่าง จำกัด"
    else:
        c = st.columns(2)
        f1 = c[0].file_uploader("1. Deployment log (จาก CI/CD หรือระบบจริง)", type=["xlsx", "csv"])
        f2 = c[1].file_uploader("2. รายการใบคำขอจาก ITSM", type=["xlsx", "csv"])
        if not (f1 and f2):
            st.info("อัปโหลดทั้ง 2 ไฟล์ หรือเปิดข้อมูลตัวอย่างด้านบน")
            ui.footer()
            st.stop()
        dep, tix = cm.load(f1, f2, {"deployments": f1.name, "tickets": f2.name})
    res = cm.analyze(dep, tix, cm.Params(work_start=work[0], work_end=work[1], emergency_days=int(em_days),
                                         emergency_ratio=em_ratio / 100))
    buf = io.BytesIO()
    cm.write_report(res, buf, org or "(ไม่ระบุ)")

s = res["stats"]
ui.metrics(res["findings"], [("การ deploy", s["deploys"]), ("Emergency", f"{s['emergency_ratio']:.1%}")])
ui.download(buf.getvalue(), "Change_Management_Report.xlsx")
t = st.tabs(["สรุปผล", "ข้อตรวจพบ", "แนวโน้มรายเดือน", "รายระบบ"])
with t[0]:
    ui.check_summary(cm.CHECKS, res["findings"])
with t[1]:
    ui.findings_table(res["findings"], cm.CHECKS, cm.COL_TH)
with t[2]:
    st.bar_chart(res["monthly"].set_index("month"))
with t[3]:
    st.dataframe(res["by_system"], hide_index=True)
ui.footer()
