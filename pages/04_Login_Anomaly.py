import io

import streamlit as st

from audit_tools import login_anomaly as la
from audit_tools import ui

ui.page("Login Anomaly Detection", "🕵️",
        "วิเคราะห์ log การเข้าสู่ระบบเพื่อหา brute force, password spraying, impossible travel, "
        "การเข้าใช้ของบัญชีที่ปิดแล้ว และพฤติกรรมผิดปกติอื่น ๆ "
        "รองรับ Windows Security log (4624/4625), Microsoft Entra ID sign-in log และ log ทั่วไป",
        "ISO/IEC 27001:2022 A.8.15 Logging, A.8.16 Monitoring, A.5.25 · NIST CSF 2.0 DE.CM · CIS Control 8")

log_d, ul_d = la.demo_frames()
ui.template_buttons({"ตัวอย่าง Login log": ("login_log.xlsx", ui.xlsx_bytes(log_d)),
                     "ตัวอย่างรายชื่อผู้ใช้": ("login_users.xlsx", ui.xlsx_bytes(ul_d))})
with st.sidebar:
    st.subheader("⚙️ ตั้งค่า")
    org = st.text_input("ชื่อองค์กร")
    source = st.text_input("แหล่งข้อมูล", placeholder="เช่น VPN, Domain Controller")
    with st.expander("เกณฑ์การตรวจ", expanded=True):
        n_fail = st.number_input("ผิดกี่ครั้ง = brute force", 2, 100, 5)
        w_fail = st.number_input("ภายในกี่นาที", 1, 1440, 10)
        n_spray = st.number_input("IP เดียวลองกี่บัญชี = spraying", 2, 100, 5)
        travel = st.number_input("ต่างประเทศภายในกี่ชั่วโมง = เดินทางไม่ทัน", 1, 48, 4)
        work = st.slider("เวลาทำการ", 0, 24, (7, 20))
        dormant = st.number_input("ไม่ใช้งานกี่วัน = dormant", 7, 365, 60)
        countries = st.text_input("ประเทศที่อนุญาต (รหัส 2 ตัว คั่นด้วย ,)", "TH")

demo = ui.demo_toggle()
with ui.guard():
    if demo:
        log, users = log_d, ul_d
        org, source = org or "บริษัทตัวอย่าง จำกัด", source or "VPN + Domain Controller"
    else:
        c = st.columns(2)
        f1 = c[0].file_uploader("1. Login log", type=["xlsx", "csv"])
        f2 = c[1].file_uploader("2. รายชื่อผู้ใช้และสถานะ (ไม่บังคับ)", type=["xlsx", "csv"])
        if not f1:
            st.info("อัปโหลด log การเข้าสู่ระบบ หรือเปิดข้อมูลตัวอย่างด้านบน")
            ui.footer()
            st.stop()
        log, users = la.load(f1, f2, {"log": f1.name, "users": f2.name if f2 else None})
    params = la.Params(fail_threshold=int(n_fail), fail_window_min=int(w_fail), spray_users=int(n_spray),
                       travel_hours=float(travel), work_start=work[0], work_end=work[1],
                       dormant_days=int(dormant), allowed_countries=countries.split(","))
    res = la.analyze(log, users, params)
    buf = io.BytesIO()
    la.write_report(res, buf, org or "(ไม่ระบุ)", source or "(ไม่ระบุ)")

s = res["stats"]
ui.metrics(res["findings"], [("เหตุการณ์", s["events"]), ("ไม่สำเร็จ", s["failure"]),
                             ("บัญชีที่ผิดปกติ", s["flagged_users"])])
ui.download(buf.getvalue(), "Login_Anomaly_Report.xlsx")
t = st.tabs(["สรุปผล", "ข้อตรวจพบ", "รูปแบบรายชั่วโมง", "บัญชีที่ผิดบ่อย"])
with t[0]:
    ui.check_summary(la.CHECKS, res["findings"], res["status"])
with t[1]:
    ui.findings_table(res["findings"], la.CHECKS, la.COL_TH)
with t[2]:
    st.bar_chart(res["hourly"].set_index("hour"))
    st.caption("การเข้าสู่ระบบช่วงกลางคืนที่สูงผิดปกติ ควรตรวจสอบเพิ่มเติม")
with t[3]:
    st.dataframe(res["top_fail"], hide_index=True)
ui.footer()
