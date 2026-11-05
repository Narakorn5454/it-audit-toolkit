import io
from datetime import date

import pandas as pd
import streamlit as st

from audit_tools import finding_tracker as ft
from audit_tools import ui

ui.page("Audit Finding Tracker", "📌",
        "ติดตามข้อตรวจพบและแผนแก้ไขของหน่วยรับตรวจ: สถานะ อายุเกินกำหนด การเลื่อนกำหนด ข้อตรวจพบที่พบซ้ำ "
        "พร้อมร่างอีเมลติดตามรายผู้รับผิดชอบ และรายงานสรุปสำหรับคณะกรรมการตรวจสอบ",
        "IIA Global Internal Audit Standards (Domain IV: การติดตามผลการแก้ไข) · COBIT 2019 MEA")

blank = pd.DataFrame(columns=ft.COLUMNS)
ui.template_buttons({"แบบฟอร์ม Tracker (เปล่า)": ("finding_tracker_template.xlsx", ui.xlsx_bytes(blank)),
                     "ตัวอย่าง Tracker": ("finding_tracker_sample.xlsx", ui.xlsx_bytes(ft.demo_frame()))})
with st.sidebar:
    st.subheader("⚙️ ตั้งค่า")
    org = st.text_input("ชื่อองค์กร")
    as_of = st.date_input("ข้อมูล ณ วันที่", date.today())

demo = ui.demo_toggle()
with ui.guard():
    if demo:
        base = ft.demo_frame(as_of)
        org = org or "บริษัทตัวอย่าง จำกัด"
    else:
        c = st.columns(2)
        up = c[0].file_uploader("Tracker ที่มีอยู่ (.xlsx / .csv)", type=["xlsx", "csv"])
        rep = c[1].file_uploader("หรือนำเข้าจากรายงานของเครื่องมือในชุดนี้ (.xlsx)", type=["xlsx"],
                                 help="เช่น รายงาน SoD, Change Management, AWS — สร้าง 1 ข้อตรวจพบต่อ 1 รหัสการตรวจ")
        parts = []
        if up:
            parts.append(ft.load(up, up.name))
        if rep:
            with st.expander("ข้อมูลของรายการที่นำเข้า", expanded=True):
                cc = st.columns(3)
                aname = cc[0].text_input("ชื่องานตรวจ", rep.name.rsplit(".", 1)[0])
                owner = cc[1].text_input("ผู้รับผิดชอบ")
                dept = cc[2].text_input("ฝ่าย")
            parts.append(ft.import_toolkit_report(rep, rep.name, aname, owner, dept))
        if not parts:
            st.info("อัปโหลด Tracker เดิม นำเข้าจากรายงาน หรือเปิดข้อมูลตัวอย่าง — ดาวน์โหลดแบบฟอร์มเปล่าได้จากแถบด้านซ้าย")
            ui.footer()
            st.stop()
        base = pd.concat(parts, ignore_index=True)

st.subheader("✏️ แก้ไขสถานะและความคืบหน้า")
st.caption("แก้ในตารางได้โดยตรง เพิ่มแถวใหม่ได้ที่ท้ายตาราง แล้วกดดาวน์โหลด Tracker ฉบับปรับปรุงด้านล่าง")
edited = st.data_editor(
    base, num_rows="dynamic", hide_index=True, key=f"tracker_{demo}",
    column_config={"risk": st.column_config.SelectboxColumn("risk", options=ft.RISKS),
                   "status": st.column_config.SelectboxColumn("status", options=ft.STATUSES),
                   "title": st.column_config.TextColumn("title", width="large")})

with ui.guard():
    res = ft.analyze(edited, as_of)
    buf = io.BytesIO()
    ft.write_report(res, buf, org or "(ไม่ระบุ)")

k = res["kpi"]
c = st.columns(6)
c[0].metric("ทั้งหมด", k["total"])
c[1].metric("ยังค้าง", k["open"])
c[2].metric("🔴 เกินกำหนด", k["overdue"], f"High {k['overdue_high']}", delta_color="inverse")
c[3].metric("เฉลี่ยเกินกำหนด", f"{k['avg_days_overdue']:.0f} วัน")
c[4].metric("เคยเลื่อนกำหนด", k["extended"])
c[5].metric("ปิดตามกำหนด", f"{k['on_time_rate']:.0f}%" if k["on_time_rate"] is not None else "-")

c1, c2 = st.columns(2)
with c1:
    ui.download(buf.getvalue(), f"Finding_Status_Report_{as_of:%Y%m%d}.xlsx", "⬇️ รายงานสำหรับคณะกรรมการตรวจสอบ")
with c2:
    st.download_button("💾 Tracker ฉบับปรับปรุง", ui.xlsx_bytes(edited), f"finding_tracker_{as_of:%Y%m%d}.xlsx",
                       ui.XLSX)

t = st.tabs(["เกินกำหนด", "อายุเกินกำหนด", "รายฝ่าย", "ความเสี่ยง × สถานะ", "ร่างอีเมลติดตาม", "พบซ้ำ"])
with t[0]:
    od = res["overdue"][["finding_id", "audit_name", "title", "risk", "owner", "department", "effective_due",
                         "days_overdue", "latest_update"]].copy()
    od["risk"] = od["risk"].map(lambda r: f"{ui.SEV_EMOJI.get(r, '')} {r}")
    st.dataframe(od.rename(columns=ft.COL_TH), hide_index=True)
with t[1]:
    if not res["aging"].empty:
        st.bar_chart(res["aging"].set_index("aging"))
        st.dataframe(res["aging"].rename(columns={"aging": "อายุเกินกำหนด"}), hide_index=True)
with t[2]:
    st.dataframe(res["by_dept"].rename(columns=ft.COL_TH), hide_index=True)
with t[3]:
    st.dataframe(res["by_status"].rename(columns=ft.COL_TH), hide_index=True)
with t[4]:
    em = ft.followup_emails(res)
    if em.empty:
        st.success("ไม่มีรายการที่ต้องติดตาม")
    for r in em.itertuples():
        with st.expander(f"{r.owner} ({r.department}) — เกินกำหนด {r.overdue} / ใกล้ครบกำหนด {r.upcoming}"):
            st.text_input("หัวเรื่อง", r.subject, key=f"sub_{r.Index}")
            st.text_area("เนื้อหา", r.body, height=260, key=f"body_{r.Index}")
with t[5]:
    rp = res["data"][res["data"]["repeat"]][["finding_id", "audit_name", "title", "status"]]
    if rp.empty:
        st.success("ไม่พบข้อตรวจพบซ้ำ")
    else:
        st.dataframe(rp.rename(columns=ft.COL_TH), hide_index=True)
        st.caption("ข้อตรวจพบที่เกิดซ้ำข้ามงวด บ่งชี้ว่าการแก้ไขไม่ได้แก้ที่สาเหตุ ควรรายงานคณะกรรมการตรวจสอบ")
ui.footer()
