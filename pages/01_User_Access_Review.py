
from __future__ import annotations

import io
from datetime import date

import pandas as pd
import streamlit as st

from audit_tools import access_review as uar
from audit_tools import ui


SEV_EMOJI = {"High": "🔴", "Medium": "🟠", "Low": "🟢", "Review": "🔵"}

st.set_page_config(page_title="User Access Review Tool", page_icon="🔍", layout="wide")


def to_excel_bytes(df: pd.DataFrame) -> bytes:
    buf = io.BytesIO()
    df.to_excel(buf, index=False)
    return buf.getvalue()


@st.cache_data
def templates() -> dict[str, bytes]:
    hr = pd.DataFrame(columns=["employee_id", "full_name", "department", "position",
                               "status", "termination_date"])
    users = pd.DataFrame(columns=["username", "employee_id", "full_name", "role",
                                  "account_status", "last_login", "created_date"])
    sod = pd.DataFrame(uar.DEFAULT_SOD_RULES, columns=["role_a", "role_b", "risk"])
    return {"hr": to_excel_bytes(hr), "users": to_excel_bytes(users), "sod": to_excel_bytes(sod)}


# ---------------------------------------------------------------------------
# Sidebar: ตั้งค่า
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ ตั้งค่าการตรวจ")
    system_name = st.text_input("ชื่อระบบที่ตรวจ", placeholder="เช่น SAP, Active Directory")
    as_of = st.date_input("ข้อมูล ณ วันที่", value=date.today())
    dormant_days = st.number_input("เกณฑ์ไม่ได้ใช้งาน (วัน)", min_value=1, max_value=3650,
                                   value=90, step=15)
    st.divider()
    st.subheader("📄 แบบฟอร์มไฟล์ (Template)")
    t = templates()
    xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    st.download_button("แบบฟอร์ม HR", t["hr"], "template_hr.xlsx", xlsx)
    st.download_button("แบบฟอร์ม Users", t["users"], "template_users.xlsx", xlsx)
    st.download_button("แบบฟอร์มกฎ SoD", t["sod"], "template_sod_rules.xlsx", xlsx)
    st.caption("ชื่อคอลัมน์ภาษาไทยที่พบบ่อย เช่น รหัสพนักงาน, ตำแหน่ง, สิทธิ์ "
               "ระบบจะจับคู่ให้อัตโนมัติ")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
st.title("🔍 User Access Review Tool")
st.write("เทียบรายชื่อพนักงานจาก HR กับบัญชีผู้ใช้ในระบบ แล้วออกรายงานข้อตรวจพบสำหรับงาน IT Audit "
         "ภายในไม่กี่วินาที")

use_demo = st.toggle("ทดลองด้วยข้อมูลตัวอย่าง", value=False)

if use_demo:
    hr_df, users_df, sod_df = uar.demo_frames(as_of)
    sod_rules = uar.DEFAULT_SOD_RULES
    if not system_name:
        system_name = "ระบบ ERP (ข้อมูลตัวอย่าง)"
    with st.expander("ดูข้อมูลตัวอย่าง"):
        st.write("**HR**")
        st.dataframe(hr_df, hide_index=True)
        st.write("**Users**")
        st.dataframe(users_df, hide_index=True)
    ready = True
else:
    c1, c2, c3 = st.columns(3)
    hr_file = c1.file_uploader("1. รายชื่อพนักงาน (HR)", type=["xlsx", "csv"])
    users_file = c2.file_uploader("2. รายชื่อ User จากระบบ", type=["xlsx", "csv"])
    sod_file = c3.file_uploader("3. กฎ SoD (ไม่บังคับ)", type=["xlsx", "csv"],
                                help="ถ้าไม่อัปโหลด จะใช้กฎตั้งต้น 8 ข้อ")
    ready = hr_file is not None and users_file is not None
    if not ready:
        st.info("อัปโหลดไฟล์ HR และ Users เพื่อเริ่มตรวจ หรือเปิด **ทดลองด้วยข้อมูลตัวอย่าง** ด้านบน")

if ready:
    try:
        if not use_demo:
            hr_df = uar.read_table(hr_file, hr_file.name)
            users_df = uar.read_table(users_file, users_file.name)
            sod_rules = uar.load_sod_rules(sod_file, sod_file.name) if sod_file else uar.DEFAULT_SOD_RULES
        findings, stats = uar.run_checks(hr_df, users_df, sod_rules, as_of, int(dormant_days))
        report = io.BytesIO()
        uar.write_report(findings, stats, report, system_name or "(ไม่ระบุ)", as_of, int(dormant_days))
    except uar.UARError as e:
        st.error(str(e))
        st.stop()

    # --- Metrics ---
    st.divider()
    high = int((findings["severity"] == "High").sum()) if not findings.empty else 0
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("พนักงานใน HR", stats["hr_total"], f"ลาออก {stats['hr_resigned']}", delta_color="off")
    m2.metric("บัญชีในระบบ", stats["user_total"], f"เปิดใช้ {stats['user_active']}", delta_color="off")
    m3.metric("ข้อตรวจพบทั้งหมด", len(findings))
    m4.metric("ความเสี่ยงสูง (High)", high)

    fname = f"UAR_Report_{as_of:%Y%m%d}.xlsx"
    st.download_button("⬇️ ดาวน์โหลดรายงาน Excel", report.getvalue(), fname,
                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                       type="primary")

    tab1, tab2, tab3 = st.tabs(["สรุปผล", "ข้อตรวจพบ", "เกณฑ์การตรวจ"])

    with tab1:
        rows = []
        for cid, (title, sev, rec) in uar.CHECKS.items():
            n = int((findings["check_id"] == cid).sum()) if not findings.empty else 0
            rows.append({"รหัส": cid, "รายการตรวจสอบ": title,
                         "ระดับ": f"{SEV_EMOJI.get(sev, '')} {sev}",
                         "จำนวนที่พบ": n, "ผล": "⚠️ พบข้อสังเกต" if n else "✅ ไม่พบ"})
        summary = pd.DataFrame(rows)
        st.dataframe(summary, hide_index=True)
        chart = summary[summary["จำนวนที่พบ"] > 0].set_index("รหัส")["จำนวนที่พบ"]
        if not chart.empty:
            st.bar_chart(chart)

    with tab2:
        if findings.empty:
            st.success("ไม่พบข้อตรวจพบ 🎉")
        else:
            f1, f2 = st.columns(2)
            sev_pick = f1.multiselect("ระดับความเสี่ยง", list(uar.SEVERITY_ORDER),
                                      default=list(uar.SEVERITY_ORDER))
            chk_pick = f2.multiselect("รายการตรวจ", list(uar.CHECKS), default=list(uar.CHECKS))
            view = findings[findings["severity"].isin(sev_pick) & findings["check_id"].isin(chk_pick)]
            view = view.rename(columns=uar.COL_TH)
            st.dataframe(view, hide_index=True)
            st.caption(f"แสดง {len(view)} จาก {len(findings)} รายการ")

    with tab3:
        st.dataframe(pd.DataFrame(
            [{"รหัส": k, "รายการตรวจสอบ": v[0], "ระดับ": v[1], "ข้อเสนอแนะ": v[2]}
             for k, v in uar.CHECKS.items()]), hide_index=True)
        st.write("**กฎ SoD ที่ใช้**")
        st.dataframe(pd.DataFrame(sod_rules, columns=["สิทธิ์ A", "สิทธิ์ B", "ความเสี่ยง"]),
                     hide_index=True)

ui.footer()
