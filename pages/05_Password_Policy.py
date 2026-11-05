import io
from pathlib import Path

import pandas as pd
import streamlit as st

from audit_tools import password_policy as pp
from audit_tools import ui

ui.page("Password Policy Review", "🔑",
        "เทียบค่านโยบายรหัสผ่านที่ตั้งไว้จริงในแต่ละระบบกับเกณฑ์ รองรับไฟล์จาก Windows (secedit, net accounts), "
        "Active Directory, Linux (login.defs, pwquality, faillock, PAM) และตารางค่าของระบบงานอื่น",
        "ITGC Logical Access · ISO/IEC 27001:2022 A.5.17 Authentication information · CIS Benchmarks")

ui.template_buttons({
    **{f"ตัวอย่าง: {name}": (fname, content.strip().encode()) for name, (fname, content) in pp.DEMO_FILES.items()},
    "ตารางค่าระบบงาน (xlsx)": ("password_settings.xlsx", ui.xlsx_bytes(pp.demo_table())),
    "สคริปต์เก็บข้อมูล Windows": ("collect_windows.ps1", Path("scripts/collect_windows.ps1").read_bytes()),
    "สคริปต์เก็บข้อมูล Linux": ("collect_linux.sh", Path("scripts/collect_linux.sh").read_bytes()),
})
with st.sidebar:
    st.subheader("⚙️ เกณฑ์")
    org = st.text_input("ชื่อองค์กร")
    preset = st.selectbox("เลือกเกณฑ์ตั้งต้น", list(pp.BASELINES))

base_df = pd.DataFrame([{"param": p, "พารามิเตอร์": pp.PARAMS[p][0], "ต่ำสุด": lo, "สูงสุด": hi,
                         "ระดับ": sev, "คำอธิบายเกณฑ์": desc}
                        for p, (lo, hi, sev, desc) in pp.BASELINES[preset].items()])
with st.expander("✏️ ปรับเกณฑ์ให้ตรงกับนโยบายขององค์กร"):
    edited = st.data_editor(base_df, hide_index=True, disabled=["param", "พารามิเตอร์"],
                            column_config={"ระดับ": st.column_config.SelectboxColumn(
                                options=["High", "Medium", "Low"])})
    st.caption("เว้นว่าง = ไม่กำหนดขอบเขตด้านนั้น · อายุรหัสผ่านที่ไม่หมดอายุจะถือว่าเป็น ∞")
num = lambda v: None if pd.isna(v) or v == "" else float(v)
baseline = {r["param"]: (num(r["ต่ำสุด"]), num(r["สูงสุด"]), r["ระดับ"], r["คำอธิบายเกณฑ์"])
            for _, r in edited.iterrows()}

demo = ui.demo_toggle()
skipped = []
with ui.guard():
    if demo:
        systems = pp.demo_systems()
        org = org or "บริษัทตัวอย่าง จำกัด"
    else:
        ups = st.file_uploader("อัปโหลดไฟล์นโยบายรหัสผ่าน (เลือกได้หลายไฟล์)", accept_multiple_files=True,
                               type=["txt", "inf", "conf", "defs", "xlsx", "csv", "log"])
        if not ups:
            st.info("อัปโหลดไฟล์ที่ได้จากสคริปต์เก็บข้อมูล หรือเปิดข้อมูลตัวอย่างด้านบน")
            ui.footer()
            st.stop()
        st.write("**ตั้งชื่อระบบของแต่ละไฟล์** (ไฟล์ที่ชื่อระบบเหมือนกันจะถูกรวมกัน)")
        files = []
        for i, f in enumerate(ups):
            name = st.text_input(f.name, Path(f.name).stem.split("__")[0], key=f"sys_{i}")
            files.append((name, f, f.name))
        systems = pp.load_files(files, skipped)
    res = pp.evaluate(systems, baseline)
    buf = io.BytesIO()
    name = preset if edited.equals(base_df) else f"{preset} (ปรับตามนโยบายองค์กร)"
    pp.write_report(res, buf, name, org or "(ไม่ระบุ)", baseline)

if skipped:
    st.warning("ข้ามไฟล์ที่ไม่ใช่นโยบายรหัสผ่าน: " + ", ".join(skipped))
ui.metrics(res["findings"], [("ระบบ", len(systems))])
ui.download(buf.getvalue(), "Password_Policy_Report.xlsx")
t = st.tabs(["คะแนนรายระบบ", "เทียบค่าทุกระบบ", "ข้อตรวจพบ", "ไฟล์ที่อ่าน"])
with t[0]:
    st.bar_chart(res["score"].set_index("system")["compliance_pct"])
    st.dataframe(res["score"].rename(columns=pp.COL_TH), hide_index=True)
with t[1]:
    st.dataframe(res["pivot"].rename(columns=pp.COL_TH), hide_index=True)
with t[2]:
    ui.findings_table(res["findings"], pp.checks_for(baseline), pp.COL_TH)
with t[3]:
    st.dataframe(pd.DataFrame([{"ระบบ": s["system"], "รูปแบบไฟล์": s["source"],
                                "จำนวนค่าที่อ่านได้": len(s["values"])} for s in systems]), hide_index=True)
ui.footer()
