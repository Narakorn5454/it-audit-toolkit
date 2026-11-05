import io
from pathlib import Path

import streamlit as st

from audit_tools import hardening as hd
from audit_tools import ui

ui.page("System Hardening Review", "🛡️",
        "ตรวจค่าความปลอดภัยของเครื่อง Linux และ Windows เทียบเกณฑ์แนว CIS Benchmark "
        "จากไฟล์ที่ได้จากสคริปต์เก็บข้อมูลแบบอ่านอย่างเดียว",
        "CIS Benchmarks · ISO/IEC 27001:2022 A.8.9 Configuration management · NIST CSF 2.0 PR.PS-01")

ui.template_buttons({
    **{f"ตัวอย่าง {host}: {fname}": (fname, content.encode()) for (host, fname), content in hd.DEMO.items()},
    "สคริปต์เก็บข้อมูล Windows": ("collect_windows.ps1", Path("scripts/collect_windows.ps1").read_bytes()),
    "สคริปต์เก็บข้อมูล Linux": ("collect_linux.sh", Path("scripts/collect_linux.sh").read_bytes()),
})
with st.sidebar:
    st.subheader("⚙️ ตั้งค่า")
    org = st.text_input("ชื่อองค์กร")

with st.expander("📋 วิธีเก็บข้อมูลจากหน่วยรับตรวจ"):
    st.markdown("""
1. ดาวน์โหลดสคริปต์จากแถบด้านซ้าย ส่งให้ผู้ดูแลระบบของหน่วยรับตรวจ
2. **Windows:** เปิด PowerShell แบบ Run as Administrator แล้วรัน `powershell -ExecutionPolicy Bypass -File .\\collect_windows.ps1`
3. **Linux:** รัน `sudo sh collect_linux.sh`
4. สคริปต์อ่านอย่างเดียว ไม่เปลี่ยนการตั้งค่า และไม่เก็บรหัสผ่าน ได้ไฟล์ zip / tar.gz ส่งกลับ
5. แตกไฟล์แล้วอัปโหลดที่นี่ (ไฟล์ที่ไม่เกี่ยวข้องจะถูกข้ามให้อัตโนมัติ)
""")

demo = ui.demo_toggle()
with ui.guard():
    if demo:
        files = hd.demo_files()
        org = org or "บริษัทตัวอย่าง จำกัด"
    else:
        host_all = st.text_input("ชื่อเครื่อง (ใช้กับทุกไฟล์ แก้รายไฟล์ได้ด้านล่าง)", "server-01")
        ups = st.file_uploader("อัปโหลดไฟล์การตั้งค่า (เลือกได้หลายไฟล์)", accept_multiple_files=True)
        if not ups:
            st.info("อัปโหลดไฟล์ที่ได้จากสคริปต์ หรือเปิดข้อมูลตัวอย่างด้านบน")
            ui.footer()
            st.stop()
        files = []
        cols = st.columns(3)
        for i, f in enumerate(ups):
            h = cols[i % 3].text_input(f.name, f.name.split("__")[0] if "__" in f.name else host_all, key=f"host_{i}")
            files.append((h, f, f.name))
    res = hd.review(files)
    buf = io.BytesIO()
    hd.write_report(res, buf, org or "(ไม่ระบุ)")

hs = res["host_score"]
ui.metrics(res["findings"], [("เครื่อง", len(hs)),
                             ("% ผ่านเกณฑ์เฉลี่ย", f"{hs['compliance_pct'].mean():.0f}%")])
ui.download(buf.getvalue(), "System_Hardening_Report.xlsx")
t = st.tabs(["คะแนน", "ข้อตรวจพบ", "ผลทุกข้อ", "ไฟล์ที่อ่าน"])
with t[0]:
    st.bar_chart(hs.set_index("host")["compliance_pct"])
    st.dataframe(res["score"].rename(columns=hd.COL_TH), hide_index=True)
with t[1]:
    ui.findings_table(res["findings"], hd.CHECKS, hd.COL_TH)
with t[2]:
    st.dataframe(res["matrix"].rename(columns=hd.COL_TH), hide_index=True)
with t[3]:
    st.dataframe(res["files"].rename(columns=hd.COL_TH), hide_index=True)
ui.footer()
