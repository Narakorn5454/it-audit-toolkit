import io
from datetime import date
from pathlib import Path

import streamlit as st

from audit_tools import cloud_aws as aws
from audit_tools import cloud_azure as azure
from audit_tools import cloud_gcp as gcp
from audit_tools import cloud_summary as cs
from audit_tools import ui
from audit_tools.common import AuditError

ui.page("Multi-Cloud Configuration Review", "☁️",
        "ตรวจการตั้งค่าความปลอดภัยของ AWS, Microsoft Azure และ Google Cloud จากไฟล์ที่หน่วยรับตรวจ export "
        "ด้วยสคริปต์แบบอ่านอย่างเดียว ผู้ตรวจไม่ต้องเข้าบัญชี cloud เอง และเปรียบเทียบความเสี่ยงข้าม cloud ได้ในหน้าเดียว",
        "CIS Foundations Benchmarks (AWS / Azure / GCP) · ISO/IEC 27001:2022 A.5.23 Cloud services · CSA CCM")

with st.sidebar:
    st.subheader("⚙️ ตั้งค่า")
    org = st.text_input("ชื่อองค์กร")
    as_of = st.date_input("วันที่ของข้อมูล", date.today())
    with st.expander("เกณฑ์"):
        rot = st.number_input("หมุนเวียน access key / SA key ทุก (วัน)", 1, 3650, 90)
        unused = st.number_input("AWS: credential ไม่ใช้งานเกิน (วัน)", 1, 3650, 45)
        min_len = st.number_input("AWS: ความยาวรหัสผ่านขั้นต่ำ", 6, 128, 14)
        reuse = st.number_input("AWS: ป้องกันใช้รหัสเดิม (รหัส)", 0, 24, 24)
ui.template_buttons({
    "สคริปต์เก็บข้อมูล AWS": ("collect_aws.sh", Path("scripts/collect_aws.sh").read_bytes()),
    "สคริปต์เก็บข้อมูล Azure": ("collect_azure.sh", Path("scripts/collect_azure.sh").read_bytes()),
    "สคริปต์เก็บข้อมูล Google Cloud": ("collect_gcp.sh", Path("scripts/collect_gcp.sh").read_bytes()),
})

HOWTO = {
    "AWS": "ให้หน่วยรับตรวจสร้างสิทธิ์สำหรับผู้ตรวจด้วย policy **SecurityAudit** แล้วรัน `bash collect_aws.sh` "
           "ใน AWS CloudShell",
    "Azure": "ให้สิทธิ์ผู้ตรวจ **Reader + Security Reader** (subscription) และ **Global Reader** (Entra ID) "
             "แล้วรัน `bash collect_azure.sh` ใน Azure Cloud Shell (Bash)",
    "Google Cloud": "ให้สิทธิ์ผู้ตรวจ **roles/viewer + roles/iam.securityReviewer** ระดับ project "
                    "แล้วรัน `bash collect_gcp.sh <project-id>` ใน Google Cloud Shell",
}
CLOUDS = {
    "AWS": dict(mod=aws, demo=lambda: aws.demo_files(as_of), report="AWS_Configuration_Report.xlsx",
                analyze=lambda d: aws.analyze(d, aws.Params(as_of=as_of, key_rotation_days=int(rot),
                                                            unused_days=int(unused), min_password_length=int(min_len),
                                                            password_reuse=int(reuse))),
                metrics=lambda s: [("IAM users", s["users"]), ("Security groups", s["security_groups"])]),
    "Azure": dict(mod=azure, demo=azure.demo_files, report="Azure_Configuration_Report.xlsx",
                  analyze=lambda d: azure.analyze(d),
                  metrics=lambda s: [("ผู้ใช้ (MFA)", s["users_mfa_checked"]), ("NSGs", s["nsgs"])]),
    "Google Cloud": dict(mod=gcp, demo=lambda: gcp.demo_files(as_of), report="GCP_Configuration_Report.xlsx",
                         analyze=lambda d: gcp.analyze(d, gcp.Params(as_of=as_of, key_rotation_days=int(rot))),
                         metrics=lambda s: [("Firewall rules", s["firewall_rules"]), ("Buckets", s["buckets"])]),
}

results: dict[str, dict] = {}


def cloud_tab(name: str, spec: dict):
    key = name.split()[0].lower()
    st.caption("📋 " + HOWTO[name])
    c1, c2 = st.columns([1, 2])
    demo = c1.toggle("ทดลองด้วยข้อมูลตัวอย่าง", key=f"demo_{key}")
    label = c2.text_input("ชื่อบัญชี / subscription / project", key=f"name_{key}")
    if demo:
        files = spec["demo"]()
    else:
        ups = st.file_uploader(f"อัปโหลดไฟล์จากสคริปต์ {name} (เลือกได้หลายไฟล์)", accept_multiple_files=True,
                               type=["json", "csv"], key=f"up_{key}")
        if not ups:
            st.info("อัปโหลดไฟล์ที่ได้จากสคริปต์ (ดาวน์โหลดสคริปต์ได้ที่แถบซ้าย) หรือเปิดข้อมูลตัวอย่าง")
            return
        files = [(f, f.name) for f in ups]
    try:
        res = spec["analyze"](spec["mod"].load_files(files))
        buf = io.BytesIO()
        spec["mod"].write_report(res, buf, label or "(ไม่ระบุ)")
    except AuditError as e:
        st.error(str(e))
        return
    results[name] = res
    if res["stats"].get("skipped"):
        st.warning("ข้ามไฟล์ที่ไม่รู้จัก: " + ", ".join(res["stats"]["skipped"]))
    ui.metrics(res["findings"], spec["metrics"](res["stats"]))
    ui.download(buf.getvalue(), spec["report"], f"⬇️ รายงาน {name} (Excel)")
    a, b = st.tabs(["สรุปผล", "ข้อตรวจพบ"])
    with a:
        ui.check_summary(spec["mod"].CHECKS, res["findings"], res["status"])
        if not res["admins"].empty:
            with st.expander("ผู้ถือสิทธิ์ระดับสูง"):
                st.dataframe(res["admins"], hide_index=True)
    with b:
        ui.findings_table(res["findings"], spec["mod"].CHECKS, spec["mod"].COL_TH, key=f"f_{key}")


tabs = st.tabs(["🟧 AWS", "🟦 Azure", "🟩 Google Cloud", "📊 สรุปรวมทุก Cloud"])
for tab, (name, spec) in zip(tabs[:3], CLOUDS.items()):
    with tab:
        cloud_tab(name, spec)

with tabs[3]:
    if not results:
        st.info("เปิดข้อมูลตัวอย่างหรืออัปโหลดไฟล์ในแท็บของแต่ละ cloud ก่อน แล้วสรุปรวมจะแสดงที่นี่")
    else:
        comb = cs.combine(results)
        st.write(f"**Cloud ที่ตรวจ:** {', '.join(comb['clouds'])} · ข้อตรวจพบรวม **{len(comb['findings']):,}** รายการ")
        c1, c2 = st.columns(2)
        with c1:
            st.write("**จำนวนข้อตรวจพบตามระดับความเสี่ยง**")
            st.dataframe(comb["by_cloud"], hide_index=True)
        with c2:
            st.write("**เปรียบเทียบตามหมวดความเสี่ยง**")
            st.dataframe(comb["matrix"], hide_index=True)
        st.bar_chart(comb["matrix"].set_index("หมวดความเสี่ยง"), stack=False)
        st.caption("ช่วยให้เห็นว่าแต่ละ cloud อ่อนด้านไหน เช่น Identity บน AWS แต่ Network บน Azure — "
                   "ใช้วางลำดับความสำคัญและสื่อสารกับผู้บริหาร")
        buf = io.BytesIO()
        cs.write_report(comb, buf, org or "(ไม่ระบุ)")
        ui.download(buf.getvalue(), "MultiCloud_Configuration_Report.xlsx", "⬇️ รายงานรวมทุก Cloud (Excel)")
        ui.findings_table(comb["findings"], cs.CHECKS_ALL, cs.COL_TH, key="f_all")
ui.footer()
