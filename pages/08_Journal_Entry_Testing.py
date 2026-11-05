
from __future__ import annotations

import io

import pandas as pd
import streamlit as st

from audit_tools import journal_entry as jet
from audit_tools import ui


LEVEL_EMOJI = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

st.set_page_config(page_title="Journal Entry Testing", page_icon="📒", layout="wide")


def to_xlsx(df: pd.DataFrame) -> bytes:
    b = io.BytesIO()
    df.to_excel(b, index=False)
    return b.getvalue()


@st.cache_data
def templates() -> dict[str, bytes]:
    gl = pd.DataFrame(columns=["je_number", "line_no", "posting_date", "entry_date", "entry_time",
                               "account", "account_name", "description", "debit", "credit",
                               "created_by", "approved_by", "source"])
    return {"gl": to_xlsx(gl), "hol": to_xlsx(jet.demo_holidays())}


@st.cache_data
def demo_data():
    return jet.demo_gl()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ ตั้งค่าการทดสอบ")
    company = st.text_input("ชื่อบริษัท", placeholder="เช่น บริษัท ABC จำกัด")
    period = st.text_input("งวดบัญชี", placeholder="เช่น FY2026")

    with st.expander("วงเงินและยอดเงิน", expanded=True):
        thr_txt = st.text_input("วงเงินอนุมัติ (คั่นด้วย ,)", "50000, 100000, 500000, 1000000")
        below_pct = st.slider("ต่ำกว่าวงเงินไม่เกิน (%)", 1, 20, 5)
        round_unit = st.number_input("ยอดกลม: หารด้วยค่านี้ลงตัว", 100, 1_000_000, 1000, step=100)
        round_min = st.number_input("ยอดกลม: ขั้นต่ำ", 0, 100_000_000, 10_000, step=1000)
        large_amt = st.number_input("ยอดเงินสูง (0 = ใช้ percentile 99)", 0, 10_000_000_000, 0, step=100_000)

    with st.expander("เวลาและงวดบัญชี"):
        work = st.slider("เวลาทำการ", 0, 24, (8, 18))
        period_end_days = st.number_input("ช่วงสิ้นงวด (วันสุดท้ายของเดือน)", 1, 10, 3)
        close_days = st.number_input("ปิดงวดภายใน (วันหลังสิ้นเดือน)", 0, 60, 5)
        hol_file = st.file_uploader("ไฟล์วันหยุด (คอลัมน์ date)", type=["xlsx", "csv"])

    with st.expander("ผู้บันทึกและคำอธิบาย"):
        rare_user = st.number_input("ผู้บันทึกน้อยผิดปกติ (ไม่เกิน n เอกสาร)", 1, 100, 3)
        kw_txt = st.text_area("คำที่น่าสงสัย (คั่นด้วย ,)", ", ".join(jet.DEFAULT_KEYWORDS), height=120)

    st.divider()
    t = templates()
    st.download_button("📄 แบบฟอร์มไฟล์ GL", t["gl"], "template_gl.xlsx", XLSX)
    st.download_button("📅 ตัวอย่างไฟล์วันหยุด 2026", t["hol"], "holidays_2026.xlsx", XLSX)
    st.caption("รองรับชื่อคอลัมน์ภาษาไทย และไฟล์ export จาก SAP (BELNR, BUDAT, CPUDT, CPUTM, "
               "HKONT, DMBTR, SHKZG, USNAM, SGTXT) รวมถึงวันที่แบบ พ.ศ.")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
st.title("📒 Journal Entry Testing")
st.write("วิเคราะห์รายการบันทึกบัญชีทั้งหมด 100% ด้วยการทดสอบ 16 รายการ "
         "แล้วจัดลำดับเอกสารที่มีความเสี่ยงสูงสุดให้ตรวจก่อน (อ้างอิง ISA 240)")

use_demo = st.toggle("ทดลองด้วยข้อมูลตัวอย่าง (900 เอกสาร)", value=False)

if use_demo:
    gl_df = demo_data()
    holidays = set(pd.to_datetime(jet.demo_holidays()["date"]).dt.date)
    company = company or "บริษัทตัวอย่าง จำกัด"
    period = period or "ม.ค.–ก.ย. 2026"
    gl_file = None
else:
    gl_file = st.file_uploader("อัปโหลดไฟล์ General Ledger (.xlsx / .csv)", type=["xlsx", "csv"])
    if gl_file is None:
        st.info("อัปโหลดไฟล์ GL เพื่อเริ่มทดสอบ หรือเปิด **ทดลองด้วยข้อมูลตัวอย่าง** ด้านบน")
        st.stop()

try:
    if not use_demo:
        gl_df = jet.read_gl(gl_file, gl_file.name)
        holidays = jet.read_holidays(hol_file, hol_file.name) if hol_file else set()
    params = jet.Params(
        approval_thresholds=[float(x) for x in thr_txt.replace(" ", "").split(",") if x],
        below_threshold_pct=below_pct / 100, work_start=work[0], work_end=work[1],
        period_end_days=int(period_end_days), close_days=int(close_days),
        round_unit=float(round_unit), round_min=float(round_min), rare_user_max=int(rare_user),
        large_amount=float(large_amt) or None,
        keywords=[k.strip() for k in kw_txt.split(",") if k.strip()], holidays=holidays,
    )
    with st.spinner("กำลังทดสอบ..."):
        res = jet.run_tests(gl_df, params)
        report = io.BytesIO()
        jet.write_report(res, report, company or "(ไม่ระบุ)", period or "(ไม่ระบุ)")
except jet.JEError as e:
    st.error(str(e))
    st.stop()
except ValueError:
    st.error("วงเงินอนุมัติต้องเป็นตัวเลขคั่นด้วยเครื่องหมายจุลภาค เช่น 50000, 100000")
    st.stop()

stt, ranking, findings = res["stats"], res["ranking"], res["findings"]
bi = res["benford_info"]

# --- Metrics ---
st.divider()
c = st.columns(5)
c[0].metric("เอกสารทั้งหมด", f"{stt['je_count']:,}", f"{stt['lines']:,} บรรทัด", delta_color="off")
c[1].metric("ยอดรวมเดบิต", f"{stt['total_debit']:,.0f}")
c[2].metric("เอกสารที่มีความเสี่ยง", f"{stt['flagged_je']:,}",
            f"{stt['flagged_je'] / max(stt['je_count'], 1):.1%}", delta_color="off")
c[3].metric("ความเสี่ยงสูง (High)", stt["high_je"])
c[4].metric("Benford", "ผิดปกติ" if bi.get("mad", 0) > 0.015 else ("ปกติ" if bi["performed"] else "-"))

if abs(stt["total_debit"] - stt["total_credit"]) > 0.01:
    st.warning(f"ยอดรวมเดบิต ({stt['total_debit']:,.2f}) ไม่เท่ากับเครดิต ({stt['total_credit']:,.2f})")
st.caption("⚠️ ก่อนสรุปผล ให้กระทบยอดรวมกับงบทดลอง (Trial Balance) เพื่อยืนยันว่าข้อมูลครบถ้วน")

st.download_button("⬇️ ดาวน์โหลดรายงาน Excel", report.getvalue(),
                   f"JE_Testing_Report_{pd.Timestamp.now():%Y%m%d}.xlsx", XLSX, type="primary")

tabs = st.tabs(["🎯 เอกสารเสี่ยงสูงสุด", "📋 สรุปการทดสอบ", "🔎 ข้อตรวจพบรายข้อ",
                "📊 Benford's Law", "🔢 เลขที่เอกสารขาด", "👤 ผู้บันทึก"])

with tabs[0]:
    if ranking.empty:
        st.success("ไม่พบเอกสารที่มีความเสี่ยง")
    else:
        lv = st.multiselect("ระดับความเสี่ยง", ["High", "Medium", "Low"], default=["High", "Medium"])
        v = ranking[ranking["risk_level"].isin(lv)].copy()
        v["risk_level"] = v["risk_level"].map(lambda x: f"{LEVEL_EMOJI[x]} {x}")
        v["posting_date"] = v["posting_date"].dt.strftime("%Y-%m-%d")
        v = v.drop(columns=["entry_date"]).rename(columns=jet.COL_TH)
        st.dataframe(v, hide_index=True, column_config={
            jet.COL_TH["amount"]: st.column_config.NumberColumn(format="%.2f")})
        st.caption("คะแนนความเสี่ยง = ผลรวมคะแนนของการทดสอบที่เอกสารนั้นติด · High ≥ 8, Medium 4–7, Low 1–3 "
                   "· แนะนำให้เลือกตรวจหลักฐานจากเอกสาร High และ Medium ก่อน")

with tabs[1]:
    rows = []
    for tid, (name, w, why) in jet.TESTS.items():
        status, note = res["status"][tid]
        n = int((findings["test_id"] == tid).sum()) if not findings.empty else 0
        rows.append({"รหัส": tid, "การทดสอบ": name, "คะแนน": w,
                     "ผล": (f"⚠️ {n}" if n else "✅ 0") if status == "ทดสอบแล้ว" else "⏭️ ไม่ได้ทดสอบ",
                     "หมายเหตุ": note or why})
    st.dataframe(pd.DataFrame(rows), hide_index=True)

with tabs[2]:
    if findings.empty:
        st.success("ไม่พบข้อตรวจพบ")
    else:
        opts = [f"{k} {v[0]}" for k, v in jet.TESTS.items() if (findings["test_id"] == k).any()]
        pick = st.selectbox("เลือกการทดสอบ", opts)
        tid = pick.split()[0]
        st.caption(jet.TESTS[tid][2])
        fv = findings[findings["test_id"] == tid].drop(columns=["test_id", "test_name", "severity"]).copy()
        fv["posting_date"] = fv["posting_date"].dt.strftime("%Y-%m-%d")
        st.dataframe(fv.rename(columns=jet.COL_TH), hide_index=True)

with tabs[3]:
    if not bi["performed"]:
        st.info(bi["conclusion"])
    else:
        st.write(f"**สรุป:** {bi['conclusion']}")
        st.write(f"MAD = {bi['mad']:.4f} · Chi-square = {bi['chi2']:.1f} (ค่าวิกฤต 15.507) · "
                 f"จำนวนรายการ {bi['n']:,}")
        chart = res["benford"].set_index("digit")[["actual_pct", "expected_pct"]]
        chart.columns = ["สัดส่วนจริง", "ตาม Benford"]
        st.bar_chart(chart, stack=False)
        st.caption("เกณฑ์ MAD (Nigrini): ≤0.006 สอดคล้องมาก · ≤0.012 ยอมรับได้ · ≤0.015 เล็กน้อย · "
                   ">0.015 ไม่สอดคล้อง")

with tabs[4]:
    g = res["gaps"]
    if g.empty:
        st.success("ไม่พบเลขที่เอกสารขาดหาย")
    else:
        st.write(f"พบเลขที่เอกสารขาด **{int(g['count_missing'].sum()):,}** เลข ใน {len(g)} ช่วง")
        st.dataframe(g, hide_index=True)

with tabs[5]:
    je = res["je"]
    by_user = je.groupby("created_by").agg(เอกสาร=("amount", "size"), ยอดรวม=("amount", "sum"))
    if not ranking.empty:
        r = ranking.groupby("created_by").agg(เอกสารเสี่ยง=("je_number", "size"),
                                                คะแนนรวม=("risk_score", "sum"))
        by_user = by_user.join(r).fillna(0)
        by_user["สัดส่วนเสี่ยง"] = (by_user["เอกสารเสี่ยง"] / by_user["เอกสาร"] * 100).round(1)
    st.dataframe(by_user.sort_values(by_user.columns[-1], ascending=False), column_config={
        "ยอดรวม": st.column_config.NumberColumn(format="%.2f"),
        "สัดส่วนเสี่ยง": st.column_config.ProgressColumn(format="%.0f%%", min_value=0, max_value=100)})
    st.caption("ผู้ที่มีสัดส่วนรายการเสี่ยงสูงผิดปกติ ควรได้รับความสนใจเป็นพิเศษ")

ui.footer()
