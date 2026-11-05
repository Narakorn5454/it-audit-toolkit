import pandas as pd
import streamlit as st

from audit_tools import assessment as A
from audit_tools import assessment_ui


def profile():
    st.subheader("1) ความเสี่ยงตั้งต้นของผู้ให้บริการ (Inherent risk)")
    st.caption("ประเมินจากลักษณะบริการ ก่อนพิจารณาการควบคุมของผู้ให้บริการ")
    cols = st.columns(len(A.VENDOR_PROFILE))
    picks, rows = {}, []
    for c, (k, (label, opts)) in zip(cols, A.VENDOR_PROFILE.items()):
        choice = c.selectbox(label, [o for o, _ in opts], index=len(opts) - 1, key=f"vp_{k}")
        picks[k] = dict(opts)[choice]
        rows.append({"ปัจจัย": label, "คำตอบ": choice, "คะแนน": picks[k]})
    tier, pts = A.inherent_tier(picks)
    st.session_state["vendor_tier"] = tier
    st.info(f"ความเสี่ยงตั้งต้น: **{tier}** ({pts} คะแนน) — จากนั้นประเมินการควบคุมด้านล่างเพื่อหาความเสี่ยงคงเหลือ")
    st.subheader("2) ประเมินการควบคุมของผู้ให้บริการ")
    return ([("ความเสี่ยงตั้งต้น (Inherent)", f"{tier} ({pts} คะแนน)")],
            {"Inherent Risk Profile": pd.DataFrame(rows)}, [("Inherent", tier)])


def residual(res):
    tier = st.session_state.get("vendor_tier", "High")
    rr = A.residual_risk(tier, res["overall"])
    st.subheader("3) ความเสี่ยงคงเหลือ (Residual risk)")
    c = st.columns(3)
    c[0].metric("ความเสี่ยงตั้งต้น", tier)
    c[1].metric("คะแนนการควบคุม", f"{res['overall']:.0f}%")
    c[2].metric("ความเสี่ยงคงเหลือ", rr)
    st.write(f"**ความถี่ในการทบทวนที่แนะนำ:** {A.REVIEW_FREQ[rr]}")
    with st.expander("ตารางเกณฑ์ความเสี่ยงคงเหลือ"):
        st.dataframe(pd.DataFrame(A.RESIDUAL, index=["คะแนน ≥80", "60–79", "40–59", "<40"]).T
                     .rename_axis("ตั้งต้น \\ การควบคุม").reset_index(), hide_index=True)
    st.divider()
    return [("ความเสี่ยงคงเหลือ (Residual)", rr), ("ความถี่ในการทบทวนที่แนะนำ", A.REVIEW_FREQ[rr])]


assessment_ui.render(
    "vendor", "Third-party / Vendor Risk Assessment", "🤝",
    "ประเมินความเสี่ยงผู้ให้บริการภายนอก: จัดระดับความเสี่ยงตั้งต้นจากลักษณะบริการ แล้วประเมินการควบคุมของผู้ให้บริการ "
    "เพื่อหาความเสี่ยงคงเหลือและความถี่ในการทบทวน ส่งแบบสอบถาม Excel ให้ผู้ให้บริการกรอกแล้วอัปโหลดกลับได้",
    "ISO/IEC 27001:2022 A.5.19–A.5.23 (Supplier relationships, Cloud services) · พ.ร.บ.คุ้มครองข้อมูลส่วนบุคคล มาตรา 40",
    profile=profile, after=residual)
