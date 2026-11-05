"""
AI-assisted Policy Review — ตรวจว่านโยบาย/ระเบียบขององค์กรครอบคลุมข้อกำหนดตามมาตรฐานหรือไม่
================================================================================================
2 โหมด
  1. Keyword (ออฟไลน์ ฟรี): หาคำสำคัญภาษาไทย/อังกฤษของแต่ละข้อกำหนด + ตรวจว่าระบุความถี่/ระยะเวลาหรือไม่
  2. AI (Claude API): ให้ AI อ่านนโยบายทั้งฉบับแล้วประเมินทีละข้อ พร้อมอ้างข้อความที่เป็นหลักฐาน
ผลลัพธ์ใช้เป็นร่างการสอบทานเอกสาร ผู้ตรวจต้องทบทวนก่อนสรุป
"""

from __future__ import annotations

import io
import json
import os
import re
from dataclasses import dataclass

import pandas as pd

from .common import AuditError, read_text, write_df

DEFAULT_MODEL = "claude-sonnet-5-5"

# (rid, หัวข้อ, ข้อกำหนด, อ้างอิง, คำสำคัญ, ต้องระบุความถี่/ระยะเวลาหรือไม่)
REQUIREMENTS = {
    "Access Control Policy": [
        ("AC-01", "หลักการให้สิทธิ์", "ให้สิทธิ์ตามความจำเป็นในการปฏิบัติงาน (least privilege / need-to-know)",
         "ISO/IEC 27001:2022 A.5.15", ["least privilege", "need-to-know", "need to know", "ตามความจำเป็น", "เท่าที่จำเป็น", "ตามหน้าที่"], False),
        ("AC-02", "การขอและอนุมัติสิทธิ์", "การขอสิทธิ์ต้องมีแบบคำขอและได้รับอนุมัติจากผู้บังคับบัญชา/เจ้าของระบบก่อน",
         "ISO/IEC 27001:2022 A.5.16, A.5.18", ["request", "approv", "ขอสิทธิ์", "คำขอ", "อนุมัติ", "เจ้าของระบบ"], False),
        ("AC-03", "การยกเลิกสิทธิ์", "ยกเลิกสิทธิ์เมื่อพนักงานพ้นสภาพหรือย้ายงานภายในระยะเวลาที่กำหนด",
         "ISO/IEC 27001:2022 A.5.18", ["terminat", "resign", "revoke", "remov", "พ้นสภาพ", "ลาออก", "ยกเลิกสิทธิ์", "เพิกถอน", "โยกย้าย"], True),
        ("AC-04", "การทบทวนสิทธิ์", "ทบทวนสิทธิ์ผู้ใช้เป็นระยะ โดยระบุความถี่",
         "ISO/IEC 27001:2022 A.5.18", ["access review", "review of access", "recertif", "ทบทวนสิทธิ์", "สอบทานสิทธิ์"], True),
        ("AC-05", "สิทธิ์ระดับสูง", "ควบคุมการให้และการใช้สิทธิ์ระดับสูง (privileged access) และบันทึกการใช้งาน",
         "ISO/IEC 27001:2022 A.8.2", ["privileged", "administrator", "admin", "สิทธิ์ระดับสูง", "ผู้ดูแลระบบ", "สิทธิ์พิเศษ"], False),
        ("AC-06", "การยืนยันตัวตน", "กำหนดการยืนยันตัวตน รวมถึง MFA สำหรับการเข้าถึงระยะไกลหรือสิทธิ์สูง",
         "ISO/IEC 27001:2022 A.8.5", ["multi-factor", "mfa", "two-factor", "2fa", "ยืนยันตัวตนหลายปัจจัย", "หลายปัจจัย", "otp"], False),
        ("AC-07", "บัญชีใช้ร่วมกัน", "ห้ามใช้บัญชีร่วมกัน หรือกำหนดเงื่อนไขและผู้รับผิดชอบหากจำเป็น",
         "ISO/IEC 27001:2022 A.5.16", ["shared account", "generic account", "บัญชีร่วม", "ใช้ร่วมกัน", "บัญชีกลาง"], False),
    ],
    "Password / Authentication": [
        ("PW-01", "ความยาวรหัสผ่าน", "กำหนดความยาวรหัสผ่านขั้นต่ำเป็นตัวเลขชัดเจน",
         "ISO/IEC 27001:2022 A.5.17", ["minimum length", "at least", "characters", "ความยาว", "ตัวอักษร", "ไม่น้อยกว่า"], True),
        ("PW-02", "ความซับซ้อน", "กำหนดความซับซ้อนหรือการใช้ passphrase",
         "ISO/IEC 27001:2022 A.5.17", ["complex", "passphrase", "uppercase", "special character", "ซับซ้อน", "ตัวพิมพ์ใหญ่", "อักขระพิเศษ"], False),
        ("PW-03", "การล็อกบัญชี", "ล็อกบัญชีเมื่อใส่รหัสผ่านผิดเกินจำนวนครั้งที่กำหนด",
         "ISO/IEC 27001:2022 A.8.5", ["lockout", "locked", "failed attempt", "ล็อก", "ระงับบัญชี", "ผิดเกิน"], True),
        ("PW-04", "การเปลี่ยนรหัสผ่าน", "กำหนดการเปลี่ยนรหัสผ่านเมื่อครบอายุหรือเมื่อสงสัยว่ารั่วไหล",
         "ISO/IEC 27001:2022 A.5.17", ["change password", "expire", "compromise", "เปลี่ยนรหัสผ่าน", "หมดอายุ", "รั่วไหล"], True),
        ("PW-05", "การเก็บรักษารหัสผ่าน", "ห้ามเปิดเผย/จดรหัสผ่าน และระบบต้องเก็บรหัสผ่านแบบ hash/เข้ารหัส",
         "ISO/IEC 27001:2022 A.5.17, A.8.24", ["do not share", "hash", "encrypt", "ห้ามเปิดเผย", "ห้ามบอก", "เข้ารหัส", "เก็บเป็นความลับ"], False),
        ("PW-06", "รหัสผ่านเริ่มต้น", "บังคับเปลี่ยนรหัสผ่านเริ่มต้น/ชั่วคราวในการเข้าใช้ครั้งแรก",
         "ISO/IEC 27001:2022 A.5.17", ["default password", "temporary password", "first login", "รหัสผ่านเริ่มต้น", "รหัสผ่านชั่วคราว", "ครั้งแรก"], False),
    ],
    "Incident Management": [
        ("IM-01", "นิยามและการจัดระดับ", "นิยามเหตุการณ์ความมั่นคงปลอดภัยและเกณฑ์จัดระดับความรุนแรง",
         "ISO/IEC 27001:2022 A.5.25", ["severity", "classif", "priority", "ระดับความรุนแรง", "จัดระดับ", "นิยาม"], False),
        ("IM-02", "การรายงานเหตุ", "หน้าที่และช่องทางการรายงานเหตุของพนักงาน",
         "ISO/IEC 27001:2022 A.6.8", ["report", "hotline", "รายงานเหตุ", "แจ้งเหตุ", "ช่องทาง"], True),
        ("IM-03", "ทีมและบทบาท", "กำหนดทีมรับมือเหตุการณ์และบทบาทหน้าที่",
         "ISO/IEC 27001:2022 A.5.24", ["incident response team", "csirt", "roles", "ทีมรับมือ", "ผู้รับผิดชอบ", "บทบาท"], False),
        ("IM-04", "ขั้นตอนรับมือ", "ขั้นตอนการควบคุม กำจัด และกู้คืน",
         "ISO/IEC 27001:2022 A.5.26", ["contain", "eradicat", "recover", "ควบคุมความเสียหาย", "จำกัดความเสียหาย", "กู้คืน"], False),
        ("IM-05", "การเก็บหลักฐาน", "การเก็บรักษาหลักฐานดิจิทัล",
         "ISO/IEC 27001:2022 A.5.28", ["evidence", "forensic", "chain of custody", "หลักฐาน", "พยานหลักฐาน"], False),
        ("IM-06", "การแจ้งหน่วยงานกำกับ", "การแจ้งเหตุละเมิดข้อมูลส่วนบุคคลต่อ สคส. ภายใน 72 ชั่วโมง และหน่วยงานกำกับอื่น",
         "พ.ร.บ.คุ้มครองข้อมูลส่วนบุคคล มาตรา 37(4)", ["72", "regulator", "pdpc", "สำนักงานคณะกรรมการ", "สคส", "หน่วยงานกำกับ"], True),
        ("IM-07", "การเรียนรู้และทดสอบ", "ทบทวนบทเรียนหลังเหตุการณ์และซ้อมแผน",
         "ISO/IEC 27001:2022 A.5.27", ["lessons learned", "post-incident", "exercise", "drill", "บทเรียน", "ซ้อม", "ทดสอบแผน"], True),
    ],
    "Backup": [
        ("BK-01", "ขอบเขตและความถี่", "กำหนดข้อมูล/ระบบที่ต้องสำรองและความถี่",
         "ISO/IEC 27001:2022 A.8.13", ["daily", "weekly", "frequency", "ทุกวัน", "รายวัน", "ความถี่", "สำรองข้อมูล"], True),
        ("BK-02", "ระยะเวลาเก็บรักษา", "กำหนดระยะเวลาเก็บรักษาข้อมูลสำรอง",
         "ISO/IEC 27001:2022 A.8.13", ["retention", "retain", "ระยะเวลาเก็บ", "เก็บรักษา"], True),
        ("BK-03", "สำเนานอกสถานที่", "เก็บสำเนานอกสถานที่หรือแบบ offline/immutable",
         "ISO/IEC 27001:2022 A.8.13", ["offsite", "off-site", "offline", "immutable", "air-gap", "นอกสถานที่", "ต่างสถานที่"], False),
        ("BK-04", "การเข้ารหัส", "เข้ารหัสข้อมูลสำรอง",
         "ISO/IEC 27001:2022 A.8.13, A.8.24", ["encrypt", "เข้ารหัส"], False),
        ("BK-05", "การทดสอบกู้คืน", "ทดสอบการกู้คืนข้อมูลสำรองเป็นระยะ",
         "ISO/IEC 27001:2022 A.8.13", ["restore test", "restoration", "test restore", "ทดสอบการกู้คืน", "ทดสอบกู้คืน"], True),
        ("BK-06", "การติดตามผล", "ติดตามผลการสำรองข้อมูลและจัดการกรณีล้มเหลว",
         "ISO/IEC 27001:2022 A.8.13", ["monitor", "failed backup", "alert", "ตรวจสอบผล", "ล้มเหลว", "แจ้งเตือน"], False),
    ],
    "Change Management": [
        ("CM-01", "การขอเปลี่ยนแปลง", "ทุกการเปลี่ยนแปลงต้องมีคำขอและบันทึก",
         "ISO/IEC 27001:2022 A.8.32", ["change request", "rfc", "ticket", "คำขอเปลี่ยนแปลง", "แบบคำขอ"], False),
        ("CM-02", "การประเมินผลกระทบ", "ประเมินความเสี่ยงและผลกระทบก่อนเปลี่ยนแปลง",
         "ISO/IEC 27001:2022 A.8.32", ["impact", "risk assessment", "ผลกระทบ", "ประเมินความเสี่ยง"], False),
        ("CM-03", "การอนุมัติ", "อนุมัติโดยผู้มีอำนาจ/CAB ก่อนนำขึ้นระบบจริง",
         "ISO/IEC 27001:2022 A.8.32", ["approv", "cab", "อนุมัติ", "คณะกรรมการ"], False),
        ("CM-04", "การทดสอบ", "ทดสอบและ UAT ก่อนนำขึ้นระบบจริง",
         "ISO/IEC 27001:2022 A.8.29, A.8.32", ["test", "uat", "ทดสอบ", "ยอมรับผล"], False),
        ("CM-05", "การแยกสภาพแวดล้อมและหน้าที่", "แยกสภาพแวดล้อม dev/test/prod และผู้พัฒนาไม่นำขึ้นระบบจริงเอง",
         "ISO/IEC 27001:2022 A.8.31, A.5.3", ["segregat", "separation", "production", "แยก", "ผู้พัฒนา", "ระบบจริง"], False),
        ("CM-06", "การเปลี่ยนแปลงฉุกเฉิน", "ขั้นตอนการเปลี่ยนแปลงฉุกเฉินและการอนุมัติย้อนหลัง",
         "ISO/IEC 27001:2022 A.8.32", ["emergency", "ฉุกเฉิน", "เร่งด่วน"], True),
        ("CM-07", "แผนย้อนกลับ", "มีแผนย้อนกลับ (rollback) หากการเปลี่ยนแปลงล้มเหลว",
         "ISO/IEC 27001:2022 A.8.32", ["rollback", "roll back", "back-out", "fallback", "ย้อนกลับ", "คืนค่า"], False),
    ],
}

FREQ_RX = re.compile(r"(\d+\s*(วัน|ชั่วโมง|ชม|เดือน|ปี|ครั้ง|ตัวอักษร|นาที|days?|hours?|months?|years?|times|characters|minutes)"
                     r"|ทุกวัน|รายวัน|รายสัปดาห์|รายเดือน|รายไตรมาส|ทุกไตรมาส|ประจำปี|ปีละ|ทุกปี|ทุกเดือน|ภายใน|ไม่เกิน|ไม่น้อยกว่า"
                     r"|annually|quarterly|monthly|weekly|daily|within|at least)", re.I)


def extract_text(src, name: str) -> str:
    n = name.lower()
    data = src.read() if hasattr(src, "read") else open(src, "rb").read()
    if hasattr(src, "seek"):
        src.seek(0)
    if n.endswith(".docx"):
        import docx
        d = docx.Document(io.BytesIO(data))
        parts = [p.text for p in d.paragraphs]
        for t in d.tables:
            for row in t.rows:
                parts.append(" | ".join(c.text for c in row.cells))
        text = "\n".join(parts)
    elif n.endswith(".pdf"):
        from pypdf import PdfReader
        text = "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(data)).pages)
        if len(text.strip()) < 50:
            raise AuditError(f"{name}: ไม่พบข้อความใน PDF (อาจเป็นไฟล์สแกน) — กรุณาใช้ไฟล์ที่ค้นหาข้อความได้")
    elif n.endswith((".txt", ".md")):
        text = read_text(io.BytesIO(data), name)
    else:
        raise AuditError(f"{name}: รองรับ .docx, .pdf, .txt, .md")
    return text


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?。])\s+|\n+|\s{2,}", text)
    return [p.strip() for p in parts if len(p.strip()) > 8]


@dataclass
class Result:
    table: pd.DataFrame
    summary: pd.DataFrame
    mode: str
    coverage: float


def review_keywords(text: str, areas: list[str]) -> Result:
    sents = _sentences(text)
    low = [s.lower() for s in sents]
    rows = []
    for area in areas:
        for rid, topic, req, ref, kws, needs_freq in REQUIREMENTS[area]:
            hits = [k for k in kws if any(k.lower() in s for s in low)]
            ev_idx = [i for i, s in enumerate(low) if any(k.lower() in s for k in kws)]
            # หลักฐาน: ประโยคที่มีคำสำคัญมากที่สุด โดยเลี่ยงหัวข้อสั้น ๆ
            ranked = sorted(ev_idx, key=lambda i: (len(sents[i]) >= 25, sum(k.lower() in low[i] for k in kws),
                                                   len(sents[i])), reverse=True)
            evidence = sents[ranked[0]][:220] if ranked else ""
            has_freq = any(FREQ_RX.search(sents[i]) for i in ev_idx)
            specific = any(len(k) >= 6 for k in hits)
            if len(hits) >= 2 or (hits and len(kws) <= 2) or (specific and (not needs_freq or has_freq)
                                                              and any(len(sents[i]) >= 25 for i in ev_idx)):
                status = "Covered"
            elif hits:
                status = "Partial"
            else:
                status = "Missing"
            gap = ""
            if status == "Covered" and needs_freq and not has_freq:
                status, gap = "Partial", "กล่าวถึงแต่ไม่ระบุความถี่/ระยะเวลา/ตัวเลขที่วัดผลได้"
            elif status == "Partial":
                gap = "กล่าวถึงบางส่วน ควรระบุให้ชัดเจน"
            elif status == "Missing":
                gap = "ไม่พบข้อกำหนดนี้ในนโยบาย"
            rows.append({"area": area, "rid": rid, "topic": topic, "requirement": req, "reference": ref,
                         "status": status, "evidence": evidence, "gap": gap,
                         "recommendation": "" if status == "Covered" else f"เพิ่มข้อกำหนด: {req}",
                         "keywords_found": ", ".join(hits)})
    return _finish(pd.DataFrame(rows), "Keyword (ออฟไลน์)")


def _finish(t: pd.DataFrame, mode: str) -> Result:
    sc = t["status"].map({"Covered": 1, "Partial": 0.5, "Missing": 0}).fillna(0)
    t = t.assign(_s=sc)
    summary = t.groupby("area").agg(requirements=("rid", "size"), covered=("status", lambda s: int((s == "Covered").sum())),
                                    partial=("status", lambda s: int((s == "Partial").sum())),
                                    missing=("status", lambda s: int((s == "Missing").sum())),
                                    coverage_pct=("_s", lambda s: round(s.mean() * 100, 0))).reset_index()
    return Result(t.drop(columns="_s"), summary, mode, round(float(sc.mean() * 100), 0))


PROMPT = """คุณคือผู้ตรวจสอบด้านเทคโนโลยีสารสนเทศ (IT Auditor) ที่มีประสบการณ์ หน้าที่ของคุณคือสอบทานเอกสารนโยบายขององค์กร
ว่าครอบคลุมข้อกำหนดแต่ละข้อหรือไม่

สำหรับแต่ละข้อกำหนด ให้ประเมิน:
- status: "Covered" (ครอบคลุมชัดเจนและวัดผลได้), "Partial" (กล่าวถึงแต่ไม่ครบ หรือขาดความถี่/ผู้รับผิดชอบ/ตัวเลข), "Missing" (ไม่พบ)
- evidence: ข้อความสั้น ๆ จากนโยบายที่เป็นหลักฐาน (ไม่เกิน 30 คำ คัดลอกตามต้นฉบับ) หรือว่างถ้าไม่พบ
- gap: ช่องว่างที่พบ เป็นภาษาไทย 1 ประโยค
- recommendation: ข้อเสนอแนะการปรับปรุงนโยบาย เป็นภาษาไทย 1 ประโยค

ตอบเป็น JSON array เท่านั้น ไม่มีข้อความอื่น รูปแบบ:
[{"rid": "...", "status": "...", "evidence": "...", "gap": "...", "recommendation": "..."}]

<requirements>
{requirements}
</requirements>

<policy_document>
{policy}
</policy_document>"""


def review_ai(text: str, areas: list[str], api_key: str | None = None, model: str = DEFAULT_MODEL,
              max_chars: int = 180_000) -> Result:
    try:
        import anthropic
    except ImportError as e:
        raise AuditError("ยังไม่ได้ติดตั้งไลบรารี anthropic — รัน: pip install anthropic") from e
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise AuditError("กรุณาใส่ Claude API key (สร้างได้ที่ Claude Console) หรือใช้โหมด Keyword")
    reqs = [{"rid": r[0], "area": a, "topic": r[1], "requirement": r[2], "reference": r[3]}
            for a in areas for r in REQUIREMENTS[a]]
    prompt = PROMPT.replace("{requirements}", json.dumps(reqs, ensure_ascii=False, indent=1)) \
                   .replace("{policy}", text[:max_chars])
    try:
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(model=model, max_tokens=8000, messages=[{"role": "user", "content": prompt}])
    except Exception as e:  # noqa: BLE001
        raise AuditError(f"เรียก Claude API ไม่สำเร็จ: {e}") from e
    raw = "".join(getattr(b, "text", "") for b in msg.content)
    m = re.search(r"\[.*\]", raw, re.S)
    if not m:
        raise AuditError("AI ตอบกลับในรูปแบบที่อ่านไม่ได้ ลองใหม่อีกครั้ง หรือใช้โหมด Keyword")
    try:
        items = {i["rid"]: i for i in json.loads(m.group())}
    except json.JSONDecodeError as e:
        raise AuditError(f"อ่านผลจาก AI ไม่ได้: {e}") from e
    rows = []
    for r in reqs:
        i = items.get(r["rid"], {})
        st = i.get("status", "Missing")
        rows.append({"area": r["area"], "rid": r["rid"], "topic": r["topic"], "requirement": r["requirement"],
                     "reference": r["reference"], "status": st if st in ("Covered", "Partial", "Missing") else "Missing",
                     "evidence": i.get("evidence", ""), "gap": i.get("gap", ""),
                     "recommendation": i.get("recommendation", ""), "keywords_found": ""})
    return _finish(pd.DataFrame(rows), f"AI ({model})")


COL_TH = {"area": "นโยบาย", "rid": "รหัส", "topic": "หัวข้อ", "requirement": "ข้อกำหนด", "reference": "อ้างอิง",
          "status": "ผล", "evidence": "ข้อความที่เป็นหลักฐาน", "gap": "ช่องว่าง", "recommendation": "ข้อเสนอแนะ",
          "keywords_found": "คำสำคัญที่พบ", "requirements": "จำนวนข้อกำหนด", "covered": "ครอบคลุม", "partial": "บางส่วน",
          "missing": "ไม่พบ", "coverage_pct": "% ครอบคลุม"}


def write_report(res: Result, out, doc_name: str, org: str = "(ไม่ระบุ)"):
    from datetime import datetime
    with pd.ExcelWriter(out, engine="openpyxl") as xw:
        info = pd.DataFrame([("องค์กร", org), ("เอกสารที่สอบทาน", doc_name), ("วิธีการ", res.mode),
                             ("ความครอบคลุมโดยรวม", f"{res.coverage:.0f}%"),
                             ("วันที่ออกรายงาน", datetime.now().strftime("%Y-%m-%d %H:%M")),
                             ("หมายเหตุ", "ผลนี้เป็นร่างการสอบทาน ผู้ตรวจสอบต้องทบทวนก่อนสรุป")],
                            columns=["รายการ", "ค่า"])
        write_df(xw, info, "Summary", widths=[26, 70])
        write_df(xw, res.summary, "Coverage by Policy", COL_TH)
        gaps = res.table[res.table["status"] != "Covered"]
        write_df(xw, gaps if len(gaps) else pd.DataFrame({"ผล": ["ครอบคลุมทุกข้อ"]}), "Gaps", COL_TH,
                 widths=[18, 8, 18, 40, 22, 10, 50, 40, 45, 20])
        write_df(xw, res.table, "All Requirements", COL_TH, widths=[18, 8, 18, 40, 22, 10, 50, 40, 45, 20])


DEMO_POLICY = """นโยบายการควบคุมการเข้าถึงระบบสารสนเทศ บริษัท ตัวอย่าง จำกัด (ฉบับที่ 2)

1. วัตถุประสงค์
เพื่อกำหนดหลักเกณฑ์การเข้าถึงระบบสารสนเทศให้มีความมั่นคงปลอดภัย

2. หลักการให้สิทธิ์
2.1 การให้สิทธิ์เข้าถึงระบบให้เป็นไปตามหน้าที่ความรับผิดชอบ และเท่าที่จำเป็นต่อการปฏิบัติงานเท่านั้น
2.2 ผู้ใช้งานต้องยื่นแบบคำขอสิทธิ์ และได้รับอนุมัติจากผู้บังคับบัญชาและเจ้าของระบบก่อนดำเนินการ

3. การยกเลิกสิทธิ์
3.1 เมื่อพนักงานลาออกหรือพ้นสภาพ ฝ่ายบุคคลต้องแจ้งฝ่ายเทคโนโลยีสารสนเทศเพื่อยกเลิกสิทธิ์

4. การทบทวนสิทธิ์
4.1 เจ้าของระบบต้องทบทวนสิทธิ์ผู้ใช้งานอย่างน้อยปีละ 1 ครั้ง

5. สิทธิ์ระดับสูง
5.1 บัญชีผู้ดูแลระบบต้องได้รับอนุมัติจากผู้อำนวยการฝ่ายเทคโนโลยีสารสนเทศ และบันทึกการใช้งานทุกครั้ง

6. รหัสผ่าน
6.1 รหัสผ่านต้องมีความยาวไม่น้อยกว่า 8 ตัวอักษร และมีความซับซ้อน ประกอบด้วยตัวพิมพ์ใหญ่ ตัวเลข และอักขระพิเศษ
6.2 ผู้ใช้งานต้องเก็บรหัสผ่านเป็นความลับ ห้ามเปิดเผยรหัสผ่านแก่ผู้อื่น
6.3 ผู้ใช้งานต้องเปลี่ยนรหัสผ่านทุก 90 วัน

7. การสำรองข้อมูล
7.1 ฝ่ายเทคโนโลยีสารสนเทศต้องสำรองข้อมูลระบบงานสำคัญทุกวัน และเก็บรักษาข้อมูลสำรองไว้ 1 ปี
7.2 ข้อมูลสำรองต้องเก็บไว้นอกสถานที่
"""
