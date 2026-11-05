# คู่มือ: ติดตั้ง ทดลอง ขึ้น GitHub และเปิดเว็บสาธารณะ (ฟรี)

ใช้เวลารวมประมาณ 45–60 นาที ไม่ต้องใช้คำสั่ง git

---

## ส่วนที่ 1 รันในเครื่องตัวเอง

1. แตกไฟล์ `it-audit-toolkit.zip` ไปที่ `C:\it-audit-toolkit` (ข้างในต้องเห็น `Home.py`)
2. เปิด cmd แล้วพิมพ์ทีละบรรทัด
   ```
   cd C:\it-audit-toolkit
   pip install -r requirements.txt
   python -m streamlit run Home.py
   ```
3. เบราว์เซอร์เปิดหน้า `http://localhost:8501` ให้เอง เมนูเครื่องมือทั้ง 13 ตัวอยู่แถบซ้าย
4. ทุกหน้ามีสวิตช์ **ทดลองด้วยข้อมูลตัวอย่าง** ลองเปิดดูทีละหน้า
5. ปิดโปรแกรม: กด `Ctrl + C` ในหน้าต่าง cmd

**รันชุดทดสอบ (ใช้โชว์ตอนสัมภาษณ์ได้):**
```
python -m pytest -q
```
ต้องขึ้น `19 passed`

## ส่วนที่ 2 ใส่ข้อมูลของคุณ (ทำครั้งเดียว)

| ไฟล์ | แก้อะไร |
|---|---|
| `audit_tools/config.py` | ชื่อ ตำแหน่ง อีเมล ลิงก์ LinkedIn / GitHub (แสดงทุกหน้า) |
| `README.md` | `[Your Name]`, ลิงก์ LinkedIn, อีเมล, ลิงก์ Live demo |
| `LICENSE` | `[YOUR NAME]`, `[YOUR EMAIL]` |

**ภาพหน้าจอสำหรับ README:** เปิดหน้า Home แล้วกด Windows + Shift + S บันทึกเป็น
`docs/screenshot_home.png` (ถ้ามีเวลา ถ่ายหน้า JE Testing และ SoD เพิ่มด้วย แล้วใส่ใน README)

## ส่วนที่ 3 ขึ้น GitHub

1. สมัคร https://github.com (ใช้ชื่อผู้ใช้ที่เป็นมืออาชีพ เช่น ชื่อ-นามสกุล)
2. มุมขวาบน **+** → **New repository**
   - Repository name: `it-audit-toolkit`
   - Description: `13 audit analytics tools for IT auditors: ITGC, IAM, Cloud, JE testing, PDPA, AI governance`
   - เลือก **Public** · **ไม่ต้อง** ติ๊ก Add README
3. กด **Create repository** → กดลิงก์ **uploading an existing file**
4. ลากไฟล์และโฟลเดอร์ทั้งหมดใน `C:\it-audit-toolkit` ลงไป (GitHub รับได้ครั้งละ 100 ไฟล์ ถ้าเกินให้อัปโหลด 2 รอบ)
5. พิมพ์ข้อความ `Initial release v2.0` แล้วกด **Commit changes**

**โฟลเดอร์ที่ขึ้นต้นด้วยจุด (`.streamlit`) อาจไม่ติดไป:** ใน repo กด **Add file → Create new file**
ตั้งชื่อ `.streamlit/config.toml` แล้วคัดลอกเนื้อหาจากไฟล์ในเครื่องมาวาง

**ตกแต่งหน้า repo (สำคัญต่อความประทับใจแรก):**
- กดรูปฟันเฟืองข้าง About → ใส่ Website (ลิงก์ Live demo) และ Topics:
  `it-audit` `itgc` `internal-audit` `python` `streamlit` `pdpa` `iso27001` `aws-security` `data-analytics` `ai-governance`
- ที่หน้าโปรไฟล์ GitHub → **Customize your pins** → ปักหมุด repo นี้

⚠️ **ห้ามอัปโหลดข้อมูลจริงของบริษัทใดขึ้น GitHub** ใช้เฉพาะ `sample_data`

## ส่วนที่ 4 เปิดเว็บสาธารณะด้วย Streamlit Community Cloud

1. ไปที่ https://share.streamlit.io → **Continue with GitHub**
2. **Create app** → **Deploy a public app from GitHub**
   - Repository: `ชื่อคุณ/it-audit-toolkit` · Branch: `main`
   - Main file path: **`Home.py`**
   - App URL: เช่น `it-audit-toolkit-ชื่อคุณ`
3. กด **Deploy** รอ 3–5 นาที
4. นำลิงก์ที่ได้ไปใส่ใน README และ About ของ repo

**เปิดโหมด AI ของ AI Policy Review บนเว็บ (ไม่บังคับ):** ใน Streamlit Cloud ไปที่ App → Settings → Secrets แล้วใส่
```
ANTHROPIC_API_KEY = "ใส่ key ของคุณ"
```
⚠️ ถ้าใส่ key ไว้บนเว็บสาธารณะ ใครก็ใช้โหมด AI ได้และค่าใช้จ่ายเป็นของคุณ แนะนำให้ไม่ใส่ แล้วให้ผู้ใช้กรอก key เองในหน้าเว็บ
หรือใช้โหมด AI เฉพาะตอนรันในเครื่องตัวเองเท่านั้น

**หมายเหตุ**
- แอปฟรีจะหลับเมื่อไม่มีคนใช้ ผู้เข้าชมคนแรกต้องกดปุ่มปลุกและรอประมาณ 1 นาที
  → ก่อนส่งลิงก์ให้ HR หรือก่อนสัมภาษณ์ ให้เปิดลิงก์เองก่อน 1 ครั้ง
- เว็บสาธารณะใช้สาธิตด้วยข้อมูลตัวอย่าง ข้อมูลจริงของลูกค้าให้รันในเครื่อง (ส่วนที่ 1)

## ส่วนที่ 5 ถ้าเจอปัญหา

| อาการ | วิธีแก้ |
|---|---|
| `'streamlit' is not recognized` | ใช้ `python -m streamlit run Home.py` |
| `ModuleNotFoundError: audit_tools` | ต้อง `cd` เข้าโฟลเดอร์ที่มี `Home.py` ก่อนรัน |
| Deploy แล้ว error เรื่อง package | ตรวจว่า `requirements.txt` อยู่ระดับเดียวกับ `Home.py` |
| หน้าเว็บแสดงภาษาไทยเพี้ยน | เปิดไฟล์ด้วย Excel โดยตรง หรือใช้ไฟล์ .xlsx แทน .csv |
