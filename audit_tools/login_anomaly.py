"""
Login Anomaly Detection — วิเคราะห์ log การเข้าสู่ระบบเพื่อหาพฤติกรรมผิดปกติ
===========================================================================
Input
  1. auth log : timestamp, username, result (Success/Failure), source_ip, country, application
     รองรับ: Windows Security log (Event ID 4624/4625), Microsoft Entra ID sign-in log, log ทั่วไป
  2. user list (ไม่บังคับ): username, status (Active/Disabled/Terminated), privileged (Y/N)
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .common import ensure, make_findings, standardize_columns, parse_dates, read_table, require, sort_findings, write_findings_report, yes

CHECKS = {
    "LOG-01": ("พยายามเข้าสู่ระบบผิดซ้ำหลายครั้งในเวลาสั้น (Brute force)", "High",
               "ตรวจสอบแหล่งที่มา ยืนยันกับเจ้าของบัญชี และตรวจว่ามีการล็อกบัญชีตามนโยบาย",
               "ผู้ไม่หวังดีพยายามเดารหัสผ่านของบัญชีเป้าหมาย"),
    "LOG-02": ("เข้าสู่ระบบสำเร็จหลังจากผิดหลายครั้ง", "High",
               "ถือเป็นเหตุการณ์ที่ต้องสอบสวน: บังคับเปลี่ยนรหัสผ่าน ตรวจกิจกรรมหลังเข้าระบบ",
               "อาจเดารหัสผ่านสำเร็จ (บัญชีอาจถูกยึด)"),
    "LOG-03": ("IP เดียวพยายามเข้าหลายบัญชี (Password spraying)", "High",
               "บล็อก IP ต้นทาง และตรวจว่าบัญชีใดถูกเข้าสำเร็จจาก IP นี้",
               "ลองรหัสผ่านยอดนิยมกับหลายบัญชีเพื่อหลบการล็อกบัญชี"),
    "LOG-04": ("เข้าสู่ระบบจากต่างประเทศในเวลาที่เดินทางไม่ทัน (Impossible travel)", "High",
               "ยืนยันกับเจ้าของบัญชี และพิจารณาใช้ Conditional Access / MFA",
               "บัญชีอาจถูกใช้โดยบุคคลอื่นพร้อมกัน"),
    "LOG-05": ("เข้าสู่ระบบนอกเวลาทำการ", "Low",
               "ทบทวนความจำเป็น โดยเฉพาะบัญชีสิทธิ์สูง",
               "การใช้งานนอกเวลามีผู้กำกับดูแลน้อย"),
    "LOG-06": ("บัญชีที่ปิด/พ้นสภาพแล้วยังมีการเข้าสู่ระบบ", "High",
               "ตรวจสอบทันทีว่าบัญชียังเปิดอยู่ได้อย่างไร และใครเป็นผู้ใช้",
               "การควบคุมการปิดบัญชีไม่มีประสิทธิผล"),
    "LOG-07": ("เข้าสู่ระบบจากประเทศที่ไม่ได้รับอนุญาต", "Medium",
               "ยืนยันการเดินทางกับเจ้าของบัญชี และพิจารณาจำกัดประเทศ",
               "การเข้าถึงจากต่างประเทศเพิ่มความเสี่ยงการถูกโจมตี"),
    "LOG-08": ("บัญชีไม่เคลื่อนไหวนานแล้วกลับมาใช้งาน", "Medium",
               "ยืนยันว่าเจ้าของเป็นผู้ใช้จริง และทบทวนการปิดบัญชีที่ไม่ใช้งาน",
               "บัญชีเก่าที่ไม่มีคนดูแลมักถูกนำไปใช้ในทางที่ผิด"),
}

ALIASES = {
    "timestamp": ["timecreated", "time_created", "date_and_time", "date_(utc)", "date", "datetime",
                  "event_time", "time", "createddatetime", "วันเวลา"],
    "username": ["targetusername", "target_user_name", "account_name", "user_principal_name", "user",
                 "userprincipalname", "user_id", "login", "ชื่อผู้ใช้"],
    "result": ["status", "outcome", "keywords", "event_result", "ผล"],
    "event_id": ["eventid", "event_id", "id"],
    "source_ip": ["ipaddress", "ip_address", "source_network_address", "client_ip", "ip", "src_ip"],
    "country": ["country_code", "countryorregion", "ประเทศ"],
    "location": ["city", "geo"],
    "application": ["app", "app_display_name", "host", "workstation_name", "workstationname", "ระบบ"],
}

USER_ALIASES = {
    "username": ["user", "user_id", "login", "samaccountname", "user_principal_name", "ชื่อผู้ใช้"],
    "status": ["account_status", "user_status", "enabled", "สถานะ"],
    "privileged": ["is_privileged", "admin", "privileged_account", "สิทธิ์สูง"],
}

COL_TH = {"username": "ผู้ใช้", "timestamp": "เวลา", "source_ip": "IP ต้นทาง", "country": "ประเทศ",
          "application": "ระบบ", "events": "จำนวนเหตุการณ์"}
FIELDS = ["username", "timestamp", "source_ip", "country", "application", "events"]


@dataclass
class Params:
    fail_threshold: int = 5          # ผิดกี่ครั้ง
    fail_window_min: int = 10        # ภายในกี่นาที
    spray_users: int = 5             # IP เดียวลองกี่บัญชี
    spray_window_min: int = 60
    travel_hours: float = 4.0        # ต่างประเทศภายในกี่ชั่วโมง = เดินทางไม่ทัน
    work_start: int = 7
    work_end: int = 20
    dormant_days: int = 60
    allowed_countries: list[str] = field(default_factory=lambda: ["TH"])


def _normalize_result(df: pd.DataFrame) -> pd.Series:
    res = pd.Series("Other", index=df.index)
    if "event_id" in df and (df["event_id"] != "").any():
        eid = df["event_id"].astype(str).str.strip()
        res = res.mask(eid == "4624", "Success").mask(eid.isin(["4625", "4771", "4776F"]), "Failure")
    if "result" in df:
        r = df["result"].astype(str).str.strip().str.lower()
        res = res.mask(r.str.contains(r"^(?:success|succeeded|audit success|0|ok|pass|สำเร็จ)", regex=True), "Success")
        res = res.mask(r.str.contains(r"fail|denied|invalid|audit failure|ไม่สำเร็จ|ผิด", regex=True), "Failure")
    return res


def load(log, users=None, names: dict | None = None):
    names = names or {}
    lg = read_table(log, names.get("log"), ALIASES)
    us = read_table(users, names.get("users"), USER_ALIASES) if users is not None else None
    return lg, us


def prepare(log: pd.DataFrame) -> pd.DataFrame:
    log = standardize_columns(log, ALIASES)
    require(log, ["timestamp", "username"], "Login log")
    df = ensure(log.copy(), ["source_ip", "country", "location", "application", "result", "event_id"])
    df["timestamp"] = parse_dates(df["timestamp"])
    df["username"] = df["username"].astype(str).str.strip().str.lower()
    df["username"] = df["username"].str.replace(r"^.*\\", "", regex=True)  # DOMAIN\user → user
    df["result"] = _normalize_result(df)
    if (df["country"] == "").all() and (df["location"] != "").any():   # Entra: "Bangkok, Bangkok, TH"
        df["country"] = df["location"].astype(str).str.split(",").str[-1].str.strip()
    df["country"] = df["country"].astype(str).str.strip().str.upper()
    df = df[df["timestamp"].notna() & (df["username"] != "") & (df["username"] != "-")]
    if df.empty:
        from .common import AuditError
        raise AuditError("ไม่พบเหตุการณ์ที่อ่านได้ ตรวจสอบคอลัมน์ timestamp และ username")
    return df.sort_values("timestamp").reset_index(drop=True)


def _row(r, **kw):
    return {"username": r.username, "timestamp": r.timestamp, "source_ip": r.source_ip,
            "country": r.country, "application": r.application, **kw}


def analyze(log: pd.DataFrame, users: pd.DataFrame | None = None, params: Params | None = None) -> dict:
    p = params or Params()
    df = prepare(log)
    rows = []
    W = np.timedelta64(p.fail_window_min, "m")
    fails = df[df["result"] == "Failure"]
    succ = df[df["result"] == "Success"]

    # LOG-01 brute force (บันทึกครั้งเดียวต่อช่วง)
    for user, g in fails.groupby("username"):
        t = g["timestamp"].values
        i = 0
        while i < len(t):
            j = np.searchsorted(t, t[i] + W, side="right")
            if j - i >= p.fail_threshold:
                r = g.iloc[i]
                ips = ", ".join(sorted(set(g.iloc[i:j]["source_ip"]) - {""}))
                rows.append({"check_id": "LOG-01", **_row(r, events=j - i, source_ip=ips),
                             "detail": f"ผิด {j - i} ครั้งใน {p.fail_window_min} นาที "
                                       f"({pd.Timestamp(t[i]):%H:%M}–{pd.Timestamp(t[j - 1]):%H:%M})"})
                i = j
            else:
                i += 1

    # LOG-02 success หลังผิดหลายครั้ง
    fail_times = {u: g["timestamp"].values for u, g in fails.groupby("username")}
    for r in succ.itertuples(index=False):
        t = fail_times.get(r.username)
        if t is None:
            continue
        ts = np.datetime64(r.timestamp)
        n = np.searchsorted(t, ts, side="left") - np.searchsorted(t, ts - W, side="left")
        if n >= p.fail_threshold:
            rows.append({"check_id": "LOG-02", **_row(r, events=int(n)),
                         "detail": f"สำเร็จหลังผิด {n} ครั้งภายใน {p.fail_window_min} นาที จาก IP {r.source_ip}"})

    # LOG-03 password spraying
    SW = pd.Timedelta(minutes=p.spray_window_min)
    for ip, g in fails[fails["source_ip"] != ""].groupby("source_ip"):
        g = g.reset_index(drop=True)
        i = 0
        while i < len(g):
            win = g[(g["timestamp"] >= g.loc[i, "timestamp"]) & (g["timestamp"] <= g.loc[i, "timestamp"] + SW)]
            users_hit = win["username"].nunique()
            if users_hit >= p.spray_users:
                r = g.iloc[i]
                rows.append({"check_id": "LOG-03", **_row(r, username=f"{users_hit} บัญชี", events=len(win)),
                             "detail": f"IP {ip} ลอง {users_hit} บัญชีใน {p.spray_window_min} นาที: "
                                       + ", ".join(sorted(win["username"].unique())[:10])})
                i = int(win.index.max()) + 1
            else:
                i += 1

    # LOG-04 impossible travel
    TW = pd.Timedelta(hours=p.travel_hours)
    s = succ[succ["country"] != ""]
    for user, g in s.groupby("username"):
        prev = None
        for r in g.itertuples(index=False):
            if prev is not None and r.country != prev.country and r.timestamp - prev.timestamp <= TW:
                hrs = (r.timestamp - prev.timestamp).total_seconds() / 3600
                rows.append({"check_id": "LOG-04", **_row(r, events=2),
                             "detail": f"{prev.country} ({prev.timestamp:%Y-%m-%d %H:%M}) → {r.country} "
                                       f"({r.timestamp:%H:%M}) ห่างกัน {hrs:.1f} ชม."})
            prev = r

    # ข้อมูลผู้ใช้ (ถ้ามี)
    priv, inactive = set(), {}
    if users is not None and not users.empty:
        users = ensure(users.copy(), ["status", "privileged"])
        users["username"] = users["username"].astype(str).str.strip().str.lower()
        priv = set(users.loc[yes(users["privileged"]), "username"])
        st = users["status"].astype(str).str.lower()
        bad = users[st.str.contains("disab|termin|resign|inactive|lock|ปิด|ลาออก|พ้น", regex=True)]
        inactive = dict(zip(bad["username"], bad["status"]))

    # LOG-05 นอกเวลา (รวมเป็นรายวันต่อผู้ใช้)
    h = succ["timestamp"].dt.hour
    off = succ[(succ["timestamp"].dt.dayofweek >= 5) | (h < p.work_start) | (h >= p.work_end)]
    for (user, day), g in off.groupby(["username", off["timestamp"].dt.date]):
        r = g.iloc[0]
        row = {"check_id": "LOG-05", **_row(r, events=len(g)),
               "detail": f"{len(g)} ครั้ง วัน{['จันทร์','อังคาร','พุธ','พฤหัส','ศุกร์','เสาร์','อาทิตย์'][r.timestamp.dayofweek]} "
                         f"เวลา " + ", ".join(t.strftime("%H:%M") for t in g["timestamp"].head(5))}
        if user in priv:
            row["severity"] = "Medium"
            row["detail"] = "[บัญชีสิทธิ์สูง] " + row["detail"]
        rows.append(row)

    # LOG-06 บัญชีที่ปิดแล้ว
    for user, status in inactive.items():
        g = df[df["username"] == user]
        if g.empty:
            continue
        ok = g[g["result"] == "Success"]
        r = (ok if not ok.empty else g).iloc[-1]
        row = {"check_id": "LOG-06", **_row(r, events=len(g)),
               "detail": f"สถานะ '{status}' แต่มีการเข้าสู่ระบบสำเร็จ {len(ok)} ครั้ง" if not ok.empty
               else f"สถานะ '{status}' มีความพยายามเข้าสู่ระบบ {len(g)} ครั้ง (ไม่สำเร็จ)"}
        if ok.empty:
            row["severity"] = "Medium"
        rows.append(row)

    # LOG-07 ประเทศที่ไม่อนุญาต
    allowed = {c.strip().upper() for c in p.allowed_countries if c.strip()}
    if allowed and (df["country"] != "").any():
        foreign = succ[(succ["country"] != "") & ~succ["country"].isin(allowed)]
        for (user, ctry), g in foreign.groupby(["username", "country"]):
            r = g.iloc[0]
            rows.append({"check_id": "LOG-07", **_row(r, events=len(g)),
                         "detail": f"สำเร็จจาก {ctry} {len(g)} ครั้ง (ครั้งแรก {r.timestamp:%Y-%m-%d %H:%M})"})

    # LOG-08 ไม่เคลื่อนไหวแล้วกลับมาใช้
    for user, g in succ.groupby("username"):
        gap = g["timestamp"].diff()
        for idx in gap[gap > pd.Timedelta(days=p.dormant_days)].index:
            r = g.loc[idx]
            rows.append({"check_id": "LOG-08", **_row(r, events=1),
                         "detail": f"ไม่ได้ใช้งาน {gap[idx].days} วัน แล้วกลับมาใช้เมื่อ {r.timestamp:%Y-%m-%d %H:%M}"})

    findings = sort_findings(make_findings(rows, CHECKS, FIELDS), ["timestamp"])
    hourly = df.assign(hour=df["timestamp"].dt.hour).pivot_table(
        index="hour", columns="result", values="username", aggfunc="count", fill_value=0)
    hourly = hourly.reindex(range(24), fill_value=0).reset_index()
    top_fail = (fails.groupby("username").size().sort_values(ascending=False).head(15)
                .rename("failures").reset_index())
    flagged_users = set(findings["username"]) if not findings.empty else set()
    stats = {"events": len(df), "success": int((df["result"] == "Success").sum()),
             "failure": int((df["result"] == "Failure").sum()), "users": df["username"].nunique(),
             "ips": df["source_ip"].replace("", np.nan).nunique(),
             "period": f"{df['timestamp'].min():%Y-%m-%d} ถึง {df['timestamp'].max():%Y-%m-%d}",
             "flagged_users": len(flagged_users), "has_country": bool((df["country"] != "").any()),
             "has_users": users is not None}
    status = {}
    if not stats["has_country"]:
        status["LOG-04"] = status["LOG-07"] = "ไม่ได้ตรวจ: ไม่มีข้อมูลประเทศ"
    if users is None:
        status["LOG-06"] = "ไม่ได้ตรวจ: ไม่มีรายชื่อผู้ใช้และสถานะ"
    return {"findings": findings, "hourly": hourly, "top_fail": top_fail, "stats": stats, "status": status}


def write_report(res: dict, out, org: str = "(ไม่ระบุ)", source: str = "(ไม่ระบุ)"):
    s = res["stats"]
    info = [("องค์กร", org), ("แหล่งข้อมูล", source), ("ช่วงเวลา", s["period"]),
            ("จำนวนเหตุการณ์", f"{s['events']:,} (สำเร็จ {s['success']:,} / ไม่สำเร็จ {s['failure']:,})"),
            ("จำนวนบัญชี / IP", f"{s['users']:,} / {s['ips']:,}"), ("บัญชีที่พบความผิดปกติ", s["flagged_users"])]
    write_findings_report(out, "รายงานการวิเคราะห์ความผิดปกติของการเข้าสู่ระบบ (Login Anomaly)", info, CHECKS,
                          res["findings"], COL_TH, status=res["status"],
                          extra_sheets={"Hourly Pattern": res["hourly"], "Top Failed Accounts": res["top_fail"]})


# ----------------------------------------------------------------------------
# ข้อมูลตัวอย่าง
# ----------------------------------------------------------------------------

def demo_frames(seed: int = 3):
    rng = np.random.default_rng(seed)
    users = [f"user{i:02d}" for i in range(1, 26)] + ["somchai.k", "nida.p", "sompong.r", "admin.root",
                                                       "ex.employee"]
    days = pd.bdate_range("2026-07-01", "2026-09-13")
    ev = []

    def add(ts, u, res, ip, ctry="TH", app="VPN"):
        ev.append({"timestamp": pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M:%S"), "username": u, "result": res,
                   "source_ip": ip, "country": ctry, "application": app})

    normal = [u for u in users if u not in ("sompong.r", "ex.employee")]
    for d in days:
        for u in rng.choice(normal, size=18, replace=False):
            ts = d + pd.Timedelta(hours=float(rng.uniform(8, 18)))
            ip = f"10.10.{rng.integers(1, 30)}.{rng.integers(2, 250)}"
            if rng.random() < 0.08:                                     # พิมพ์ผิดเป็นครั้งคราว
                add(ts - pd.Timedelta(seconds=40), u, "Failure", ip)
            add(ts, u, "Success", ip)
    # --- ฝังความผิดปกติ ---
    t0 = pd.Timestamp("2026-08-18 03:12:00")                            # brute force + สำเร็จ
    for k in range(12):
        add(t0 + pd.Timedelta(seconds=25 * k), "somchai.k", "Failure", "185.220.101.4", "RU")
    add(t0 + pd.Timedelta(seconds=25 * 12), "somchai.k", "Success", "185.220.101.4", "RU")
    t1 = pd.Timestamp("2026-08-25 21:40:00")                            # password spraying
    for k, u in enumerate(["user01", "user02", "user03", "user05", "user08", "user09", "user11", "user13"]):
        add(t1 + pd.Timedelta(minutes=2 * k), u, "Failure", "45.13.1.9", "NL")
    add("2026-09-03 09:05:00", "nida.p", "Success", "10.10.4.21", "TH")  # impossible travel
    add("2026-09-03 10:35:00", "nida.p", "Success", "104.28.9.77", "US")
    for ts in ("2026-08-02 02:13:00", "2026-08-16 23:48:00", "2026-09-06 01:30:00"):   # privileged นอกเวลา
        add(ts, "admin.root", "Success", "10.10.1.5", "TH", "Domain Controller")
    add("2026-08-28 14:22:00", "ex.employee", "Success", "10.10.9.40", "TH")   # บัญชีพ้นสภาพ
    add("2026-07-02 10:00:00", "sompong.r", "Success", "10.10.3.3", "TH")       # dormant แล้วกลับมา
    add("2026-09-10 19:55:00", "sompong.r", "Success", "10.10.3.3", "TH")
    log = pd.DataFrame(ev).sort_values("timestamp").reset_index(drop=True)
    ul = pd.DataFrame({"username": users, "status": "Active", "privileged": "N"})
    ul.loc[ul["username"] == "admin.root", "privileged"] = "Y"
    ul.loc[ul["username"] == "ex.employee", "status"] = "Terminated"
    return log, ul
