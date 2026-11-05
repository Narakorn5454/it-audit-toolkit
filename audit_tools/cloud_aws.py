"""
AWS Cloud Configuration Review — ตรวจการตั้งค่าความปลอดภัยบัญชี AWS จากไฟล์ export (อ่านอย่างเดียว)
====================================================================================================
ไฟล์ที่ได้จาก scripts/collect_aws.sh (ระบบตรวจชนิดไฟล์ให้อัตโนมัติ):
  credential_report.csv         IAM credential report
  password_policy.json          aws iam get-account-password-policy
  security_groups_<region>.json aws ec2 describe-security-groups
  cloudtrail_trails.json        aws cloudtrail describe-trails
  cloudtrail_status.csv         trail_name,is_logging
  s3_public_access.csv          bucket, block settings, policy_is_public
  s3_account_public_access.json aws s3control get-public-access-block
  admin_policy_entities.json    aws iam list-entities-for-policy (AdministratorAccess)
แนวเกณฑ์: CIS Amazon Web Services Foundations Benchmark (หมวด IAM, Logging, Storage, Networking)
"""

from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass
from datetime import date

import pandas as pd

from .common import AuditError, make_findings, parse_dates, read_text, sort_findings, write_findings_report

CHECKS = {
    "AWS-01": ("Root account ไม่ได้เปิด MFA", "High", "เปิด MFA (แนะนำ hardware MFA) ให้ root account ทันที",
               "CIS AWS — IAM: root ต้องมี MFA"),
    "AWS-02": ("Root account มี access key ที่ใช้งานอยู่", "High", "ลบ access key ของ root และใช้ IAM role แทน",
               "CIS AWS — IAM: ไม่ควรมี root access key"),
    "AWS-03": ("มีการใช้ root account ในช่วงที่ผ่านมา", "Medium",
               "จำกัดการใช้ root เฉพาะงานที่จำเป็น และตั้งการแจ้งเตือนเมื่อมีการใช้", "CIS AWS — IAM: หลีกเลี่ยงการใช้ root"),
    "AWS-04": ("ผู้ใช้ที่เข้า Console ได้แต่ไม่ได้เปิด MFA", "High", "บังคับ MFA สำหรับผู้ใช้ทุกคนที่มีรหัสผ่าน Console",
               "CIS AWS — IAM: MFA สำหรับผู้ใช้ Console"),
    "AWS-05": ("Access key ไม่ได้หมุนเวียนเกินกำหนด", "Medium", "หมุนเวียน access key อย่างน้อยทุก 90 วัน หรือเปลี่ยนไปใช้ role",
               "CIS AWS — IAM: หมุนเวียน access key ทุก 90 วัน"),
    "AWS-06": ("ข้อมูลยืนยันตัวตนที่ไม่ได้ใช้งานเกินกำหนด", "Medium", "ปิดรหัสผ่าน / access key ที่ไม่ได้ใช้",
               "CIS AWS — IAM: ปิด credential ที่ไม่ได้ใช้ 45 วันขึ้นไป"),
    "AWS-07": ("ผู้ใช้มี access key ใช้งานอยู่ 2 ชุด", "Low", "เหลือ access key ที่ใช้งานเพียงชุดเดียว",
               "CIS AWS — IAM: หนึ่ง active key ต่อผู้ใช้"),
    "AWS-08": ("นโยบายรหัสผ่าน IAM ไม่เป็นไปตามเกณฑ์", "Medium", "ตั้งความยาวขั้นต่ำ 14 ตัวและป้องกันการใช้รหัสเดิม 24 รหัส",
               "CIS AWS — IAM: password policy"),
    "AWS-09": ("Security group เปิดพอร์ตผู้ดูแลระบบ/ทุกพอร์ตสู่อินเทอร์เน็ต", "High",
               "จำกัดแหล่งที่มาเฉพาะ IP ที่จำเป็น หรือใช้ Session Manager / VPN แทน",
               "CIS AWS — Networking: ห้ามเปิด 22/3389 จาก 0.0.0.0/0 หรือ ::/0"),
    "AWS-10": ("Security group เปิดพอร์ตฐานข้อมูลสู่อินเทอร์เน็ต", "High",
               "ย้ายฐานข้อมูลไป subnet ภายใน และจำกัดการเข้าถึงเฉพาะ application", "ฐานข้อมูลไม่ควรเข้าถึงได้จากอินเทอร์เน็ต"),
    "AWS-11": ("S3 bucket อาจเปิดสาธารณะ", "Medium",
               "เปิด S3 Block Public Access ระดับบัญชีและ bucket และทบทวน bucket policy",
               "CIS AWS — Storage: Block Public Access"),
    "AWS-12": ("CloudTrail ไม่ครอบคลุม/ไม่ได้บันทึก", "High",
               "ตั้ง CloudTrail แบบ multi-region ที่บันทึกอยู่ และเปิด log file validation",
               "CIS AWS — Logging: CloudTrail ทุก region"),
    "AWS-13": ("AdministratorAccess ผูกกับผู้ใช้โดยตรง", "Medium",
               "ให้สิทธิ์ผ่านกลุ่มหรือ role และทบทวนรายชื่อผู้มีสิทธิ์ admin ทั้งหมด",
               "CIS AWS — IAM: ให้สิทธิ์ผ่าน group/role"),
}

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 27017: "MongoDB",
            6379: "Redis", 9200: "Elasticsearch", 5984: "CouchDB"}
OPEN = {"0.0.0.0/0", "::/0"}

COL_TH = {"resource": "ทรัพยากร", "resource_type": "ประเภท", "region": "Region"}
FIELDS = ["resource", "resource_type", "region"]


@dataclass
class Params:
    as_of: date | None = None
    key_rotation_days: int = 90
    unused_days: int = 45
    root_recent_days: int = 90
    min_password_length: int = 14
    password_reuse: int = 24


# ----------------------------------------------------------------------------
# อ่านไฟล์
# ----------------------------------------------------------------------------

def detect(text: str, fname: str) -> str:
    t = text.lstrip()
    if t.startswith("{") or t.startswith("["):
        try:
            j = json.loads(t)
        except json.JSONDecodeError as e:
            raise AuditError(f"{fname}: JSON ไม่ถูกต้อง ({e})") from e
        if isinstance(j, dict):
            for key, kind in (("PasswordPolicy", "password_policy"), ("SecurityGroups", "security_groups"),
                              ("trailList", "trails"), ("PolicyUsers", "admin_entities"),
                              ("PublicAccessBlockConfiguration", "account_s3")):
                if key in j:
                    return kind
        raise AuditError(f"{fname}: ไม่รู้จักรูปแบบ JSON นี้")
    head = t.splitlines()[0].lower() if t else ""
    if "mfa_active" in head and "arn" in head:
        return "credential_report"
    if head.startswith("bucket"):
        return "s3"
    if head.startswith("trail_name"):
        return "trail_status"
    raise AuditError(f"{fname}: ไม่รู้จักชนิดไฟล์")


def load_files(files: list[tuple[object, str]]) -> dict:
    """files: [(src, filename)] → dict ของข้อมูลแต่ละชนิด"""
    data: dict = {"security_groups": [], "skipped": []}
    for src, fname in files:
        text = read_text(src, fname)
        try:
            kind = detect(text, fname)
        except AuditError:
            data["skipped"].append(fname)
            continue
        if kind in ("credential_report", "s3", "trail_status"):
            data[kind] = pd.read_csv(io.StringIO(text), dtype=str).fillna("")
        elif kind == "security_groups":
            m = re.search(r"security_groups_([a-z0-9-]+)\.json", fname)
            for g in json.loads(text)["SecurityGroups"]:
                g["_region"] = m.group(1) if m else ""
                data["security_groups"].append(g)
        else:
            data[kind] = json.loads(text)
    if len(data) == 2 and not data["security_groups"]:
        raise AuditError("ไม่พบไฟล์ AWS ที่อ่านได้ — ใช้ไฟล์จาก scripts/collect_aws.sh")
    return data


# ----------------------------------------------------------------------------
# ตรวจ
# ----------------------------------------------------------------------------

def _true(v) -> bool:
    return str(v).strip().lower() == "true"


def analyze(data: dict, params: Params | None = None) -> dict:
    p = params or Params()
    today = pd.Timestamp(p.as_of or date.today())
    rows, status = [], {}

    def add(cid, resource, rtype, detail, region="", severity=None):
        r = {"check_id": cid, "resource": resource, "resource_type": rtype, "region": region, "detail": detail}
        if severity:
            r["severity"] = severity
        rows.append(r)

    # --- IAM credential report ---
    cr = data.get("credential_report")
    if cr is None:
        for c in ("AWS-01", "AWS-02", "AWS-03", "AWS-04", "AWS-05", "AWS-06", "AWS-07"):
            status[c] = "ไม่ได้ตรวจ: ไม่มี credential report"
    else:
        for c in ("user_creation_time", "password_last_used", "access_key_1_last_rotated", "access_key_2_last_rotated",
                  "access_key_1_last_used_date", "access_key_2_last_used_date"):
            if c in cr:
                cr[c + "_dt"] = parse_dates(cr[c])
        age = lambda d: (today - d).days if pd.notna(d) else None
        for r in cr.to_dict("records"):
            user = r["user"]
            if user == "<root_account>":
                if not _true(r.get("mfa_active")):
                    add("AWS-01", "root", "IAM root", "mfa_active = false")
                keys = [k for k in (1, 2) if _true(r.get(f"access_key_{k}_active"))]
                if keys:
                    add("AWS-02", "root", "IAM root", f"มี access key ที่ active: {', '.join(f'key {k}' for k in keys)}")
                d = age(r.get("password_last_used_dt"))
                if d is not None and d <= p.root_recent_days:
                    add("AWS-03", "root", "IAM root", f"ใช้งานล่าสุด {r['password_last_used_dt']:%Y-%m-%d} ({d} วันก่อน)")
                continue
            pw = _true(r.get("password_enabled"))
            if pw and not _true(r.get("mfa_active")):
                add("AWS-04", user, "IAM user", "มีรหัสผ่าน Console แต่ไม่ได้เปิด MFA")
            created = age(r.get("user_creation_time_dt"))
            if pw:
                d = age(r.get("password_last_used_dt"))
                if (d is None and (created or 0) > p.unused_days) or (d is not None and d > p.unused_days):
                    add("AWS-06", user, "IAM user (console)",
                        "ไม่เคยเข้า Console" if d is None else f"ไม่ได้เข้า Console {d} วัน")
            active = []
            for k in (1, 2):
                if not _true(r.get(f"access_key_{k}_active")):
                    continue
                active.append(k)
                rot = age(r.get(f"access_key_{k}_last_rotated_dt"))
                if rot is not None and rot > p.key_rotation_days:
                    add("AWS-05", user, f"Access key {k}", f"ไม่ได้หมุนเวียน {rot} วัน (เกณฑ์ {p.key_rotation_days} วัน)")
                used = age(r.get(f"access_key_{k}_last_used_date_dt"))
                if (used is None and (rot or 0) > p.unused_days) or (used is not None and used > p.unused_days):
                    add("AWS-06", user, f"Access key {k}",
                        "ไม่เคยถูกใช้งาน" if used is None else f"ไม่ได้ใช้งาน {used} วัน")
            if len(active) == 2:
                add("AWS-07", user, "IAM user", "access key 1 และ 2 active พร้อมกัน")

    # --- Password policy ---
    pol = data.get("password_policy")
    if pol is None:
        if cr is not None:
            add("AWS-08", "Account", "IAM password policy",
                "ไม่พบไฟล์นโยบายรหัสผ่าน (อาจยังไม่ได้ตั้งค่า ใช้ค่า default ของ AWS)")
        else:
            status["AWS-08"] = "ไม่ได้ตรวจ: ไม่มีไฟล์นโยบายรหัสผ่าน"
    else:
        pp = pol["PasswordPolicy"]
        gaps = []
        if pp.get("MinimumPasswordLength", 0) < p.min_password_length:
            gaps.append(f"ความยาวขั้นต่ำ {pp.get('MinimumPasswordLength')} (เกณฑ์ ≥ {p.min_password_length})")
        if pp.get("PasswordReusePrevention", 0) < p.password_reuse:
            gaps.append(f"ป้องกันใช้รหัสเดิม {pp.get('PasswordReusePrevention', 0)} (เกณฑ์ ≥ {p.password_reuse})")
        for k, label in (("RequireSymbols", "สัญลักษณ์"), ("RequireNumbers", "ตัวเลข"),
                         ("RequireUppercaseCharacters", "ตัวพิมพ์ใหญ่"), ("RequireLowercaseCharacters", "ตัวพิมพ์เล็ก")):
            if not pp.get(k, False):
                gaps.append(f"ไม่บังคับ{label}")
        if gaps:
            add("AWS-08", "Account", "IAM password policy", "; ".join(gaps))

    # --- Security groups ---
    sgs = data.get("security_groups") or []
    if not sgs:
        status["AWS-09"] = status["AWS-10"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ security groups"
    for g in sgs:
        name = f"{g.get('GroupId')} ({g.get('GroupName')})"
        for perm in g.get("IpPermissions", []):
            cidrs = {x.get("CidrIp") for x in perm.get("IpRanges", [])} | \
                    {x.get("CidrIpv6") for x in perm.get("Ipv6Ranges", [])}
            open_ = sorted(cidrs & OPEN)
            if not open_:
                continue
            proto = str(perm.get("IpProtocol"))
            lo, hi = perm.get("FromPort"), perm.get("ToPort")
            if proto == "-1" or (lo in (0, None) and hi in (65535, None)):
                add("AWS-09", name, "Security group", f"เปิดทุกพอร์ต/ทุกโปรโตคอลจาก {', '.join(open_)}", g["_region"])
                continue
            if proto not in ("tcp", "6", "udp", "17"):
                continue
            for port, svc in ADMIN_PORTS.items():
                if lo <= port <= hi:
                    add("AWS-09", name, "Security group", f"เปิด {svc} ({port}) จาก {', '.join(open_)}", g["_region"])
            for port, svc in DB_PORTS.items():
                if lo <= port <= hi:
                    add("AWS-10", name, "Security group", f"เปิด {svc} ({port}) จาก {', '.join(open_)}", g["_region"])

    # --- S3 ---
    s3, acct = data.get("s3"), data.get("account_s3")
    acct_all = False
    if acct:
        cfg = acct["PublicAccessBlockConfiguration"]
        acct_all = all(cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                                            "RestrictPublicBuckets"))
    if s3 is None:
        status["AWS-11"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ S3"
    else:
        flags = ["block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"]
        for r in s3.to_dict("records"):
            if _true(r.get("policy_is_public")):
                add("AWS-11", r["bucket"], "S3 bucket", "Bucket policy เปิดสาธารณะ (IsPublic = true)", severity="High")
                continue
            off = [f for f in flags if not _true(r.get(f))]
            if off and not acct_all:
                add("AWS-11", r["bucket"], "S3 bucket",
                    "Block Public Access ไม่ครบ: " + ", ".join(off) + " (และไม่ได้เปิดระดับบัญชี)")

    # --- CloudTrail ---
    trails = (data.get("trails") or {}).get("trailList")
    if trails is None:
        status["AWS-12"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ CloudTrail"
    else:
        st = data.get("trail_status")
        logging = dict(zip(st["trail_name"], st["is_logging"].map(_true))) if st is not None else {}
        good = [t for t in trails if t.get("IsMultiRegionTrail") and logging.get(t["Name"], True)]
        if not trails:
            add("AWS-12", "Account", "CloudTrail", "ไม่มี trail")
        elif not good:
            add("AWS-12", ", ".join(t["Name"] for t in trails), "CloudTrail",
                "ไม่มี trail แบบ multi-region ที่กำลังบันทึก")
        for t in trails:
            if t["Name"] in logging and not logging[t["Name"]]:
                add("AWS-12", t["Name"], "CloudTrail", "trail ถูกหยุดบันทึก (IsLogging = false)", t.get("HomeRegion", ""))
            if not t.get("LogFileValidationEnabled"):
                add("AWS-12", t["Name"], "CloudTrail", "ไม่ได้เปิด log file validation", t.get("HomeRegion", ""),
                    severity="Low")

    # --- AdministratorAccess ---
    ae = data.get("admin_entities")
    admins = pd.DataFrame()
    if ae is None:
        status["AWS-13"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ผู้ถือ AdministratorAccess"
    else:
        lst = [("User", x["UserName"]) for x in ae.get("PolicyUsers", [])] + \
              [("Group", x["GroupName"]) for x in ae.get("PolicyGroups", [])] + \
              [("Role", x["RoleName"]) for x in ae.get("PolicyRoles", [])]
        admins = pd.DataFrame(lst, columns=["ประเภท", "ชื่อ"])
        for kind, n in lst:
            if kind == "User":
                add("AWS-13", n, "IAM user", "ผูก AdministratorAccess โดยตรง")

    findings = sort_findings(make_findings(rows, CHECKS, FIELDS), ["resource"])
    stats = {"users": 0 if cr is None else int((cr["user"] != "<root_account>").sum()),
             "security_groups": len(sgs), "buckets": 0 if s3 is None else len(s3),
             "trails": 0 if trails is None else len(trails), "skipped": data.get("skipped", [])}
    return {"findings": findings, "status": status, "stats": stats, "admins": admins,
            "credential_report": cr.drop(columns=[c for c in cr.columns if c.endswith("_dt")]) if cr is not None else None}


def write_report(res: dict, out, account: str = "(ไม่ระบุ)"):
    s = res["stats"]
    info = [("AWS Account", account), ("IAM users", s["users"]), ("Security groups", s["security_groups"]),
            ("S3 buckets", s["buckets"]), ("CloudTrail trails", s["trails"])]
    extra = {"Administrator Access": res["admins"]}
    if res["credential_report"] is not None:
        extra["Credential Report"] = res["credential_report"]
    write_findings_report(out, "รายงานการตรวจสอบการตั้งค่า AWS (Cloud Configuration Review)", info, CHECKS,
                          res["findings"], COL_TH, status=res["status"], extra_sheets=extra,
                          note="เกณฑ์อ้างอิงแนว CIS AWS Foundations Benchmark — ควรยืนยันกับเวอร์ชันล่าสุด")


# ----------------------------------------------------------------------------
# ไฟล์ตัวอย่าง
# ----------------------------------------------------------------------------

def demo_files(as_of: date | None = None) -> list[tuple[bytes, str]]:
    t = pd.Timestamp(as_of or date.today())
    d = lambda days: (t - pd.Timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    hdr = ("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
           "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
           "access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
           "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
           "access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,"
           "cert_2_active,cert_2_last_rotated")
    acct = "arn:aws:iam::111122223333"
    rows = [
        f"<root_account>,{acct}:root,{d(1500)},not_supported,{d(12)},not_supported,not_supported,false,"
        f"true,{d(900)},{d(30)},ap-southeast-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        f"alice,{acct}:user/alice,{d(700)},true,{d(1)},{d(60)},N/A,true,true,{d(30)},{d(1)},ap-southeast-1,ec2,"
        f"false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        f"bob,{acct}:user/bob,{d(500)},true,{d(3)},{d(100)},N/A,false,false,N/A,N/A,N/A,N/A,"
        f"false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        f"ci-deploy,{acct}:user/ci-deploy,{d(800)},false,N/A,N/A,N/A,false,true,{d(400)},{d(2)},"
        f"ap-southeast-1,ecr,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        f"old-contractor,{acct}:user/old-contractor,{d(400)},true,{d(200)},{d(380)},N/A,true,true,{d(390)},"
        f"no_information,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        f"svc-backup,{acct}:user/svc-backup,{d(300)},false,N/A,N/A,N/A,false,true,{d(60)},{d(1)},"
        f"ap-southeast-1,s3,true,{d(20)},{d(1)},ap-southeast-1,s3,false,N/A,false,N/A",
    ]
    files = [("\n".join([hdr] + rows) + "\n", "credential_report.csv")]
    files.append((json.dumps({"PasswordPolicy": {"MinimumPasswordLength": 8, "RequireSymbols": False,
                                                 "RequireNumbers": True, "RequireUppercaseCharacters": True,
                                                 "RequireLowercaseCharacters": True,
                                                 "AllowUsersToChangePassword": True, "ExpirePasswords": False}},
                             indent=2), "password_policy.json"))
    sg = lambda gid, name, perms: {"GroupId": gid, "GroupName": name, "VpcId": "vpc-0a1b", "IpPermissions": perms}
    rule = lambda proto, lo, hi, v4=(), v6=(): {"IpProtocol": proto, "FromPort": lo, "ToPort": hi,
                                                "IpRanges": [{"CidrIp": c} for c in v4],
                                                "Ipv6Ranges": [{"CidrIpv6": c} for c in v6]}
    files.append((json.dumps({"SecurityGroups": [
        sg("sg-0web", "web-public", [rule("tcp", 443, 443, ["0.0.0.0/0"]), rule("tcp", 22, 22, ["0.0.0.0/0"])]),
        sg("sg-0db", "db-mysql", [rule("tcp", 3306, 3306, ["0.0.0.0/0"])]),
        sg("sg-0tmp", "temp-allow-all", [{"IpProtocol": "-1", "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]),
        sg("sg-0int", "internal-ssh", [rule("tcp", 22, 22, ["10.0.0.0/16"])]),
    ]}, indent=2), "security_groups_ap-southeast-1.json"))
    files.append((json.dumps({"trailList": [{"Name": "main-trail", "S3BucketName": "corp-cloudtrail-logs",
                                             "IsMultiRegionTrail": False, "LogFileValidationEnabled": False,
                                             "HomeRegion": "ap-southeast-1"}]}, indent=2), "cloudtrail_trails.json"))
    files.append(("trail_name,is_logging\nmain-trail,True\n", "cloudtrail_status.csv"))
    files.append(("bucket,block_public_acls,ignore_public_acls,block_public_policy,restrict_public_buckets,"
                  "policy_is_public\n"
                  "corp-public-website,False,False,False,False,True\n"
                  "corp-cloudtrail-logs,True,True,True,True,False\n"
                  "finance-reports-2026,True,True,False,False,False\n", "s3_public_access.csv"))
    files.append((json.dumps({"PolicyGroups": [{"GroupName": "Admins"}], "PolicyUsers": [{"UserName": "bob"}],
                              "PolicyRoles": [{"RoleName": "OrganizationAccountAccessRole"}]}, indent=2),
                  "admin_policy_entities.json"))
    return [(c.encode(), n) for c, n in files]


# หมวดความเสี่ยงสำหรับเปรียบเทียบข้าม cloud (ใช้ใน cloud_summary)
CATEGORY = {"AWS-01": "Identity & MFA", "AWS-02": "Privileged access", "AWS-03": "Privileged access",
            "AWS-04": "Identity & MFA", "AWS-05": "Identity & MFA", "AWS-06": "Identity & MFA",
            "AWS-07": "Identity & MFA", "AWS-08": "Identity & MFA", "AWS-09": "Network exposure",
            "AWS-10": "Network exposure", "AWS-11": "Storage & data", "AWS-12": "Logging",
            "AWS-13": "Privileged access"}
