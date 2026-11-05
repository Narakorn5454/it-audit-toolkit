"""
Google Cloud (GCP) Configuration Review — ตรวจการตั้งค่าความปลอดภัย GCP จากไฟล์ export (อ่านอย่างเดียว)
=====================================================================================================
ไฟล์จาก scripts/collect_gcp.sh (gcloud) — ระบบตรวจชนิดไฟล์ให้อัตโนมัติ:
  project_info.json            gcloud projects describe
  project_iam_policy.json      gcloud projects get-iam-policy
  firewall_rules.json          gcloud compute firewall-rules list
  networks.json                gcloud compute networks list
  sa_keys_<account>.json       gcloud iam service-accounts keys list --managed-by=user
  buckets.json                 gcloud storage buckets list
  bucket_iam_<bucket>.json     gcloud storage buckets get-iam-policy
  sql_instances.json           gcloud sql instances list
แนวเกณฑ์: CIS Google Cloud Platform Foundation Benchmark
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date

import pandas as pd

from .cloud_aws import ADMIN_PORTS, DB_PORTS
from .common import AuditError, make_findings, parse_dates, read_text, sort_findings, write_findings_report

CHECKS = {
    "GCP-01": ("Project IAM ให้สิทธิ์ allUsers / allAuthenticatedUsers", "High",
               "ลบ binding สาธารณะออกจาก project IAM", "CIS GCP — IAM: ไม่ให้สิทธิ์สาธารณะระดับ project"),
    "GCP-02": ("ผู้ใช้ได้รับ basic role (Owner / Editor)", "Medium",
               "เปลี่ยนเป็น predefined role ที่จำกัดตามหน้าที่ และให้สิทธิ์ผ่านกลุ่ม",
               "CIS GCP — IAM: หลีกเลี่ยง basic roles ที่ให้สิทธิ์กว้างเกินจำเป็น"),
    "GCP-03": ("Service account ได้รับสิทธิ์ระดับผู้ดูแล (Owner / Editor / Admin)", "High",
               "จำกัดสิทธิ์ service account ให้เท่าที่ application ต้องใช้",
               "CIS GCP — IAM: service account ไม่ควรมีสิทธิ์ admin"),
    "GCP-04": ("Service account key ที่สร้างเองไม่ได้หมุนเวียนเกินกำหนด", "Medium",
               "หมุนเวียน key ภายใน 90 วัน หรือเปลี่ยนไปใช้ Workload Identity แทน key",
               "CIS GCP — IAM: หมุนเวียน user-managed keys"),
    "GCP-05": ("Firewall เปิดพอร์ตผู้ดูแลระบบ/ทุกพอร์ตจากอินเทอร์เน็ต", "High",
               "จำกัดแหล่งที่มา หรือใช้ Identity-Aware Proxy (IAP) สำหรับ SSH/RDP",
               "CIS GCP — Networking: ห้ามเปิด 22/3389 จาก 0.0.0.0/0"),
    "GCP-06": ("Firewall เปิดพอร์ตฐานข้อมูลจากอินเทอร์เน็ต", "High",
               "ใช้ private IP และจำกัดการเข้าถึงเฉพาะ application", "ฐานข้อมูลไม่ควรเข้าถึงได้จากอินเทอร์เน็ต"),
    "GCP-07": ("ยังมี default network", "Low", "ลบ default network และสร้าง VPC ที่ออกแบบ firewall เอง",
               "CIS GCP — Networking: default network มี firewall rule ที่เปิดกว้าง"),
    "GCP-08": ("Cloud Storage bucket เปิดสาธารณะ", "High", "ลบสิทธิ์ allUsers / allAuthenticatedUsers และเปิด Public access prevention",
               "CIS GCP — Storage: bucket ต้องไม่เปิดสาธารณะ"),
    "GCP-09": ("Bucket ไม่ได้เปิด Uniform bucket-level access / Public access prevention", "Low",
               "เปิด Uniform bucket-level access และ Public access prevention = enforced",
               "CIS GCP — Storage: ควบคุมสิทธิ์แบบรวมศูนย์"),
    "GCP-10": ("Cloud SQL เปิดรับการเชื่อมต่อจากอินเทอร์เน็ต / ไม่บังคับ SSL", "High",
               "ลบ authorized network 0.0.0.0/0 ใช้ private IP หรือ Cloud SQL Auth Proxy และบังคับ SSL",
               "CIS GCP — Cloud SQL"),
    "GCP-11": ("Cloud Audit Logs (Data Access) ไม่ครอบคลุมทุกบริการ", "Medium",
               "ตั้ง auditConfigs สำหรับ allServices ให้มี ADMIN_READ, DATA_READ, DATA_WRITE",
               "CIS GCP — Logging: เปิด Data Access audit logs"),
}
CATEGORY = {"GCP-01": "Privileged access", "GCP-02": "Privileged access", "GCP-03": "Privileged access",
            "GCP-04": "Identity & MFA", "GCP-05": "Network exposure", "GCP-06": "Network exposure",
            "GCP-07": "Network exposure", "GCP-08": "Storage & data", "GCP-09": "Storage & data",
            "GCP-10": "Network exposure", "GCP-11": "Logging"}

COL_TH = {"resource": "ทรัพยากร", "resource_type": "ประเภท", "region": "Region"}
FIELDS = ["resource", "resource_type", "region"]
PUBLIC = {"allUsers", "allAuthenticatedUsers"}
OPEN = {"0.0.0.0/0", "::/0"}
ADMIN_ROLE = re.compile(r"^roles/(owner|editor|.*[aA]dmin)$")
# service account ที่ Google สร้างและจัดการเอง (ลูกค้าแก้สิทธิ์ไม่ได้) — ไม่นับเป็นข้อตรวจพบ
GOOGLE_MANAGED = re.compile(r"(@cloudservices\.gserviceaccount\.com|@gcp-sa-[^.]+\.iam\.gserviceaccount\.com"
                            r"|^service-\d+@)")


@dataclass
class Params:
    as_of: date | None = None
    key_rotation_days: int = 90


def detect(text: str, fname: str) -> str:
    f = fname.lower()
    try:
        j = json.loads(text)
    except json.JSONDecodeError:
        raise AuditError(f"{fname}: ไม่ใช่ไฟล์ JSON")
    first = j[0] if isinstance(j, list) and j and isinstance(j[0], dict) else {}
    if isinstance(j, dict) and "bindings" in j:
        return "bucket_iam" if "bucket" in f else "project_iam"
    if isinstance(j, dict) and "projectId" in j:
        return "project"
    if "sourceRanges" in first or ("direction" in first and ("allowed" in first or "denied" in first)) or "firewall" in f:
        return "firewall"
    if "keyType" in first or "validAfterTime" in first or f.startswith("sa_keys"):
        return "sa_keys"
    if "databaseVersion" in first or "sql" in f:
        return "sql"
    if "subnetworks" in first or "autoCreateSubnetworks" in first or "network" in f:
        return "networks"
    if "storage_url" in first or "storageClass" in first or "iamConfiguration" in first or \
            "uniform_bucket_level_access" in first or f.startswith("bucket"):
        return "buckets"
    if "uniqueId" in first and "email" in first or "service_accounts" in f:
        return "service_accounts"
    raise AuditError(f"{fname}: ไม่รู้จักรูปแบบไฟล์ GCP นี้")


def load_files(files: list[tuple[object, str]]) -> dict:
    data: dict = {"sa_keys": [], "bucket_iam": {}, "skipped": []}
    for src, fname in files:
        text = read_text(src, fname)
        if not text.strip():
            data["skipped"].append(fname)
            continue
        try:
            kind = detect(text, fname)
        except AuditError:
            data["skipped"].append(fname)
            continue
        j = json.loads(text)
        if kind == "sa_keys":
            data["sa_keys"] += j if isinstance(j, list) else [j]
        elif kind == "bucket_iam":
            m = re.search(r"bucket_iam_(.+)\.json", fname)
            data["bucket_iam"][m.group(1) if m else fname] = j
        else:
            data[kind] = j
    if len(data) == 3 and not (data["sa_keys"] or data["bucket_iam"]):
        raise AuditError("ไม่พบไฟล์ GCP ที่อ่านได้ — ใช้ไฟล์จาก scripts/collect_gcp.sh")
    return data


def _port_ranges(ports) -> list[tuple[int, int]]:
    if not ports:
        return [(0, 65535)]
    out = []
    for p in ports:
        p = str(p)
        if "-" in p:
            a, b = p.split("-", 1)
            out.append((int(a), int(b)))
        elif p.isdigit():
            out.append((int(p), int(p)))
    return out


def analyze(data: dict, params: Params | None = None) -> dict:
    p = params or Params()
    today = pd.Timestamp(p.as_of or date.today())
    rows, status = [], {}

    def add(cid, resource, rtype, detail, region="", severity=None):
        r = {"check_id": cid, "resource": resource, "resource_type": rtype, "region": region, "detail": detail}
        if severity:
            r["severity"] = severity
        rows.append(r)

    # --- Project IAM ---
    iam = data.get("project_iam")
    privileged = []
    if iam is None:
        for c in ("GCP-01", "GCP-02", "GCP-03", "GCP-11"):
            status[c] = "ไม่ได้ตรวจ: ไม่มีไฟล์ project IAM policy"
    else:
        for b in iam.get("bindings", []):
            role = b.get("role", "")
            for m in b.get("members", []):
                kind, _, who = m.partition(":")
                if ADMIN_ROLE.match(role) or role in ("roles/owner", "roles/editor"):
                    privileged.append({"ผู้ถือสิทธิ์": who or m, "ประเภท": kind, "Role": role})
                if m in PUBLIC:
                    add("GCP-01", m, "Project IAM", f"{m} ได้รับ {role}")
                elif kind == "user" and role in ("roles/owner", "roles/editor"):
                    add("GCP-02", who, "Project IAM", f"ได้รับ basic role {role}")
                elif kind == "serviceAccount" and ADMIN_ROLE.match(role) and not GOOGLE_MANAGED.search(who):
                    add("GCP-03", who, "Service account", f"ได้รับ {role}")
        cfg = {c.get("service"): {x.get("logType") for x in c.get("auditLogConfigs", [])}
               for c in iam.get("auditConfigs", [])}
        need = {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
        have = cfg.get("allServices", set())
        if not need <= have:
            add("GCP-11", "Project", "Cloud Audit Logs",
                "allServices ไม่ได้ตั้งค่า" if "allServices" not in cfg
                else "allServices ขาด: " + ", ".join(sorted(need - have)))

    # --- SA keys ---
    if not data["sa_keys"]:
        status["GCP-04"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ service account keys (หรือไม่มี user-managed key)"
    for k in data["sa_keys"]:
        if k.get("keyType", "USER_MANAGED") != "USER_MANAGED" or k.get("disabled"):
            continue
        m = re.search(r"serviceAccounts/([^/]+)/keys/([^/]+)", k.get("name", ""))
        sa, kid = (m.group(1), m.group(2)[:8]) if m else (k.get("name", "?"), "")
        created = parse_dates(pd.Series([k.get("validAfterTime", "")])).iloc[0]
        if pd.notna(created):
            age = (today - created).days
            if age > p.key_rotation_days:
                add("GCP-04", sa, f"SA key {kid}…", f"สร้างเมื่อ {created:%Y-%m-%d} อายุ {age} วัน "
                                                   f"(เกณฑ์ {p.key_rotation_days} วัน)")

    # --- Firewall ---
    fw = data.get("firewall")
    if fw is None:
        status["GCP-05"] = status["GCP-06"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ firewall rules"
    else:
        for r in fw:
            if r.get("disabled") or r.get("direction", "INGRESS") != "INGRESS":
                continue
            opened = sorted(set(r.get("sourceRanges") or []) & OPEN)
            if not opened:
                continue
            net = str(r.get("network", "")).rsplit("/", 1)[-1]
            name = f"{r.get('name')} ({net})"
            for a in r.get("allowed", []):
                proto = str(a.get("IPProtocol", "")).lower()
                if proto == "all":
                    add("GCP-05", name, "VPC firewall", f"อนุญาตทุกโปรโตคอล/ทุกพอร์ตจาก {', '.join(opened)}")
                    continue
                if proto not in ("tcp", "udp", "6", "17"):
                    continue
                ranges = _port_ranges(a.get("ports"))
                if (0, 65535) in ranges:
                    add("GCP-05", name, "VPC firewall", f"อนุญาต {proto} ทุกพอร์ตจาก {', '.join(opened)}")
                    continue
                for lo, hi in ranges:
                    for port, svc in ADMIN_PORTS.items():
                        if lo <= port <= hi:
                            add("GCP-05", name, "VPC firewall", f"เปิด {svc} ({port}) จาก {', '.join(opened)}")
                    for port, svc in DB_PORTS.items():
                        if lo <= port <= hi:
                            add("GCP-06", name, "VPC firewall", f"เปิด {svc} ({port}) จาก {', '.join(opened)}")

    nets = data.get("networks")
    if nets is None:
        status["GCP-07"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ networks"
    elif any(n.get("name") == "default" for n in nets):
        add("GCP-07", "default", "VPC network", "พบ default network ใน project")

    # --- Buckets ---
    buckets = data.get("buckets")
    if buckets is None and not data["bucket_iam"]:
        status["GCP-08"] = status["GCP-09"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ buckets"
    for bname, pol in data["bucket_iam"].items():
        for b in pol.get("bindings", []):
            pub = sorted(set(b.get("members", [])) & PUBLIC)
            if pub:
                add("GCP-08", bname, "Cloud Storage bucket", f"{', '.join(pub)} ได้รับ {b.get('role')}")
    for b in buckets or []:
        cfg = b.get("iamConfiguration") or {}
        ubla = b.get("uniform_bucket_level_access",
                     (cfg.get("uniformBucketLevelAccess") or {}).get("enabled", False))
        pap = str(b.get("public_access_prevention", cfg.get("publicAccessPrevention", "inherited"))).lower()
        gaps = ([] if ubla else ["Uniform bucket-level access ปิดอยู่"]) + \
               ([] if pap == "enforced" else [f"Public access prevention = {pap}"])
        if gaps:
            add("GCP-09", b.get("name"), "Cloud Storage bucket", "; ".join(gaps), str(b.get("location", "")))

    # --- Cloud SQL ---
    sql = data.get("sql")
    if sql is None:
        status["GCP-10"] = "ไม่ได้ตรวจ: ไม่มีไฟล์ Cloud SQL"
    else:
        for i in sql:
            ipc = (i.get("settings") or {}).get("ipConfiguration") or {}
            nets_ = [n.get("value") for n in ipc.get("authorizedNetworks", [])]
            if ipc.get("ipv4Enabled") and set(nets_) & OPEN:
                add("GCP-10", i.get("name"), "Cloud SQL", "public IP และ authorized network 0.0.0.0/0", i.get("region", ""))
            ssl_ok = ipc.get("requireSsl") or str(ipc.get("sslMode", "")).upper() in (
                "ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")
            if ipc.get("ipv4Enabled") and not ssl_ok:
                add("GCP-10", i.get("name"), "Cloud SQL", "ไม่ได้บังคับการเชื่อมต่อแบบ SSL/TLS", i.get("region", ""),
                    severity="Medium")

    findings = sort_findings(make_findings(rows, CHECKS, FIELDS), ["resource"])
    proj = data.get("project") or {}
    stats = {"project": proj.get("projectId", "-"), "firewall_rules": len(fw or []), "buckets": len(buckets or []),
             "sa_keys": len(data["sa_keys"]), "skipped": data.get("skipped", [])}
    return {"findings": findings, "status": status, "stats": stats, "admins": pd.DataFrame(privileged)}


def write_report(res: dict, out, name: str = "(ไม่ระบุ)"):
    s = res["stats"]
    info = [("GCP project", name if name != "(ไม่ระบุ)" else s["project"]), ("Firewall rules", s["firewall_rules"]),
            ("Cloud Storage buckets", s["buckets"]), ("User-managed SA keys", s["sa_keys"])]
    write_findings_report(out, "รายงานการตรวจสอบการตั้งค่า Google Cloud (Cloud Configuration Review)", info, CHECKS,
                          res["findings"], COL_TH, status=res["status"],
                          extra_sheets={"Privileged Roles": res["admins"]},
                          note="เกณฑ์อ้างอิงแนว CIS Google Cloud Platform Foundation Benchmark — ควรยืนยันกับเวอร์ชันล่าสุด")


# ----------------------------------------------------------------------------
# ไฟล์ตัวอย่าง (รูปแบบเหมือน output จริงของ gcloud --format=json)
# ----------------------------------------------------------------------------

def demo_files(as_of: date | None = None) -> list[tuple[bytes, str]]:
    t = pd.Timestamp(as_of or date.today())
    ts = lambda days: (t - pd.Timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    P = "corp-prod-2026"
    sa = lambda n: f"{n}@{P}.iam.gserviceaccount.com"
    net = f"https://www.googleapis.com/compute/v1/projects/{P}/global/networks/"
    files = {
        "project_info.json": {"projectId": P, "name": "Corp Production", "projectNumber": "123456789012"},
        "project_iam_policy.json": {"version": 1, "etag": "BwYabc=", "bindings": [
            {"role": "roles/owner", "members": ["user:cloud.admin@corp.example", "user:somchai@corp.example",
                                                "group:gcp-admins@corp.example"]},
            {"role": "roles/editor", "members": ["user:nida@corp.example", f"serviceAccount:{sa('app-backend')}",
                                                 "serviceAccount:123456789012@cloudservices.gserviceaccount.com"]},
            {"role": "roles/storage.admin", "members": [f"serviceAccount:{sa('etl-job')}"]},
            {"role": "roles/viewer", "members": ["allAuthenticatedUsers", "group:auditors@corp.example"]},
            {"role": "roles/logging.viewer", "members": ["user:security@corp.example"]}],
            "auditConfigs": [{"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}]},
        "firewall_rules.json": [
            {"name": "default-allow-ssh", "network": net + "default", "direction": "INGRESS", "disabled": False,
             "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]},
            {"name": "allow-rdp-temp", "network": net + "prod-vpc", "direction": "INGRESS", "disabled": False,
             "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}]},
            {"name": "allow-mysql", "network": net + "prod-vpc", "direction": "INGRESS", "disabled": False,
             "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["3306", "8080-8090"]}]},
            {"name": "allow-https", "network": net + "prod-vpc", "direction": "INGRESS", "disabled": False,
             "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
            {"name": "allow-internal", "network": net + "prod-vpc", "direction": "INGRESS", "disabled": False,
             "sourceRanges": ["10.10.0.0/16"], "allowed": [{"IPProtocol": "all"}]},
            {"name": "old-any", "network": net + "prod-vpc", "direction": "INGRESS", "disabled": True,
             "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "all"}]},
        ],
        "networks.json": [{"name": "default", "autoCreateSubnetworks": True, "subnetworks": []},
                          {"name": "prod-vpc", "autoCreateSubnetworks": False, "subnetworks": []}],
        "sa_keys_app-backend.json": [
            {"name": f"projects/{P}/serviceAccounts/{sa('app-backend')}/keys/a1b2c3d4e5f6", "keyType": "USER_MANAGED",
             "validAfterTime": ts(410), "keyAlgorithm": "KEY_ALG_RSA_2048"}],
        "sa_keys_etl-job.json": [
            {"name": f"projects/{P}/serviceAccounts/{sa('etl-job')}/keys/f6e5d4c3b2a1", "keyType": "USER_MANAGED",
             "validAfterTime": ts(30), "keyAlgorithm": "KEY_ALG_RSA_2048"}],
        "buckets.json": [
            {"name": "corp-public-site", "location": "ASIA-SOUTHEAST1", "storage_url": "gs://corp-public-site/",
             "uniform_bucket_level_access": True, "public_access_prevention": "inherited"},
            {"name": "corp-finance-exports", "location": "ASIA-SOUTHEAST1", "storage_url": "gs://corp-finance-exports/",
             "uniform_bucket_level_access": False, "public_access_prevention": "inherited"},
            {"name": "corp-logs", "location": "ASIA-SOUTHEAST1", "storage_url": "gs://corp-logs/",
             "uniform_bucket_level_access": True, "public_access_prevention": "enforced"}],
        "bucket_iam_corp-public-site.json": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
                                             "etag": "CAE="},
        "bucket_iam_corp-finance-exports.json": {"bindings": [{"role": "roles/storage.objectAdmin",
                                                               "members": ["user:finance@corp.example"]}], "etag": "CAE="},
        "bucket_iam_corp-logs.json": {"bindings": [{"role": "roles/storage.admin",
                                                    "members": ["group:gcp-admins@corp.example"]}], "etag": "CAE="},
        "sql_instances.json": [
            {"name": "core-mysql", "databaseVersion": "MYSQL_8_0", "region": "asia-southeast1",
             "settings": {"ipConfiguration": {"ipv4Enabled": True, "requireSsl": False,
                                              "authorizedNetworks": [{"value": "0.0.0.0/0", "name": "anywhere"}]}}},
            {"name": "reporting-pg", "databaseVersion": "POSTGRES_15", "region": "asia-southeast1",
             "settings": {"ipConfiguration": {"ipv4Enabled": False, "privateNetwork": net + "prod-vpc",
                                              "sslMode": "ENCRYPTED_ONLY"}}}],
    }
    return [(json.dumps(v, indent=2).encode(), k) for k, v in files.items()]
