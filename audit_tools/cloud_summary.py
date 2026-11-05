"""
Multi-Cloud Summary — รวมผลการตรวจ AWS / Azure / Google Cloud และเปรียบเทียบตามหมวดความเสี่ยง
"""

from __future__ import annotations

import pandas as pd

from . import cloud_aws, cloud_azure, cloud_gcp
from .common import SEVERITY_ORDER, sort_findings, write_findings_report

MODULES = {"AWS": cloud_aws, "Azure": cloud_azure, "Google Cloud": cloud_gcp}
CHECKS_ALL = {k: v for m in MODULES.values() for k, v in m.CHECKS.items()}
CATEGORY_ALL = {k: v for m in MODULES.values() for k, v in m.CATEGORY.items()}
CATEGORIES = ["Identity & MFA", "Privileged access", "Network exposure", "Storage & data", "Logging",
              "Threat detection"]
COL_TH = {"cloud": "Cloud", "category": "หมวดความเสี่ยง", "resource": "ทรัพยากร", "resource_type": "ประเภท",
          "region": "Region / ตำแหน่ง"}


def combine(results: dict[str, dict]) -> dict:
    """results: {"AWS": analyze-result, "Azure": ..., "Google Cloud": ...}"""
    frames = []
    for cloud, r in results.items():
        f = r["findings"]
        if f.empty:
            continue
        f = f.drop(columns=["finding_no"], errors="ignore").copy()
        f.insert(1, "cloud", cloud)
        f.insert(3, "category", f["check_id"].map(CATEGORY_ALL))
        frames.append(f)
    findings = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(
        columns=["check_id", "cloud", "severity", "category", "resource", "resource_type", "region", "detail",
                 "recommendation"])
    findings = sort_findings(findings, ["cloud", "resource"]) if not findings.empty else findings

    sev = [s for s in SEVERITY_ORDER]
    by_cloud = (pd.crosstab(findings["cloud"], findings["severity"]).reindex(columns=sev, fill_value=0)
                if not findings.empty else pd.DataFrame(columns=sev))
    by_cloud = by_cloud.reindex(list(results), fill_value=0)
    by_cloud["รวม"] = by_cloud.sum(axis=1)
    by_cloud = by_cloud.reset_index().rename(columns={"cloud": "Cloud", "index": "Cloud"})

    matrix = (pd.crosstab(findings["category"], findings["cloud"]) if not findings.empty else pd.DataFrame())
    matrix = matrix.reindex(index=CATEGORIES, columns=list(results), fill_value=0)
    matrix = matrix.reset_index().rename(columns={"category": "หมวดความเสี่ยง", "index": "หมวดความเสี่ยง"})

    status = {k: v for r in results.values() for k, v in r.get("status", {}).items()}
    return {"findings": findings, "by_cloud": by_cloud, "matrix": matrix, "status": status, "clouds": list(results)}


def write_report(combined: dict, out, org: str = "(ไม่ระบุ)"):
    clouds = combined["clouds"]
    prefixes = {"AWS": "AWS-", "Azure": "AZ-", "Google Cloud": "GCP-"}
    checks = {k: v for k, v in CHECKS_ALL.items() if any(k.startswith(prefixes[c]) for c in clouds)}
    info = [("องค์กร", org), ("Cloud ที่ตรวจ", ", ".join(clouds))]
    write_findings_report(out, "รายงานการตรวจสอบการตั้งค่า Multi-Cloud (AWS / Azure / Google Cloud)", info, checks,
                          combined["findings"], COL_TH, status=combined["status"], per_check_sheets=False,
                          extra_sheets={"By Cloud": combined["by_cloud"], "Category x Cloud": combined["matrix"]},
                          note="เกณฑ์อ้างอิงแนว CIS Foundations Benchmark ของแต่ละ cloud — ควรยืนยันกับเวอร์ชันล่าสุด")
