"""
ทดสอบว่าเครื่องมือแต่ละตัวตรวจพบความผิดปกติที่ฝังไว้ในข้อมูลตัวอย่างได้ครบและถูกต้อง
รัน: python -m pytest -q
"""

import io
from datetime import date

import pandas as pd
import pytest

from audit_tools import (access_review, assessment, assessment_banks, change_mgmt, cloud_aws, finding_tracker,
                         hardening, journal_entry, login_anomaly, password_policy, policy_review, sod)
from audit_tools.common import AuditError, parse_dates

AS_OF = date(2026, 11, 5)


def counts(findings: pd.DataFrame) -> dict:
    return findings.groupby("check_id").size().to_dict() if not findings.empty else {}


# ---------------------------------------------------------------- common
def test_parse_dates_handles_thai_and_iso():
    s = parse_dates(pd.Series(["31/03/2569", "2026-04-20", "2026-09-01T08:00:00Z", "", "15.04.2026"]))
    assert s.iloc[0] == pd.Timestamp("2026-03-31")
    assert s.iloc[1] == pd.Timestamp("2026-04-20")
    assert s.iloc[2] == pd.Timestamp("2026-09-01 08:00")
    assert pd.isna(s.iloc[3])


# ---------------------------------------------------------------- access review
def test_user_access_review_detects_planted_issues():
    folder = __import__("pathlib").Path("/tmp/uar_test")
    hr_p, users_p, sod_p = access_review.make_demo_data(folder, AS_OF)
    f, _ = access_review.run_checks(access_review.read_table(hr_p), access_review.read_table(users_p),
                                    access_review.load_sod_rules(sod_p), AS_OF, 90)
    c = counts(f)
    assert c["UAR-01"] == 2 and c["UAR-02"] == 1 and c["UAR-07"] == 3 and c["UAR-08"] == 1


def test_user_access_review_missing_columns():
    with pytest.raises(AuditError):
        access_review.run_checks(pd.DataFrame({"a": [1]}), pd.DataFrame({"b": [1]}))


# ---------------------------------------------------------------- SoD
def test_sod_cross_system_and_role_design():
    r = sod.analyze(*sod.demo_frames())
    c = counts(r["findings"])
    assert c == {"SOD-01": 4, "SOD-02": 2, "SOD-03": 1, "SOD-04": 1, "SOD-05": 1, "SOD-06": 1}
    cross = r["findings"][r["findings"]["check_id"] == "SOD-02"]
    assert set(cross["person"]) == {"E104", "E106"}


# ---------------------------------------------------------------- change
def test_change_management_all_checks_fire():
    r = change_mgmt.analyze(*change_mgmt.demo_frames())
    c = counts(r["findings"])
    assert c == {"CHG-01": 3, "CHG-02": 2, "CHG-03": 3, "CHG-04": 3, "CHG-05": 2, "CHG-06": 3,
                 "CHG-07": 6, "CHG-08": 2, "CHG-09": 4, "CHG-10": 1}


# ---------------------------------------------------------------- login
def test_login_anomalies():
    r = login_anomaly.analyze(*login_anomaly.demo_frames())
    c = counts(r["findings"])
    for cid in ("LOG-01", "LOG-02", "LOG-03", "LOG-04", "LOG-06", "LOG-08"):
        assert c.get(cid) == 1, cid
    assert c["LOG-07"] == 2
    priv = r["findings"][(r["findings"]["check_id"] == "LOG-05") & (r["findings"]["severity"] == "Medium")]
    assert set(priv["username"]) == {"admin.root"}


def test_login_windows_event_ids():
    df = pd.DataFrame({"timecreated": ["2026-09-01 08:00", "2026-09-01 08:01"], "event_id": ["4625", "4624"],
                       "username": ["CORP\\Somchai", "CORP\\Somchai"]})
    p = login_anomaly.prepare(df)
    assert list(p["result"]) == ["Failure", "Success"] and p["username"].iloc[0] == "somchai"


# ---------------------------------------------------------------- password policy
def test_password_policy_parsers_and_scores():
    systems = password_policy.demo_systems()
    r = password_policy.evaluate(systems, password_policy.BASELINES["CIS-style (Windows / AD)"])
    score = dict(zip(r["score"]["system"], r["score"]["compliance_pct"]))
    assert score["WebServer01"] == 100 and score["FileServer01"] < 30
    vals = {s["system"]: s["values"] for s in systems}
    assert vals["AD-Domain"]["max_age_days"] == 42 and vals["AD-Domain"]["lockout_duration_min"] == 30
    assert vals["AppServer-Linux"]["max_age_days"] == float("inf")


def test_password_policy_secedit_utf16():
    raw = password_policy.DEMO_FILES["WebServer01 (secedit)"][1].encode("utf-16")
    s = password_policy.load_files([("WS", io.BytesIO(raw), "secpol.inf")])
    assert s[0]["values"]["min_length"] == 14


# ---------------------------------------------------------------- hardening
def test_hardening_detects_backdoor_and_weak_settings():
    r = hardening.review(hardening.demo_files())
    ids = set(r["findings"]["check_id"])
    assert {"NIX-01", "NIX-03", "SSH-01", "WIN-01", "WIN-04", "AUD-02", "NIX-06"} <= ids
    assert "backdoor" in r["findings"].set_index("check_id").loc["NIX-01", "detail"]


# ---------------------------------------------------------------- AWS
def test_aws_review():
    r = cloud_aws.analyze(cloud_aws.load_files(cloud_aws.demo_files(AS_OF)), cloud_aws.Params(as_of=AS_OF))
    c = counts(r["findings"])
    assert c["AWS-01"] == 1 and c["AWS-02"] == 1 and c["AWS-04"] == 1
    assert c["AWS-09"] == 2 and c["AWS-10"] == 1 and c["AWS-11"] == 2 and c["AWS-13"] == 1
    assert not r["status"]


# ---------------------------------------------------------------- JE
def test_journal_entry_testing():
    res = journal_entry.run_tests(journal_entry.demo_gl(),
                                  journal_entry.Params(holidays=set(pd.to_datetime(
                                      journal_entry.demo_holidays()["date"]).dt.date)))
    c = res["findings"].groupby("test_id").size().to_dict()
    assert c["JE-01"] == 3 and c["JE-02"] == 5 and c["JE-14"] == 4 and c["JE-13"] == 2
    assert res["benford_info"]["over_digits"] == [4]
    assert res["gaps"]["count_missing"].sum() == 4
    assert res["ranking"].iloc[0]["created_by"] == "it.admin"


# ---------------------------------------------------------------- assessments
@pytest.mark.parametrize("key", ["pdpa", "vendor", "ai"])
def test_assessment_scoring_and_template_roundtrip(key):
    bank = assessment.bank_df(assessment_banks.BANKS[key]["bank"])
    assert bank["qid"].is_unique
    ans = assessment_banks.demo_answers(key)
    r = assessment.score(bank, ans)
    assert 0 <= r["overall"] <= 100 and r["completeness"] == 100
    back = assessment.read_answers(io.BytesIO(assessment.template_bytes(bank, "t", ans)), "q.xlsx")
    assert back.set_index("qid")["answer"].equals(ans.set_index("qid")["answer"])


def test_vendor_residual_matrix():
    assert assessment.inherent_tier({"a": 3, "b": 3, "c": 2}) == ("Critical", 8)
    assert assessment.residual_risk("Critical", 85) == "Medium"
    assert assessment.residual_risk("Medium", 30) == "High"


# ---------------------------------------------------------------- tracker
def test_finding_tracker_kpis():
    r = finding_tracker.analyze(finding_tracker.demo_frame(AS_OF), AS_OF)
    k = r["kpi"]
    assert k["total"] == 18 and k["overdue"] == 7 and k["repeat"] == 2
    assert len(finding_tracker.followup_emails(r)) >= 5


# ---------------------------------------------------------------- policy review
def test_policy_review_keyword_mode():
    r = policy_review.review_keywords(policy_review.DEMO_POLICY, ["Access Control Policy", "Backup"])
    st = r.table.set_index("rid")["status"]
    assert st["AC-06"] == "Missing"          # ไม่มี MFA
    assert st["AC-03"] == "Partial"          # ไม่ระบุระยะเวลายกเลิกสิทธิ์
    assert st["AC-04"] == "Covered"          # ทบทวนปีละ 1 ครั้ง
    assert st["BK-05"] == "Missing"          # ไม่มีการทดสอบกู้คืน


# ---------------------------------------------------------------- reports
def test_all_reports_write():
    out = io.BytesIO()
    sod.write_report(sod.analyze(*sod.demo_frames()), out)
    change_mgmt.write_report(change_mgmt.analyze(*change_mgmt.demo_frames()), io.BytesIO())
    login_anomaly.write_report(login_anomaly.analyze(*login_anomaly.demo_frames()), io.BytesIO())
    cloud_aws.write_report(cloud_aws.analyze(cloud_aws.load_files(cloud_aws.demo_files(AS_OF))), io.BytesIO())
    hardening.write_report(hardening.review(hardening.demo_files()), io.BytesIO())
    assert len(out.getvalue()) > 5000
