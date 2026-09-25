from conftest import change, make_plan

from pyrrho.core import Severity
from tfminder.config import Policy
from tfminder.engine import Decision, evaluate

LABEL = {"name": "x", "labels": {"a": "1"}}


def test_noop():
    assert evaluate(make_plan(), Policy()).decision == Decision.NOOP


def test_clean_plan_needs_approval_unless_auto_apply():
    plan = make_plan(change("google_pubsub_topic.t", ["create"], None, LABEL))
    assert evaluate(plan, Policy()).decision == Decision.APPROVAL
    assert evaluate(plan, Policy(auto_apply=True)).decision == Decision.ALLOW


def test_critical_finding_denies():
    plan = make_plan(change("google_storage_bucket_iam_member.p", ["create"], None,
                            {"role": "roles/storage.objectViewer", "member": "allUsers"}))
    ev = evaluate(plan, Policy(auto_apply=True))
    assert ev.decision == Decision.DENY
    assert any("GC001" in r for r in ev.reasons)


def test_high_finding_needs_approval():
    plan = make_plan(change("google_project_iam_member.o", ["create"], None,
                            {"role": "roles/editor", "member": "user:a@b.com"}))
    assert evaluate(plan, Policy(auto_apply=True)).decision == Decision.APPROVAL
    assert evaluate(plan, Policy(block_at=Severity.HIGH)).decision == Decision.DENY


def test_max_destroy_and_protected():
    plan = make_plan(change("google_pubsub_topic.t", ["delete"], LABEL, None))
    assert evaluate(plan, Policy(max_destroy=0)).decision == Decision.DENY
    assert evaluate(plan, Policy(max_destroy=1)).decision == Decision.APPROVAL
    assert evaluate(plan, Policy(protected=("google_pubsub_topic.*",))).decision == Decision.DENY
    assert evaluate(plan, Policy(auto_apply=True, approval_on_destroy=False)).decision == Decision.ALLOW


def test_deny_types():
    plan = make_plan(change("google_pubsub_topic.t", ["create"], None, LABEL))
    assert evaluate(plan, Policy(deny_types=("google_pubsub_*",))).decision == Decision.DENY
