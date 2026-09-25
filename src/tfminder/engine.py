"""Turn a Terraform plan into a decision: allow, needs approval, or deny."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any

import pyrrho  # noqa: F401  (registers pyrrho's analyzers)
from pyrrho import core
from pyrrho.core import Report, Severity
from pyrrho.plan import Plan

from . import gcp  # noqa: F401  (registers gcp-guard)
from .config import Policy


class Decision(str, Enum):
    ALLOW = "allow"  # may be applied without a human (only when policy.auto_apply is on)
    APPROVAL = "approval"  # a human must approve this exact plan
    DENY = "deny"  # an agent cannot apply this plan, approved or not
    NOOP = "noop"  # nothing to apply


@dataclass
class Evaluation:
    decision: Decision
    reasons: list[str]
    report: Report
    counts: dict[str, int]
    changes: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        rep = self.report.to_dict()
        return {
            "decision": self.decision.value,
            "reasons": self.reasons,
            "counts": self.counts,
            "changes": self.changes,
            "worst_severity": rep["worst_severity"],
            "by_severity": rep["by_severity"],
            "findings": rep["findings"],
            "analyzers": rep["analyzers"],
            "plan": rep["plan"],
        }


def review(plan: Plan, analyzers: list[str] | None = None) -> Report:
    chosen = core.resolve(analyzers)
    report = Report(
        plan_path=plan.path,
        plan_digest=plan.digest,
        terraform_version=plan.terraform_version,
        format_version=plan.format_version,
        analyzers=[a.name for a in chosen],
        resources_examined=len(plan.effective_changes),
    )
    for analyzer in chosen:
        report.extend(analyzer.run(plan))
    return report


def evaluate(plan: Plan, policy: Policy, analyzers: list[str] | None = None) -> Evaluation:
    report = review(plan, analyzers)
    changes = plan.effective_changes
    counts = {
        "create": sum(1 for c in changes if c.is_create),
        "update": sum(1 for c in changes if c.is_update),
        "delete": sum(1 for c in changes if c.is_delete),
        "replace": sum(1 for c in changes if c.is_replace),
    }
    summary = [{"address": c.address, "type": c.type, "action": c.summary} for c in changes]

    if not changes:
        return Evaluation(Decision.NOOP, ["plan has no changes"], report, counts, summary)

    deny: list[str] = []
    approval: list[str] = []

    for c in changes:
        if any(fnmatchcase(c.type, pattern) for pattern in policy.deny_types):
            deny.append(f"{c.address}: resource type {c.type} is on the deny list")
        if c.destroys_data and any(fnmatchcase(c.address, pattern) for pattern in policy.protected):
            deny.append(f"{c.address}: protected address would be {c.summary}")

    destroys = counts["delete"] + counts["replace"]
    if policy.max_destroy is not None and destroys > policy.max_destroy:
        deny.append(f"plan destroys or replaces {destroys} resource(s); policy allows {policy.max_destroy}")
    elif destroys and policy.approval_on_destroy:
        approval.append(f"plan destroys or replaces {destroys} resource(s)")

    for f in report.counted:
        line = f"{f.rule_id} {f.severity.value}: {f.title} ({f.resource})"
        if f.severity.rank >= policy.block_at.rank:
            deny.append(line)
        elif f.severity.rank >= policy.approval_at.rank:
            approval.append(line)

    if deny:
        return Evaluation(Decision.DENY, deny + approval, report, counts, summary)
    if approval:
        return Evaluation(Decision.APPROVAL, approval, report, counts, summary)
    if not policy.auto_apply:
        return Evaluation(Decision.APPROVAL, ["policy requires human approval for every apply (auto_apply: false)"],
                          report, counts, summary)
    return Evaluation(Decision.ALLOW, ["no findings above threshold, no destroys"], report, counts, summary)


def severity_of(value: str) -> Severity:
    return Severity.parse(value)
