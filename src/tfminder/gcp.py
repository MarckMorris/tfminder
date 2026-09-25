"""Google Cloud rules for the pyrrho engine.

pyrrho's own analyzers are AWS-first. This module adds a ``gcp-guard``
analyzer written the same way: every rule compares the prior state with the
planned state, so a plan is only blamed for what *it* changes. A firewall that
has been open for two years is not this pull request's problem; opening it is.

Rule IDs use the ``GC`` prefix so they never collide with pyrrho's.
Attribute names follow the hashicorp/google provider schema (v5/v6).
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from pyrrho.core import Analyzer, Finding, Severity, register
from pyrrho.analyzers import real_diff
from pyrrho.plan import Plan, ResourceChange

# pyrrho's real-diff analyzer already covers these (RD001/RD002, RD004). Skipping
# them here keeps one finding per problem instead of two.
_PYRRHO_STATEFUL = set(getattr(real_diff, "STATEFUL", {}))
_PYRRHO_GUARDED = {t for t, attrs in getattr(real_diff, "GUARDS", {}).items() if "deletion_protection" in attrs}

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
ESCALATION_ROLES = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.securityAdmin",
    "roles/iam.roleAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.folderIamAdmin",
    "roles/resourcemanager.organizationAdmin",
}
WORLD = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC",
    1433: "SQL Server", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 9042: "Cassandra", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
    2375: "Docker API", 2379: "etcd", 5601: "Kibana", 8080: "HTTP admin", 10250: "Kubelet",
}
DATA_STORES = {
    "google_sql_database_instance", "google_sql_database", "google_storage_bucket",
    "google_bigquery_dataset", "google_bigquery_table", "google_compute_disk", "google_compute_region_disk",
    "google_spanner_instance", "google_spanner_database", "google_bigtable_instance", "google_bigtable_table",
    "google_firestore_database", "google_filestore_instance", "google_redis_instance",
    "google_alloydb_cluster", "google_alloydb_instance", "google_kms_crypto_key", "google_kms_key_ring",
}
CRITICAL_INFRA = {
    "google_container_cluster": "the GKE cluster and every workload on it",
    "google_secret_manager_secret": "the secret and all of its versions",
    "google_logging_project_sink": "the log export (audit trail)",
    "google_logging_organization_sink": "the organization log export (audit trail)",
    "google_logging_folder_sink": "the folder log export (audit trail)",
    "google_compute_network": "the VPC network",
    "google_dns_managed_zone": "the DNS zone and every record in it",
}
DELETION_PROTECTED = {
    "google_sql_database_instance", "google_container_cluster", "google_bigquery_table",
    "google_compute_instance", "google_spanner_database", "google_alloydb_cluster",
    "google_bigtable_instance", "google_firestore_database",
}


def _first(value: Any) -> dict[str, Any]:
    """Nested blocks are lists of one mapping in plan JSON; return that mapping or {}."""
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    if isinstance(value, dict):
        return value
    return {}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _iam_pairs(rc_state: dict[str, Any], rc_type: str) -> set[tuple[str, str]]:
    """(role, member) pairs a single IAM resource grants in one snapshot."""
    if not rc_state:
        return set()
    if rc_type.endswith("_iam_member"):
        role, member = rc_state.get("role"), rc_state.get("member")
        return {(str(role), str(member))} if role and member else set()
    if rc_type.endswith("_iam_binding"):
        role = rc_state.get("role")
        return {(str(role), str(m)) for m in _list(rc_state.get("members"))} if role else set()
    if rc_type.endswith("_iam_policy"):
        raw = rc_state.get("policy_data")
        try:
            doc = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except json.JSONDecodeError:
            return set()
        pairs = set()
        for binding in _list(doc.get("bindings")):
            if isinstance(binding, dict):
                for member in _list(binding.get("members")):
                    pairs.add((str(binding.get("role")), str(member)))
        return pairs
    return set()


def _is_iam(rc: ResourceChange) -> bool:
    return rc.type.startswith("google_") and rc.type.endswith(("_iam_member", "_iam_binding", "_iam_policy"))


def _ports(allow: Iterable[Any]) -> tuple[set[int], bool]:
    """Ports opened by a firewall's allow blocks. The bool is True for 'every port'."""
    ports: set[int] = set()
    everything = False
    for block in allow:
        if not isinstance(block, dict):
            continue
        proto = str(block.get("protocol", "")).lower()
        if proto not in ("tcp", "udp", "all", "sctp"):
            continue  # icmp, esp, ah...: no ports
        raw_ports = _list(block.get("ports"))
        if proto == "all" or not raw_ports:
            everything = True
            continue
        for spec in raw_ports:
            spec = str(spec)
            if "-" in spec:
                lo, _, hi = spec.partition("-")
                if lo.isdigit() and hi.isdigit():
                    lo_i, hi_i = int(lo), int(hi)
                    if hi_i - lo_i >= 1000:
                        everything = True
                    ports.update(p for p in SENSITIVE_PORTS if lo_i <= p <= hi_i)
                    ports.update(range(lo_i, min(hi_i, lo_i + 1000) + 1))
            elif spec.isdigit():
                ports.add(int(spec))
    return ports, everything


def _world_exposure(state: dict[str, Any]) -> tuple[set[int], bool]:
    if not state or state.get("disabled"):
        return set(), False
    if str(state.get("direction") or "INGRESS").upper() != "INGRESS":
        return set(), False
    if not WORLD & set(map(str, _list(state.get("source_ranges")))):
        return set(), False
    return _ports(_list(state.get("allow")))


@register
class GcpGuard(Analyzer):
    name = "gcp-guard"
    description = "Google Cloud: public IAM, primitive roles, open firewalls, data loss and weakened protections"

    def run(self, plan: Plan) -> list[Finding]:
        out: list[Finding] = []
        for rc in plan.effective_changes:
            if not rc.type.startswith("google_"):
                continue
            if _is_iam(rc):
                out.extend(self._iam(rc))
            if rc.type == "google_compute_firewall":
                out.extend(self._firewall(rc))
            if rc.destroys_data:
                out.extend(self._destruction(rc))
            if rc.type in DELETION_PROTECTED:
                out.extend(self._deletion_protection(rc))
            if rc.type == "google_storage_bucket":
                out.extend(self._bucket(rc))
            if rc.type == "google_sql_database_instance":
                out.extend(self._sql(rc))
            if rc.type == "google_container_cluster":
                out.extend(self._gke(rc))
            if rc.type == "google_service_account_key" and (rc.is_create or rc.is_replace):
                out.append(self.finding(
                    "GC009", "Long-lived service account key created", Severity.MEDIUM, rc.address,
                    "This creates a downloadable JSON key. It never expires by default and is the most common "
                    "way GCP credentials leak.",
                    {"service_account_id": rc.value("service_account_id")},
                    "Use Workload Identity Federation or service account impersonation instead of keys.",
                ))
        return out

    # -- IAM ----------------------------------------------------------------

    def _iam(self, rc: ResourceChange) -> list[Finding]:
        before = _iam_pairs(rc.before, rc.type) if not rc.is_create else set()
        after = _iam_pairs(rc.after, rc.type) if not rc.is_delete else set()
        added = sorted(after - before)
        out: list[Finding] = []
        for role, member in added:
            if member in PUBLIC_MEMBERS:
                out.append(self.finding(
                    "GC001", "Resource made public through IAM", Severity.CRITICAL, rc.address,
                    f"Grants {role} to {member}: anyone on the internet"
                    + (" with a Google account" if member == "allAuthenticatedUsers" else "") + ".",
                    {"role": role, "member": member, "resource_type": rc.type},
                    "Grant the role to a specific group or service account. If this is meant to be public, "
                    "record the decision with a baseline entry.",
                    key=f"{role}|{member}",
                ))
            elif role in PRIMITIVE_ROLES:
                out.append(self.finding(
                    "GC002", "Primitive role granted", Severity.HIGH, rc.address,
                    f"Grants {role} to {member}. Primitive roles cover thousands of permissions across every "
                    "service in the scope.",
                    {"role": role, "member": member, "resource_type": rc.type},
                    "Grant the predefined role for the job instead (for example roles/storage.objectAdmin).",
                    key=f"{role}|{member}",
                ))
            elif role in ESCALATION_ROLES:
                out.append(self.finding(
                    "GC003", "Privilege-escalation role granted", Severity.HIGH, rc.address,
                    f"{role} lets {member} act as other identities or rewrite IAM, which leads to owner.",
                    {"role": role, "member": member, "resource_type": rc.type},
                    "Scope the grant to a single service account resource instead of the project, or use "
                    "short-lived impersonation with an approval flow.",
                    key=f"{role}|{member}",
                ))
        if rc.type.endswith("_iam_policy") and not rc.is_delete:
            removed = sorted(before - after)
            out.append(self.finding(
                "GC004", "Authoritative IAM policy written", Severity.HIGH, rc.address,
                "This resource replaces the whole IAM policy of its target. Any binding not in the file, "
                "including ones Google adds for service agents, is removed.",
                {"bindings_removed": [f"{r} {m}" for r, m in removed][:20], "bindings_after": len(after)},
                "Prefer *_iam_member or *_iam_binding. Authoritative policies can lock you out of a project.",
            ))
        return out

    # -- Network ------------------------------------------------------------

    def _firewall(self, rc: ResourceChange) -> list[Finding]:
        if rc.is_delete:
            return []
        if rc.is_unknown("source_ranges") or rc.is_unknown("allow"):
            return [self.finding(
                "GC005", "Firewall exposure cannot be verified before apply", Severity.MEDIUM, rc.address,
                "source_ranges or allow is only known after apply, so nobody can review what it opens.",
                {"unknown": rc.unknown_keys()},
                "Make the ranges static or reviewable (variables resolved at plan time).",
            )]
        before_ports, before_all = _world_exposure(rc.before) if not rc.is_create else (set(), False)
        after_ports, after_all = _world_exposure(rc.after)
        new_sensitive = sorted(p for p in (after_ports - before_ports) if p in SENSITIVE_PORTS)
        if after_all and not before_all:
            new_sensitive = sorted(SENSITIVE_PORTS)
        out: list[Finding] = []
        if new_sensitive:
            out.append(self.finding(
                "GC006", "Administrative or data port opened to the internet", Severity.CRITICAL, rc.address,
                "Ingress from 0.0.0.0/0 now reaches " + ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in new_sensitive[:8])
                + ("" if len(new_sensitive) <= 8 else ", ..."),
                {"source_ranges": _list(rc.value("source_ranges")), "allow": _list(rc.value("allow")),
                 "all_ports": after_all, "network": rc.value("network")},
                "Restrict source_ranges to your VPN/IAP range (35.235.240.0/20 for IAP TCP forwarding).",
            ))
        elif (after_ports - before_ports) - {80, 443}:
            extra = sorted((after_ports - before_ports) - {80, 443})
            out.append(self.finding(
                "GC007", "Non-web port opened to the internet", Severity.MEDIUM, rc.address,
                f"Ingress from 0.0.0.0/0 now reaches port(s) {', '.join(map(str, extra[:10]))}.",
                {"source_ranges": _list(rc.value("source_ranges")), "ports": extra[:50]},
                "Confirm the service is meant to be public, or restrict the source ranges.",
            ))
        return out

    # -- Data loss ----------------------------------------------------------

    def _destruction(self, rc: ResourceChange) -> list[Finding]:
        how = "replaces (destroys, then recreates empty)" if rc.is_replace else "destroys"
        if rc.type in _PYRRHO_STATEFUL:
            return []
        if rc.type in DATA_STORES:
            detail = f"This plan {how} {rc.type.replace('google_', '').replace('_', ' ')} and the data in it."
            if rc.type.startswith("google_kms"):
                detail += " Anything encrypted with this key becomes unreadable."
            return [self.finding(
                "GC010", "Stateful resource destroyed", Severity.CRITICAL, rc.address, detail,
                {"actions": list(rc.actions), "replace_paths": [list(p) for p in rc.replace_paths],
                 "action_reason": rc.action_reason},
                "If this is a rename, use a moved {} block. If a replace is forced by an immutable attribute, "
                "check replace_paths and migrate the data first.",
            )]
        if rc.type in CRITICAL_INFRA:
            return [self.finding(
                "GC011", "Critical infrastructure destroyed", Severity.HIGH, rc.address,
                f"This plan {how} {CRITICAL_INFRA[rc.type]}.",
                {"actions": list(rc.actions), "replace_paths": [list(p) for p in rc.replace_paths]},
                "Confirm this is intended; use moved {} for renames.",
            )]
        return []

    def _deletion_protection(self, rc: ResourceChange) -> list[Finding]:
        if rc.is_delete or rc.is_create or rc.type in _PYRRHO_GUARDED:
            return []
        if rc.prior("deletion_protection") is True and rc.value("deletion_protection") is False:
            return [self.finding(
                "GC012", "Deletion protection turned off", Severity.HIGH, rc.address,
                "deletion_protection goes from true to false. This is usually the step before a destroy.",
                {"before": True, "after": False},
                "Keep it on. Turn it off in a separate, explicitly reviewed change right before a planned deletion.",
                key="deletion_protection",
            )]
        return []

    def _bucket(self, rc: ResourceChange) -> list[Finding]:
        if rc.is_delete:
            return []
        out: list[Finding] = []
        was = {} if rc.is_create else rc.before
        if str(was.get("public_access_prevention")) == "enforced" and \
                str(rc.value("public_access_prevention")) != "enforced":
            out.append(self.finding(
                "GC013", "Bucket public access prevention removed", Severity.HIGH, rc.address,
                "public_access_prevention is no longer 'enforced', so IAM can now make this bucket public.",
                {"before": "enforced", "after": rc.value("public_access_prevention")},
                "Keep public_access_prevention = \"enforced\" unless the bucket serves public content.",
                key="pap",
            ))
        if rc.value("force_destroy") is True and was.get("force_destroy") is not True:
            out.append(self.finding(
                "GC014", "Bucket force_destroy enabled", Severity.MEDIUM, rc.address,
                "force_destroy lets Terraform delete the bucket even when it still holds objects.",
                {"force_destroy": True},
                "Leave force_destroy off for buckets that hold data you care about.",
                key="force_destroy",
            ))
        if _first(was.get("versioning")).get("enabled") is True and \
                _first(rc.value("versioning")).get("enabled") is False:
            out.append(self.finding(
                "GC015", "Bucket versioning disabled", Severity.MEDIUM, rc.address,
                "Object versioning goes from enabled to disabled; overwritten or deleted objects can no longer "
                "be recovered.",
                {"before": True, "after": False},
                "Keep versioning on and use lifecycle rules to control cost.",
                key="versioning",
            ))
        if _first(was.get("retention_policy")) and not _first(rc.value("retention_policy")):
            out.append(self.finding(
                "GC016", "Bucket retention policy removed", Severity.HIGH, rc.address,
                "The retention policy is removed, so objects can be deleted before the retention period.",
                {"before": _first(was.get("retention_policy"))},
                "Retention policies usually back a compliance requirement; confirm with its owner.",
                key="retention",
            ))
        return out

    def _sql(self, rc: ResourceChange) -> list[Finding]:
        if rc.is_delete:
            return []
        was = {} if rc.is_create else rc.before
        before_ip = _first(_first(was.get("settings")).get("ip_configuration"))
        after_ip = _first(_first(rc.value("settings")).get("ip_configuration"))
        out: list[Finding] = []

        def nets(ipc: dict[str, Any]) -> set[str]:
            return {str(n.get("value")) for n in _list(ipc.get("authorized_networks")) if isinstance(n, dict)}

        opened = (nets(after_ip) - nets(before_ip)) & WORLD
        if opened:
            out.append(self.finding(
                "GC017", "Cloud SQL open to the internet", Severity.CRITICAL, rc.address,
                "An authorized network of 0.0.0.0/0 lets any address reach the database's public IP.",
                {"authorized_networks": sorted(nets(after_ip)), "ipv4_enabled": after_ip.get("ipv4_enabled")},
                "Use private IP, or the Cloud SQL Auth Proxy with IAM authentication.",
                key="authorized_networks",
            ))
        before_bk = _first(_first(was.get("settings")).get("backup_configuration"))
        after_bk = _first(_first(rc.value("settings")).get("backup_configuration"))
        if before_bk.get("enabled") is True and after_bk.get("enabled") is False:
            out.append(self.finding(
                "GC018", "Cloud SQL backups disabled", Severity.HIGH, rc.address,
                "Automated backups go from enabled to disabled; point-in-time recovery is lost with them.",
                {"before": before_bk, "after": after_bk},
                "Keep backups on; tune retained_backups for cost.",
                key="backups",
            ))
        return out

    def _gke(self, rc: ResourceChange) -> list[Finding]:
        if rc.is_delete or rc.is_create:
            return []
        out: list[Finding] = []
        if _first(rc.before.get("private_cluster_config")).get("enable_private_endpoint") is True and \
                _first(rc.value("private_cluster_config")).get("enable_private_endpoint") is not True:
            out.append(self.finding(
                "GC019", "GKE control plane made public", Severity.HIGH, rc.address,
                "enable_private_endpoint goes from true to false: the Kubernetes API gets a public endpoint.",
                {"before": True, "after": _first(rc.value("private_cluster_config")).get("enable_private_endpoint")},
                "Keep the private endpoint, or at least restrict master_authorized_networks_config.",
                key="private_endpoint",
            ))
        if _first(rc.before.get("master_authorized_networks_config")) and \
                not _first(rc.value("master_authorized_networks_config")):
            out.append(self.finding(
                "GC020", "GKE master authorized networks removed", Severity.HIGH, rc.address,
                "The allow-list in front of the Kubernetes API is removed.",
                {"before": _first(rc.before.get("master_authorized_networks_config"))},
                "Keep master_authorized_networks_config with your admin ranges.",
                key="man",
            ))
        return out
