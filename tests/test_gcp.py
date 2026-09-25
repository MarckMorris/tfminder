import json

from conftest import change, make_plan

from tfminder.gcp import GcpGuard


def ids(plan):
    return sorted(f.rule_id for f in GcpGuard().run(plan))


def test_public_iam_member_is_critical():
    plan = make_plan(change("google_storage_bucket_iam_member.pub", ["create"], None,
                            {"bucket": "b", "role": "roles/storage.objectViewer", "member": "allUsers"}))
    findings = GcpGuard().run(plan)
    assert [f.rule_id for f in findings] == ["GC001"]
    assert findings[0].severity.value == "critical"


def test_existing_public_binding_untouched_is_not_blamed():
    state = {"role": "roles/run.invoker", "members": ["allUsers"], "service": "api"}
    tagged = dict(state, service="api")
    plan = make_plan(change("google_cloud_run_v2_service_iam_binding.inv", ["update"], state, tagged))
    assert ids(plan) == []


def test_member_added_to_binding():
    before = {"role": "roles/owner", "members": ["user:a@x.com"]}
    after = {"role": "roles/owner", "members": ["user:a@x.com", "user:b@x.com"]}
    plan = make_plan(change("google_project_iam_binding.owners", ["update"], before, after))
    findings = GcpGuard().run(plan)
    assert [f.rule_id for f in findings] == ["GC002"]
    assert findings[0].evidence["member"] == "user:b@x.com"


def test_escalation_role():
    plan = make_plan(change("google_project_iam_member.tc", ["create"], None,
                            {"role": "roles/iam.serviceAccountTokenCreator", "member": "user:x@y.com"}))
    assert ids(plan) == ["GC003"]


def test_authoritative_policy():
    policy = json.dumps({"bindings": [{"role": "roles/viewer", "members": ["group:g@x.com"]}]})
    plan = make_plan(change("google_project_iam_policy.p", ["create"], None, {"policy_data": policy}))
    assert ids(plan) == ["GC004"]


def test_firewall_ssh_opened_to_world():
    before = {"direction": "INGRESS", "source_ranges": ["10.0.0.0/8"], "allow": [{"protocol": "tcp", "ports": ["22"]}]}
    after = dict(before, source_ranges=["0.0.0.0/0"])
    plan = make_plan(change("google_compute_firewall.ssh", ["update"], before, after))
    assert ids(plan) == ["GC006"]


def test_firewall_already_open_not_blamed():
    fw = {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}],
          "description": "a"}
    plan = make_plan(change("google_compute_firewall.ssh", ["update"], fw, dict(fw, description="b")))
    assert ids(plan) == []


def test_firewall_https_is_fine_and_range_catches_sensitive():
    https = {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["443"]}]}
    assert ids(make_plan(change("google_compute_firewall.web", ["create"], None, https))) == []
    wide = dict(https, allow=[{"protocol": "tcp", "ports": ["3000-3400"]}])
    assert ids(make_plan(change("google_compute_firewall.w", ["create"], None, wide))) == ["GC006"]


def test_firewall_all_protocols():
    fw = {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "all", "ports": []}]}
    assert ids(make_plan(change("google_compute_firewall.any", ["create"], None, fw))) == ["GC006"]


def test_firewall_egress_and_disabled_ignored():
    fw = {"direction": "EGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "all"}]}
    assert ids(make_plan(change("google_compute_firewall.e", ["create"], None, fw))) == []
    fw = {"direction": "INGRESS", "disabled": True, "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "all"}]}
    assert ids(make_plan(change("google_compute_firewall.d", ["create"], None, fw))) == []


def test_firewall_unknown_ranges():
    fw = {"direction": "INGRESS", "allow": [{"protocol": "tcp", "ports": ["22"]}]}
    plan = make_plan(change("google_compute_firewall.u", ["create"], None, fw, {"source_ranges": True}))
    assert ids(plan) == ["GC005"]


def test_stateful_destroy_and_replace():
    ds = {"dataset_id": "analytics"}
    assert ids(make_plan(change("google_bigquery_dataset.a", ["delete"], ds, None))) == ["GC010"]
    assert ids(make_plan(change("google_bigquery_dataset.a", ["delete", "create"], ds, ds))) == ["GC010"]


def test_types_pyrrho_covers_are_not_duplicated():
    from tfminder.engine import review

    sql = {"name": "db", "deletion_protection": False}
    plan = make_plan(change("google_sql_database_instance.db", ["delete"], sql, None))
    assert ids(plan) == []
    assert [f.rule_id for f in review(plan).findings if f.resource.endswith(".db")] == ["RD001"]


def test_gke_destroy_is_high():
    f = GcpGuard().run(make_plan(change("google_container_cluster.c", ["delete"], {"name": "c"}, None)))
    assert [(x.rule_id, x.severity.value) for x in f] == [("GC011", "high")]


def test_deletion_protection_off():
    plan = make_plan(change("google_container_cluster.gke", ["update"],
                            {"deletion_protection": True}, {"deletion_protection": False}))
    assert ids(plan) == ["GC012"]


def test_bucket_weakened():
    before = {"public_access_prevention": "enforced", "force_destroy": False, "versioning": [{"enabled": True}],
              "retention_policy": [{"retention_period": 86400, "is_locked": False}]}
    after = {"public_access_prevention": "inherited", "force_destroy": True, "versioning": [{"enabled": False}],
             "retention_policy": []}
    plan = make_plan(change("google_storage_bucket.logs", ["update"], before, after))
    assert ids(plan) == ["GC013", "GC014", "GC015", "GC016"]


def test_sql_opened_and_backups_off():
    before = {"settings": [{"ip_configuration": [{"ipv4_enabled": True, "authorized_networks": []}],
                            "backup_configuration": [{"enabled": True}]}]}
    after = {"settings": [{"ip_configuration": [{"ipv4_enabled": True, "authorized_networks": [
        {"name": "all", "value": "0.0.0.0/0"}]}], "backup_configuration": [{"enabled": False}]}]}
    plan = make_plan(change("google_sql_database_instance.db", ["update"], before, after))
    assert ids(plan) == ["GC017", "GC018"]


def test_gke_endpoint_public():
    before = {"private_cluster_config": [{"enable_private_endpoint": True}],
              "master_authorized_networks_config": [{"cidr_blocks": [{"cidr_block": "10.0.0.0/8"}]}]}
    after = {"private_cluster_config": [{"enable_private_endpoint": False}], "master_authorized_networks_config": []}
    plan = make_plan(change("google_container_cluster.c", ["update"], before, after))
    assert ids(plan) == ["GC019", "GC020"]


def test_sa_key():
    plan = make_plan(change("google_service_account_key.k", ["create"], None, {"service_account_id": "sa"}))
    assert ids(plan) == ["GC009"]


def test_non_google_resources_ignored():
    plan = make_plan(change("aws_s3_bucket.b", ["delete"], {"bucket": "b"}, None))
    assert ids(plan) == []
