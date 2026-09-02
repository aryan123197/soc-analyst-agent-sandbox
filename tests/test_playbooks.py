"""Unit tests for Automated Containment & Host Isolation Playbooks Subsystem."""
import pytest
from soc_agent.services import playbooks


def test_block_malicious_iocs():
    ips = ["185.220.101.5", "198.51.100.42"]
    urls = ["http://malicious-login-update.com"]

    rules = playbooks.block_malicious_iocs(ips, urls)
    assert len(rules) == 3
    assert rules[0].target_type == "ip"
    assert rules[0].target_value == "185.220.101.5"
    assert rules[0].action == "DENY"
    assert rules[2].target_type == "url"
    assert rules[2].action == "BLOCK"


def test_revoke_user_credentials():
    res = playbooks.revoke_user_credentials("attacker@malicious.com", "case-123")
    assert res.target_user == "attacker@malicious.com"
    assert res.tokens_revoked == 3
    assert res.account_status == "SUSPENDED"
    assert res.revocation_ticket_id.startswith("REV-")


def test_isolate_endpoint_host():
    res = playbooks.isolate_endpoint_host("john.doe@company.org", "case-456")
    assert res.isolation_status == "HOST_CONTAINED"
    assert res.network_traffic_allowed == "SOC_MANAGEMENT_ONLY"
    assert "WORKSTATION-" in res.hostname
    assert "Falcon" in res.provider


def test_execute_containment_playbooks_severity_gate():
    low_res = playbooks.execute_containment_playbooks(
        case_id="case-low", severity="low", sender="user@example.com"
    )
    assert low_res.executed is False

    med_res = playbooks.execute_containment_playbooks(
        case_id="case-med", severity="medium", sender="user@example.com"
    )
    assert med_res.executed is False


def test_execute_containment_playbooks_critical():
    threat_intel = {"ips_found": ["185.220.101.5"], "urls_found": ["http://malicious-login-update.com"]}
    sandbox_report = {"overall_risk_score": 95}

    summary = playbooks.execute_containment_playbooks(
        case_id="case-critical",
        severity="critical",
        sender="compromised-user@corp.example",
        threat_intel=threat_intel,
        sandbox_report=sandbox_report,
    )

    assert summary.executed is True
    assert len(summary.firewall_rules) >= 2
    assert len(summary.credential_revocations) == 1
    assert len(summary.endpoint_isolations) == 1
    assert summary.endpoint_isolations[0].isolation_status == "HOST_CONTAINED"
