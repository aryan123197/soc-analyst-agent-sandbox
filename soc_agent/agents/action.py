"""Action agent — the only agent with write permission, gated by Agent Gateway.

Decides what to do based on triage severity, then calls through the gateway
(soc_agent.services.gateway) which enforces identity + allowed-action policy.
"""
from soc_agent.services import connectors, gateway, playbooks, store, trace

_SEVERITY_TO_ACTION = {
    "critical": "containment",
    "high": "escalated",
    "medium": "notified",
    "low": "closed",
}

AGENT_IDENTITY = gateway.ALLOWED_IDENTITY


def act(case_id: str, severity: str, tr: trace.Trace) -> gateway.ActionRecord:
    action_type = _SEVERITY_TO_ACTION.get(severity, "notified")

    record = gateway.execute_action(actor_identity=AGENT_IDENTITY, action_type=action_type)

    case_store = store.get_case_store()
    c = case_store.get_case(case_id) or {}
    sender = c.get("sender", "unknown@corp.example")
    triage_info = c.get("triage") or {}
    category = triage_info.get("category", "unclassified")
    reasoning = triage_info.get("reasoning", f"Actioned as {action_type} for severity {severity}")
    threat_intel_info = c.get("threat_intel")
    sandbox_info = c.get("sandbox_report")

    # Orchestrate active containment playbooks if severity is high or critical
    containment_summary = playbooks.execute_containment_playbooks(
        case_id=case_id,
        severity=severity,
        sender=sender,
        threat_intel=threat_intel_info,
        sandbox_report=sandbox_info,
    )

    integrations_record = connectors.dispatch_outbound_integrations(
        case_id=case_id,
        severity=severity,
        category=category,
        reasoning=reasoning,
        threat_intel=threat_intel_info,
        tr=tr,
    )

    case_store.update_case(
        case_id,
        {
            "status": "actioned",
            "action_taken": record.to_dict(),
            "integrations": integrations_record,
            "containment_playbooks": containment_summary.to_dict(),
        },
    )
    tr.log(
        "action",
        f"executed action={action_type} via gateway as {AGENT_IDENTITY}. "
        f"Containment playbooks executed: {containment_summary.executed}"
    )

    return record




def quarantine(case_id: str, threat_type: str, tr: trace.Trace) -> None:
    """Called when Model Armor blocks content — no gateway call, no external action."""
    case_store = store.get_case_store()
    case_store.update_case(case_id, {"status": "quarantined"})
    tr.log("action", f"case quarantined, no gateway call made (threat_type={threat_type})")
