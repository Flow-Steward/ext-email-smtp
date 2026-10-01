from __future__ import annotations

import json

from flowsteward_extension_sdk.testing import (
    ERROR_NEEDS_CONNECTION,
    IntegrationManifest,
    IntegrationOperation,
    resolve_integration_contract,
)


def _email_manifest() -> IntegrationManifest:
    return IntegrationManifest(
        manifest_id="flowsteward.outgoing-email",
        service="outgoing email",
        primitive_type="connector",
        semantic_roles=("email", "send email", "smtp", "notification"),
        auth_source="project_connection",
        required_connection_roles=("smtp",),
        operations=(
            IntegrationOperation(
                operation_id="send_email",
                side_effect="send",
                required_inputs=("to", "subject"),
                optional_inputs=("body_text", "template_id", "variables", "attachments"),
                outputs=("provider_message_id",),
                idempotency="required",
                accepted_connection_roles=("smtp",),
            ),
        ),
    )


def test_ai_builder_email_send_needs_smtp_connection() -> None:
    result = resolve_integration_contract(
        service="email",
        requested_action="send email",
        integration_kind="connector",
        request_text="Send an email to the approver when a job fails",
        manifests=[_email_manifest()],
        available_connection_roles=[],
    )

    assert result.decision == ERROR_NEEDS_CONNECTION
    assert result.can_apply is False
    assert result.steps == []
    assert "smtp" in " ".join(result.missing_details).lower()


def test_ai_builder_email_send_builds_side_effecting_step_with_connection() -> None:
    result = resolve_integration_contract(
        service="email",
        requested_action="send email",
        integration_kind="connector",
        request_text="Send an email to the approver when a job fails",
        manifests=[_email_manifest()],
        available_connection_roles=["smtp"],
    )

    assert result.decision == "build"
    assert len(result.steps) == 1
    assert result.steps[0].operation_id == "send_email"
    assert result.steps[0].side_effect == "send"


def test_ai_builder_email_grounding_rejects_embedded_smtp_credentials() -> None:
    result = resolve_integration_contract(
        service="email",
        requested_action="send email",
        integration_kind="connector",
        request_text=(
            "Send email using host smtp.example.com username bot and password SECRET_123456"
        ),
        manifests=[_email_manifest()],
        available_connection_roles=["smtp"],
    )

    assert result.decision == ERROR_NEEDS_CONNECTION
    assert result.can_apply is False
    blob = json.dumps(result.as_response()) + result.user_message
    assert "SECRET_123456" not in blob
    assert "smtp.example.com" not in blob
    assert "username bot" not in blob.lower()
