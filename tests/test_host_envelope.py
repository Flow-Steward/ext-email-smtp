"""The final extension_host_v2 envelope and execution scope."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
import smtp_extension

from tests.test_smtp_extension import (
    FOR_EACH_STEP_SCOPE,
    GROUP_STEP_SCOPE,
    NO_STEP_SCOPE,
    ROOT_STEP_SCOPE,
    _payload,
)


def _attachment_payload(scope: dict[str, Any]) -> dict[str, Any]:
    return _payload(
        {
            "to": "alice@example.com",
            "subject": "Invoice",
            "body_text": "Your invoice is attached.",
            "attachments": [
                {
                    "artifact_id": "art_pdf",
                    "filename": "invoice.pdf",
                    "content_type": "application/pdf",
                }
            ],
        },
        scope=scope,
    )


def _notification_payload(event: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
    return {
        "contract_version": "extension_host_v2",
        "runtime_context": dict(scope),
        "action": "deliver_notification",
        "action_payload": {
            "action_id": "deliver_notification",
            "target": {
                "connection": {
                    "connection_id": "conn_smtp",
                    "config": {
                        "provider": "custom_smtp",
                        "host": "smtp.example.com",
                        "port": 587,
                        "security": "starttls",
                        "username": "mailer",
                        "from_email": "robot@example.com",
                    },
                    "secrets": {"password": "secret-password"},
                }
            },
        },
        "event": event,
        "route": {"route_config": {"to": "ops@example.com"}},
    }


@pytest.mark.parametrize(
    "scope",
    [ROOT_STEP_SCOPE, GROUP_STEP_SCOPE, FOR_EACH_STEP_SCOPE],
    ids=["root", "group", "for_each"],
)
def test_send_email_with_an_artifact_runs_for_every_final_scope_owner(
    monkeypatch: pytest.MonkeyPatch, scope: dict[str, Any]
) -> None:
    streamed: list[Any] = []

    def stream(descriptor: Any, *_args: Any, **_kwargs: Any):
        streamed.append(descriptor)
        return iter([b"%PDF-1.7 invoice"])

    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "stream_artifact_bytes", stream)
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)

    response = smtp_extension.handle_payload(_attachment_payload(scope))

    assert response["ok"] is True
    assert response["delivered"] is True
    assert response["attachment_count"] == 1
    assert len(streamed) == 1
    message = send.call_args.args[1]
    [attachment] = list(message.iter_attachments())
    assert attachment.get_filename() == "invoice.pdf"
    assert attachment.get_content() == b"%PDF-1.7 invoice"


@pytest.mark.parametrize(
    ("contract_version", "scope", "reason"),
    [
        ("extension_host_v1", FOR_EACH_STEP_SCOPE, "Unsupported host contract"),
        ("", FOR_EACH_STEP_SCOPE, "Unsupported host contract"),
        (None, FOR_EACH_STEP_SCOPE, "Unsupported host contract"),
        (
            "extension_host_v2",
            {k: v for k, v in FOR_EACH_STEP_SCOPE.items() if k != "for_each_id"},
            "misses execution scope",
        ),
        (
            "extension_host_v2",
            {**FOR_EACH_STEP_SCOPE, "group_id": "notify_customers"},
            "both a Group and a For each",
        ),
        (
            "extension_host_v2",
            {**ROOT_STEP_SCOPE, "step_execution_id": None},
            "without its logical execution",
        ),
    ],
)
@pytest.mark.parametrize("operation", ["send_email", "deliver_notification"])
def test_foreign_or_incomplete_envelope_is_refused_before_any_effect(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    contract_version: str | None,
    scope: dict[str, Any],
    reason: str,
) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("a refused envelope must not read, connect or send")

    for name in ("stream_artifact_bytes", "_send_smtp", "_connection_config", "send_email"):
        monkeypatch.setattr(smtp_extension, name, forbidden)
    if operation == "send_email":
        payload = _attachment_payload(scope)
    else:
        payload = _notification_payload({"event_type": "job.failed"}, scope)
        payload["runtime_context"] = dict(scope)
    if contract_version is None:
        payload.pop("contract_version")
    else:
        payload["contract_version"] = contract_version

    response = smtp_extension.handle_payload(payload)

    assert response["ok"] is False
    assert response["delivered"] is False
    assert response["error_code"] == "invalid_host_envelope"
    assert reason in response["error"]
    assert response["definitely_no_external_effect"] is True


@pytest.mark.parametrize(
    ("event", "expected", "absent"),
    [
        # Workflow-level event: all four scope keys null.
        (
            {"workflow_id": "order_sync", "payload": {"message": "Done."}},
            ["Workflow: order_sync"],
            ["Group:", "For each:", "Step:"],
        ),
        # Group-level event names only its container.
        (
            {
                "group_id": "notify_customers",
                "payload": {
                    "message": "Group failed.",
                    "workflow_display_name": "Order sync",
                    "group_label": "Notify customers",
                },
            },
            ["Workflow: Order sync", "Group: Notify customers"],
            ["For each:", "Step:"],
        ),
        # Root step: no owner, so no Group line and no root label.
        (
            {"payload": {"message": "Failed.", "step_id": "send_email", "group_id": None}},
            ["Step: send_email"],
            ["Group:", "For each:"],
        ),
        # Step in a For each: never a Group line, even with a stale label.
        (
            {
                "payload": {
                    "message": "Failed.",
                    "for_each_id": "each_customer",
                    "for_each_label": "Each customer",
                    "group_label": "Stale group",
                    "step_id": "send_email",
                    "step_label": "Send email",
                    "phase_label": "Review",
                }
            },
            ["For each: Each customer", "Step: Send email"],
            ["Group:", "Phase"],
        ),
    ],
    ids=["workflow", "group", "root-step", "for-each-step"],
)
def test_notification_body_names_only_the_final_scope_levels(
    monkeypatch: pytest.MonkeyPatch,
    event: dict[str, Any],
    expected: list[str],
    absent: list[str],
) -> None:
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)

    response = smtp_extension.handle_payload(
        _notification_payload({"event_type": "job.step_failed", **event}, NO_STEP_SCOPE)
    )

    assert response["ok"] is True
    body = send.call_args.args[1].get_content()
    assert body.startswith(event["payload"]["message"])
    for line in expected:
        assert line in body
    for line in absent:
        assert line not in body


def test_core_standard_email_lines_are_not_repeated(monkeypatch: pytest.MonkeyPatch) -> None:
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)
    standard = (
        "❌ Step failed\n\nWorkflow: Order sync\nGroup: Notify customers\n"
        "Step: send_email\n\nSent by Flow Steward.\n"
    )

    smtp_extension.handle_payload(
        _notification_payload(
            {
                "event_type": "job.step_failed",
                "group_id": "notify_customers",
                "step_id": "send_email",
                "payload": {
                    "message": standard,
                    "workflow_display_name": "Order sync",
                    "group_label": "Notify customers",
                },
            },
            NO_STEP_SCOPE,
        )
    )

    body = send.call_args.args[1].get_content()
    for line in ("Workflow: Order sync", "Group: Notify customers", "Step: send_email"):
        assert body.count(line) == 1


def test_bundle_carries_a_valid_logo() -> None:
    # Core requires icon.png next to extension.yaml: PNG, square, 32-512 px, <= 100 KB.
    from pathlib import Path

    icon = (Path(smtp_extension.__file__).resolve().parent / "icon.png").read_bytes()
    assert icon[:8] == b"\x89PNG\r\n\x1a\n"
    assert icon[12:16] == b"IHDR"
    width = int.from_bytes(icon[16:20], "big")
    height = int.from_bytes(icon[20:24], "big")
    assert width == height
    assert 32 <= width <= 512
    assert len(icon) <= 100 * 1024
