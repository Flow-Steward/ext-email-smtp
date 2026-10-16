"""What this extension must still do for its users on a release candidate.

The way a user sends mail is not by calling `send_email` from outside — it is by
running a workflow whose step sends it. So that is what this suite checks: the
trusted harness enables the extension, prepares the project, the SMTP connection
and the workflow declared below, and the suite then does exactly what an operator
does — submits the task, waits for the job, and reads the mail sink.

`send_email` is invoked by the orchestrator inside the run, which is why this
suite never needs `admin:all`. Calling the action directly from outside is a
different question, and one the candidate currently answers with `admin:all` for
anybody; that is written up in `docs/tasks/extension-action-invoke-scope.md` and
deliberately not exercised here.

Public API only, plus the mail sink this extension delivers into — the external
system it owns, not platform internals.

Two kinds of "did not run" are distinguished on purpose:

* a **precondition the stand can meet** — a missing dev/test override — is a
  failure naming the cause, because a release candidate is supposed to have it;
* a **limitation of the platform's public surface** is recorded as NOT RUN with
  the task that would lift it.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
import uuid
from typing import Any

EXTENSION_ID = "flowsteward.outgoing-email"
SENDER = "flow-steward@candidate.local"

#: What this suite may do, and no more. Every DELETE on the candidate is
#: admin-only, and so are enabling an extension and authoring a workflow — so
#: none of them is here. The trusted harness does all three and removes what it
#: made; this suite submits a task and reads the result, as an operator does.
RELEASE_SCOPES = [
    "command:*",
    "jobs:*",
    "projects:*",
    "read:*",
    "registry:*",
    "workflows:*",
]

#: Enabled by the trusted harness for the run, and restored after it.
RELEASE_EXTENSIONS = [
    "flowsteward.outgoing-email",
]

#: The mail sink must be on this suite's network, or its deliveries have nowhere
#: to land. Named here so the runner connects it and nothing else.
RELEASE_SERVICES = ["mailpit"]

#: The mail sink this extension delivers into — the external system it owns.
#: Declared here so the runner passes it explicitly instead of the suite reading
#: whatever happens to be in the environment.
RELEASE_INPUTS = [
    "FS_SMOKE_MAILPIT_BASE",
    "FS_SMOKE_SMTP_HOST",
    "FS_SMOKE_SMTP_PORT",
]

#: The connection the workflow step delivers through. `${env:...}` is filled by
#: the harness from the declared inputs above.
#:
#: Every declaration below is a *pure literal* — no f-strings, no references to
#: names in this module. The runner reads them with `ast.literal_eval` precisely
#: so that discovering what a bundle needs never executes its code.
RELEASE_CONNECTIONS = [
    {
        "key": "smtp",
        "extension_id": "flowsteward.outgoing-email",
        "extension_install_id": "${install:flowsteward.outgoing-email}",
        "connection_kind": "extension",
        "connection_type": "custom_smtp",
        "display_name": "Release candidate mail sink",
        "runtime_mode": "local",
        "connection_config": {
            "provider": "custom_smtp",
            "host": "${env:FS_SMOKE_SMTP_HOST}",
            "port": "${env:FS_SMOKE_SMTP_PORT}",
            "security": "none",
            "from_email": "flow-steward@candidate.local",
            "from_name": "Flow Steward candidate",
        },
    }
]

#: The workflow a user would author to send mail: one connector step bound to
#: this extension's `send_email`, reading its recipient and body from the task's
#: declared inputs. Authoring it is a registry write and therefore admin-only, so
#: the definition is declared here and the harness performs the write.
RELEASE_WORKFLOWS = [
    {
        "key": "send",
        "workflow_id": "release_outgoing_email_send",
        "display_name": "Release: send one email",
        "description": "Sends a single message through the project's SMTP connection.",
        "enabled": True,
        "settings": {
            "callable": {
                "enabled": True,
                "trigger_channels": ["api"],
                "input_mode": "fields",
                "strict_inputs": False,
                "expected_inputs": [
                    {"name": "recipient", "type": "text", "required": True},
                    {"name": "subject", "type": "text", "required": True},
                    {"name": "body_text", "type": "text", "required": True},
                ],
            }
        },
        "phases": [
            {
                "phase_id": "deliver",
                "phase_kind": "start",
                "display_name": "Deliver",
                "gate": {"type": "none"},
                "steps": [
                    {
                        "step_id": "send_release_email",
                        "display_name": "Send Release Email",
                        "step_kind": "connector",
                        "connector_id": "extension.flowsteward.outgoing-email",
                        "connector_install_id": "${install:flowsteward.outgoing-email}",
                        "connection_binding_jsonb": {"connection_id": "${connection:smtp}"},
                        "override": {
                            "connector": {
                                "extension_id": "flowsteward.outgoing-email",
                                "operation_id": "send_email",
                                "input_mapping": {
                                    "to": "state.inputs.recipient",
                                    "subject": "state.inputs.subject",
                                    "body_text": "state.inputs.body_text",
                                },
                                "output_mapping": {
                                    "provider_message_id": "state.provider_message_id",
                                    "delivered": "state.delivered",
                                },
                            }
                        },
                        "input_mapping_jsonb": {
                            "to": "state.inputs.recipient",
                            "subject": "state.inputs.subject",
                            "body_text": "state.inputs.body_text",
                        },
                        "output_mapping_jsonb": {
                            "provider_message_id": "state.provider_message_id",
                            "delivered": "state.delivered",
                        },
                    }
                ],
            },
            {
                "phase_id": "done",
                "phase_kind": "end",
                "display_name": "Done",
                "gate": {"type": "none"},
                "steps": [
                    {
                        "step_id": "sent",
                        "display_name": "Sent",
                        "step_kind": "stop_success",
                        "override": {"stop_success": {"reason": "message delivered"}},
                    }
                ],
            },
        ],
    }
]

#: What the extension answers when the candidate has no dev/test override, so a
#: plaintext local sink is refused before anything is sent.
PLAINTEXT_DISABLED_CODE = "plaintext_smtp_disabled"


def _rows(payload: Any, key: str) -> list[dict[str, Any]]:
    rows = payload if isinstance(payload, list) else None
    if rows is None:
        rows = payload.get(key) if isinstance(payload, dict) else None
    return [row for row in rows or [] if isinstance(row, dict)]


def _mailpit(path: str) -> dict[str, Any]:
    base = str(os.environ.get("FS_SMOKE_MAILPIT_BASE") or "").rstrip("/")
    if not base:
        raise RuntimeError("FS_SMOKE_MAILPIT_BASE is not set")
    with urllib.request.urlopen(base + path, timeout=15) as response:  # nosec B310 - the operator's own mail sink URL
        payload = json.loads(response.read().decode() or "{}")
    return dict(payload) if isinstance(payload, dict) else {}


def _messages_for(recipient: str) -> list[dict[str, Any]]:
    query = urllib.parse.quote("to:" + recipient, safe="")
    listing = _mailpit(f"/api/v1/search?query={query}")
    messages = []
    for row in listing.get("messages") or []:
        if isinstance(row, dict) and row.get("ID"):
            message_id = urllib.parse.quote(str(row["ID"]), safe="")
            messages.append(_mailpit(f"/api/v1/message/{message_id}"))
    return messages


def _address(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("Address") or value.get("address") or "").strip()
    return str(value or "").strip()


def _normalized(text: str) -> str:
    """SMTP transmits CRLF, so a body authored with LF comes back rewritten."""
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def _message_matches(message: dict[str, Any], *, recipient: str, subject: str, body: str) -> bool:
    recipients = message.get("To") or message.get("to") or []
    if not isinstance(recipients, list):
        recipients = [recipients]
    text = str(message.get("Text") or message.get("text") or "")
    return (
        _address(message.get("From") or message.get("from")) == SENDER
        and recipient in {_address(value) for value in recipients}
        and str(message.get("Subject") or message.get("subject") or "").strip() == subject
        and _normalized(body) in _normalized(text)
    )


def _submit(api: Any, project_id: str, workflow_id: str, inputs: dict[str, Any]) -> tuple[int, str]:
    status, payload = api.request(
        "POST",
        "/api/tasks",
        {
            "task_id": f"outgoing-email-{uuid.uuid4().hex[:10]}",
            "task_summary": "Outgoing Email release check.",
            "project_id": project_id,
            "workflow_id": workflow_id,
            "mode": "brownfield",
            "inputs": inputs,
        },
    )
    return status, str((payload or {}).get("job_id") or "")


def _await_job(api: Any, job_id: str, *, timeout_seconds: int = 600) -> tuple[str, dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    detail: dict[str, Any] = {}
    status = ""
    while time.monotonic() < deadline:
        _, payload = api.request("GET", f"/api/jobs/{job_id}")
        detail = payload if isinstance(payload, dict) else {}
        status = str(detail.get("status") or "").strip()
        if status in {"completed", "failed", "cancelled"}:
            return status, detail
        time.sleep(3)
    return status or "timeout", detail


#: A message that says only that something failed. `workflow_run.error.message`
#: is one of these, so reading it first hides the reason that is right beside it.
_UNINFORMATIVE = (
    "workflow execution did not complete successfully",
    "no explicit root cause recorded.",
    "failed",
    "error",
)


def _job_error(detail: dict[str, Any]) -> str:
    """What the run says went wrong, preferring whichever place names a cause.

    The job detail carries several: the top-level `error` and
    `failure_summary.detail` name the step and what it reported, while
    `workflow_run.error.message` is the generic sentence. Order matters.
    """
    summary = detail.get("failure_summary")
    summary = summary if isinstance(summary, dict) else {}
    incident = detail.get("incident")
    incident = incident if isinstance(incident, dict) else {}
    root = incident.get("root_cause")
    root = root if isinstance(root, dict) else {}
    run = detail.get("workflow_run")
    run = run if isinstance(run, dict) else {}
    run_error = run.get("error")
    run_error = run_error if isinstance(run_error, dict) else {}
    for candidate in (
        detail.get("error"),
        summary.get("detail"),
        root.get("message"),
        detail.get("last_error"),
        run_error.get("message"),
        run_error.get("code"),
    ):
        text = str(candidate or "").strip()
        if text and text.lower() not in _UNINFORMATIVE:
            return text
    return ""


def outgoing_email_workflow_delivery(api: Any, evidence: Any) -> None:
    """Run the workflow a user would run, and read the message it sent."""
    project_id = str(os.environ.get("FS_RELEASE_PROJECT_ID") or "")
    workflow_id = str(os.environ.get("FS_RELEASE_WORKFLOW_SEND") or "")
    connection_id = str(os.environ.get("FS_RELEASE_CONNECTION_SMTP") or "")
    evidence.add(
        "outgoing_email_fixtures_prepared",
        bool(project_id and workflow_id and connection_id),
        f"project={project_id or '<missing>'}; workflow={workflow_id or '<missing>'}; "
        f"connection={connection_id or '<missing>'}",
    )
    if not (project_id and workflow_id and connection_id):
        return
    if not str(os.environ.get("FS_SMOKE_MAILPIT_BASE") or "").strip():
        evidence.add(
            "outgoing_email_workflow_delivery",
            False,
            "NOT RUN: FS_SMOKE_MAILPIT_BASE is unset, so no mail sink is available to read",
        )
        return

    marker = uuid.uuid4().hex[:10]
    recipient = f"release-{marker}@candidate.local"
    subject = f"Release delivery {marker}"
    # Non-ASCII and a newline on purpose: SMTP rewrites line endings, and a body
    # that only ever holds plain ASCII proves less than one that does not.
    body = f"Release evidence\n• owner: Žara\n• marker: {marker}"

    submit_status, job_id = _submit(
        api,
        project_id,
        workflow_id,
        {"recipient": recipient, "subject": subject, "body_text": body},
    )
    if submit_status not in {200, 201, 202} or not job_id:
        evidence.add(
            "outgoing_email_workflow_delivery",
            False,
            f"the task would not enqueue: HTTP {submit_status}",
        )
        return
    status, detail = _await_job(api, job_id)
    error = _job_error(detail)
    if PLAINTEXT_DISABLED_CODE in error:
        evidence.add(
            "outgoing_email_workflow_delivery",
            False,
            f"NOT RUN: the candidate refused delivery with {PLAINTEXT_DISABLED_CODE}; the stand "
            "needs the dev/test override the platform check asserts",
        )
        return
    messages = _messages_for(recipient)
    evidence.add(
        "outgoing_email_workflow_delivery",
        status == "completed"
        and len(messages) == 1
        and _message_matches(messages[0], recipient=recipient, subject=subject, body=body),
        f"job={job_id}; status={status}; messages={len(messages)}; error={error or '<none>'}",
    )
    _refusal_is_readable(api, evidence, project_id, workflow_id, marker)


def _refusal_is_readable(
    api: Any, evidence: Any, project_id: str, workflow_id: str, marker: str
) -> None:
    """A refused send must fail the run and say why, not pass quietly.

    An address the extension cannot accept is the cheapest honest refusal: it is
    the extension's own validation, not the platform's, and it must reach the
    operator through the job rather than being swallowed into a green run.
    """
    submit_status, job_id = _submit(
        api,
        project_id,
        workflow_id,
        {
            "recipient": "not-an-address",
            "subject": f"Release refusal {marker}",
            "body_text": "This must not be delivered.",
        },
    )
    if submit_status not in {200, 201, 202} or not job_id:
        evidence.add(
            "outgoing_email_refusal_is_readable",
            False,
            f"the refusal task would not enqueue: HTTP {submit_status}",
        )
        return
    status, detail = _await_job(api, job_id)
    error = _job_error(detail)
    delivered = _messages_for("not-an-address")
    evidence.add(
        "outgoing_email_refusal_is_readable",
        status == "failed"
        # `_job_error` returns "" for a message that only says something failed,
        # so a non-empty answer here is already one that names a cause — and it
        # must name *this* step, not some other part of the run.
        and bool(error.strip())
        and "outgoing-email" in error.lower()
        and not delivered,
        f"job={job_id}; status={status}; delivered={len(delivered)}; error={error or '<missing>'}",
    )


RELEASE_CHECKS = {
    "outgoing_email_workflow_delivery": outgoing_email_workflow_delivery,
}
