"""The release suite this bundle owns, and the boundary it must stay inside.

The suite runs the way a user sends mail: the trusted harness prepares the
project, the SMTP connection and the workflow declared in `RELEASE_WORKFLOWS`,
and the suite submits a task and reads the mail sink. `send_email` is invoked by
the orchestrator inside the run, not by an external token — which is why this
suite needs no `admin:all`.

Mapping from the assertions that moved out of the platform's smoke gate:

* "saved template delivery" -> `outgoing_email_workflow_delivery`, now through a
  real run rather than a direct action call
* "a refusal is readable" -> `outgoing_email_refusal_is_readable`
* "the fixture is enabled and its state restored" -> the harness does both

The foreign-account half of the old denial assertion did not move: reaching
across an account is generic, so the platform asserts it on a synthetic action
as `extension_action_scope_denial`. Calling `send_email` directly from outside
is a separate question, written up in
`docs/tasks/extension-action-invoke-scope.md`.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

BUNDLE_ROOT = Path(__file__).resolve().parent.parent


def _checks_module():
    path = BUNDLE_ROOT / "release" / "checks.py"
    spec = importlib.util.spec_from_file_location("email_release_checks", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_the_declared_checks_are_callable() -> None:
    module = _checks_module()

    assert module.RELEASE_CHECKS
    for check_id, check in module.RELEASE_CHECKS.items():
        assert callable(check), check_id


def test_the_suite_reaches_the_candidate_over_the_public_api_only() -> None:
    """This bundle owns neither a database handle nor a platform module.

    A guardrail, not the boundary. The boundary is the isolated runner: the
    platform starts this suite in its own container with the bundle mounted
    read-only, no Core source, no platform DSN, no Docker socket and no
    inherited environment — proved by `tests/integration/test_bundle_release_isolation.py`.
    This check just catches the honest mistake early, in review rather than in a
    release run.
    """
    source = (BUNDLE_ROOT / "release" / "checks.py").read_text(encoding="utf-8")

    for forbidden in ("psycopg", "_psql", "docker exec", "from core.", "import core"):
        assert forbidden not in source, forbidden


def _literal(name: str):
    """Read a module-level assignment the way the platform's runner does."""
    import ast

    tree = ast.parse((BUNDLE_ROOT / "release" / "checks.py").read_text(encoding="utf-8"))
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else []
        if isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            assert isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not declared")


def test_the_declared_fixtures_are_pure_literals() -> None:
    """The runner reads them with `ast.literal_eval`, never by importing.

    An f-string or a reference to a name in this module parses fine and then
    evaluates to nothing, so the fixture silently goes missing. Reading them the
    way the runner does is the only check that catches it.
    """
    connections = _literal("RELEASE_CONNECTIONS")
    assert [spec["key"] for spec in connections] == ["smtp"]
    assert connections[0]["extension_install_id"] == ("${install:flowsteward.outgoing-email}")
    assert [spec["key"] for spec in _literal("RELEASE_WORKFLOWS")] == ["send"]
    assert _literal("RELEASE_EXTENSIONS") == ["flowsteward.outgoing-email"]
    assert _literal("RELEASE_SERVICES") == ["mailpit"]
    assert "admin:all" not in _literal("RELEASE_SCOPES")


def test_the_workflow_sends_through_a_connector_step() -> None:
    """The step is what a user would author, bound to this extension's action."""
    module = _checks_module()

    workflow = next(spec for spec in module.RELEASE_WORKFLOWS if spec["key"] == "send")
    step = workflow["phases"][0]["steps"][0]
    assert step["step_kind"] == "connector"
    assert step["connector_id"] == "extension.flowsteward.outgoing-email"
    assert step["override"]["connector"]["operation_id"] == "send_email"
    # Filled by the harness, because only the trusted side knows them.
    assert step["connector_install_id"].startswith("${install:")
    assert step["connection_binding_jsonb"]["connection_id"].startswith("${connection:")
    expected_inputs = workflow["settings"]["callable"]["expected_inputs"]
    subject = next(item for item in expected_inputs if item["name"] == "subject")
    assert subject["required"] is True


def test_a_blocked_precondition_stops_before_provoking_a_second_failure() -> None:
    """A stand that refuses delivery must not also be left with a tripped breaker.

    Consecutive extension failures quarantine it. The delivery run and the
    deliberate refusal are two of them, so when the first is refused by the
    candidate's own configuration the suite reports that cause and returns
    instead of running the second.
    """
    source = (BUNDLE_ROOT / "release" / "checks.py").read_text(encoding="utf-8")

    assert "PLAINTEXT_DISABLED_CODE" in source
    assert "NOT RUN" in source
    delivery = source[source.index("def outgoing_email_workflow_delivery") :]
    blocked = delivery.index(f'"{"NOT RUN"}: the candidate refused delivery')
    refusal = delivery.index("_refusal_is_readable(api, evidence")
    assert blocked < refusal, "the refusal run must come after the precondition guard"
    assert "return" in delivery[blocked:refusal]


def test_a_generic_failure_message_is_not_treated_as_a_reason() -> None:
    """ "Workflow execution did not complete successfully" names nothing.

    The job detail carries it in `workflow_run.error.message`, right beside the
    one that does name the step and the cause. Reading the generic one first
    would let an unexplained failure pass as a readable refusal.
    """
    module = _checks_module()

    assert module._job_error({"error": "Workflow execution did not complete successfully"}) == ""
    assert module._job_error({"error": "No explicit root cause recorded."}) == ""
    assert (
        module._job_error(
            {
                "error": "Connector step 'extension.flowsteward.outgoing-email' failed via "
                "extension_action: Recipient address is invalid",
                "workflow_run": {
                    "error": {"message": "Workflow execution did not complete successfully"}
                },
            }
        )
        == "Connector step 'extension.flowsteward.outgoing-email' failed via extension_action: "
        "Recipient address is invalid"
    )
