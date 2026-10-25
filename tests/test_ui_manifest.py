from __future__ import annotations

import ast
from pathlib import Path

import yaml

EXTENSION_ROOT = Path(__file__).resolve().parents[1]


def _load_yaml(relative_path: str) -> dict:
    return yaml.safe_load((EXTENSION_ROOT / relative_path).read_text(encoding="utf-8"))


def test_outgoing_email_ui_separates_connections_and_templates() -> None:
    manifest = _load_yaml("ui/ui_manifest.yaml")
    page_refs = [row["ref"] for row in manifest["pages"]]

    assert page_refs == ["pages/connections.yaml", "pages/templates.yaml"]

    pages = [_load_yaml(f"ui/{page_ref}") for page_ref in page_refs]
    assert [(page["page_id"], page["title"]) for page in pages] == [
        ("connections", "Connections"),
        ("templates", "Templates"),
    ]
    assert pages[0]["components"] == [{"ref": "../components/connection_form.yaml"}]
    assert pages[1]["components"] == [{"ref": "../components/templates_form.yaml"}]


def test_outgoing_email_required_fields_are_declared_by_the_extension() -> None:
    connection_form = _load_yaml("ui/components/connection_form.yaml")
    template_form = _load_yaml("ui/components/templates_form.yaml")
    action_manifest = _load_yaml("ui/actions/actions.yaml")
    config_schema = _load_yaml("schemas/config.schema.yaml")
    secrets_schema = _load_yaml("schemas/secrets.schema.yaml")

    assert {field["path"] for field in connection_form["fields"] if field.get("required")} == {
        "host",
        "port",
        "security",
        "from_email",
    }
    assert connection_form["data"]["required_secret_fields"] == []
    security = next(field for field in connection_form["fields"] if field["path"] == "security")
    assert {option["value"] for option in security["options"]} == {
        "starttls",
        "ssl",
        "none",
    }
    assert 1025 in config_schema["properties"]["port"]["enum"]
    assert "username" not in config_schema["required"]
    assert secrets_schema.get("required", []) == []
    assert {field["path"] for field in template_form["fields"] if field.get("required")} == {
        "template_id",
        "body_text",
    }
    send_email = next(
        action for action in action_manifest["actions"] if action["action_id"] == "send_email"
    )
    assert {
        parameter["name"] for parameter in send_email["parameters"] if parameter.get("required")
    } == {"to"}
    subject = next(
        parameter for parameter in send_email["parameters"] if parameter["name"] == "subject"
    )
    assert "direct message" in subject["description"]
    assert {"body_required", "body_source_ambiguous", "subject_required"}.issubset(
        send_email["error_codes"]
    )


def test_plaintext_is_unavailable_in_the_form_without_removing_backend_fixture_support() -> None:
    form = _load_yaml("ui/components/connection_form.yaml")
    fields = {field["path"]: field for field in form["fields"]}
    options = {option["value"]: option for option in fields["security"]["options"]}

    assert options["none"].get("disabled") is True
    assert "unavailable" in options["none"]["label"].lower()
    assert not options["starttls"].get("disabled", False)
    assert not options["ssl"].get("disabled", False)
    assert form["defaults"]["security"] == "starttls"
    security_help = fields["security"].get("description") or fields["security"].get("help", "")
    assert "operator" in security_help.lower()
    assert "Environment does not enable plaintext" in security_help
    assert "no username or password" in security_help
    assert "metadata" in fields["environment"]["description"]
    assert "1025" in fields["port"]["description"]
    assert "TLS port" in fields["port"]["description"]
    assert form["data"]["secret_fields"] == ["password"]
    assert form["data"]["required_secret_fields"] == []
    assert set(fields) == {
        "display_name",
        "environment",
        "host",
        "port",
        "security",
        "username",
        "password",
        "from_email",
        "from_name",
        "reply_to",
        "timeout",
    }
    schema = _load_yaml("schemas/config.schema.yaml")
    connection_schema = _load_yaml("contracts/connection_types.yaml")["connection_types"][0][
        "config_schema"
    ]
    for backend_schema in (schema, connection_schema):
        assert backend_schema["properties"]["security"]["enum"] == ["ssl", "starttls", "none"]
        assert backend_schema["additionalProperties"] is False
        assert set(backend_schema["properties"]) == {
            "provider",
            "host",
            "port",
            "security",
            "username",
            "from_email",
            "from_name",
            "reply_to",
            "timeout",
            "max_message_bytes",
        }


def test_outgoing_email_publishes_one_workflow_operation_and_hidden_delivery_contract() -> None:
    operation_manifest = _load_yaml("contracts/operation_manifest.yaml")["operations"]
    connection_types = _load_yaml("contracts/connection_types.yaml")["connection_types"]
    step_ui_manifest = _load_yaml("contracts/step_ui_manifest.yaml")["forms"]

    assert [row["connection_type_id"] for row in connection_types] == ["custom_smtp"]
    assert [row["operation_id"] for row in operation_manifest] == [
        "send_email",
        "deliver_notification",
    ]
    assert [row["operation_id"] for row in operation_manifest if row.get("workflow_visible")] == [
        "send_email"
    ]
    hidden_delivery = operation_manifest[1]
    assert hidden_delivery == {
        "operation_id": "deliver_notification",
        "display_name": "Deliver Notification",
        "description": "Internal notification-provider delivery contract.",
        "operation_kind": "action",
        "category": "notification",
        "workflow_visible": False,
        "inputs": [
            {"name": "event", "value_type": "object", "required": True},
            {"name": "route", "value_type": "object", "required": True},
        ],
        "outputs": [
            {"name": "delivered", "value_type": "boolean"},
            {"name": "provider_message_id", "value_type": "text"},
        ],
    }
    operation = operation_manifest[0]
    assert operation["connection_type_ids"] == ["custom_smtp"]
    assert [rule["error"]["code"] for rule in operation["input_mapping_rules"]] == [
        "body_required",
        "body_source_ambiguous",
        "subject_required",
    ]
    assert [row["name"] for row in operation["inputs"] if row.get("required")] == [
        "connection_ref",
        "to",
    ]
    assert [row["name"] for row in step_ui_manifest[0]["fields"]] == [
        "to",
        "cc",
        "bcc",
        "subject",
        "body_text",
        "body_html",
        "template_id",
        "variables",
        "attachments",
    ]
    subject_field = next(row for row in step_ui_manifest[0]["fields"] if row["name"] == "subject")
    assert "saved template" in subject_field["help_text"]


def test_send_email_contract_declares_every_runtime_error_code() -> None:
    source = (EXTENSION_ROOT / "smtp_extension.py").read_text(encoding="utf-8")
    runtime_codes = {
        str(call.args[0].value)
        for call in ast.walk(ast.parse(source))
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "EmailExtensionError"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    }
    operation_manifest = _load_yaml("contracts/operation_manifest.yaml")
    operation = next(
        row for row in operation_manifest["operations"] if row["operation_id"] == "send_email"
    )

    assert runtime_codes <= set(operation["error_codes"])


def test_outgoing_email_owns_its_external_effect_payload_mapping() -> None:
    manifest = _load_yaml("extension.yaml")
    send_effect = next(
        effect for effect in manifest["external_effects"] if effect["operation_id"] == "send_email"
    )

    assert send_effect["observability"] == {
        "target_fields": ["to", "cc", "bcc"],
        "target_kind": "recipient",
        "target_label": "recipient",
        "artifact_field": "attachments",
        "payload_size_field": "estimated_message_bytes",
    }


def test_outgoing_email_declares_catalog_metadata_without_bundle_trust() -> None:
    manifest = _load_yaml("extension.yaml")

    assert manifest["display_name"] == "Outgoing Email"
    assert manifest["vendor"]["name"] == "Flow Steward"
    assert manifest["listing"]["category"] == "messaging"
    assert "smtp" in manifest["listing"]["tags"]
    assert manifest["machine_auth"]["service_account_key"] == "svc_ext_outgoing_email"

    assert not (EXTENSION_ROOT / ".fs-extension-install.yaml").exists()


def test_notification_recipient_items_declare_email_without_narrowing_csv() -> None:
    schema = _load_yaml("schemas/subscriptions.schema.yaml")
    for field in ("to", "cc", "bcc"):
        scalar, array = schema["properties"][field]["oneOf"]
        assert scalar == {"type": "string"}
        assert array == {"type": "array", "items": {"type": "string", "format": "email"}}
