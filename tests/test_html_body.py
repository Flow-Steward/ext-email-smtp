"""HTML email: a body_html sent as multipart/alternative with a text version."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import smtp_extension

from tests.test_smtp_extension import _payload

HTML = (
    "<h1>Spring sale</h1>"
    "<p>Fresh arrivals &amp; <b>discounts</b>.</p>"
    "<ul><li>Tea: 3 €</li><li>Cake: 5 €</li></ul>"
    '<p><a href="https://shop.example/sale">Open the shop</a></p>'
    "<style>p { color: red }</style>"
)


def _sent_message(monkeypatch: pytest.MonkeyPatch, input_payload: dict, **kwargs):
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)
    response = smtp_extension.handle_payload(_payload(input_payload, **kwargs))
    return response, send


def test_an_html_body_is_sent_as_an_alternative_to_its_derived_text(monkeypatch) -> None:
    response, send = _sent_message(
        monkeypatch, {"to": "alice@example.com", "subject": "Sale", "body_html": HTML}
    )

    assert response["ok"] is True
    message = send.call_args.args[1]
    assert message.get_content_type() == "multipart/alternative"
    plain = message.get_body(preferencelist=("plain",)).get_content()
    html = message.get_body(preferencelist=("html",)).get_content()
    assert html.strip() == HTML
    # The text version a client without HTML shows: readable, no tags, no CSS.
    assert "Spring sale" in plain
    assert "Fresh arrivals & discounts." in plain
    assert "- Tea: 3 €" in plain and "- Cake: 5 €" in plain
    assert "Open the shop (https://shop.example/sale)" in plain
    assert "<" not in plain
    assert "color: red" not in plain


def test_a_hand_written_text_version_is_kept(monkeypatch) -> None:
    _response, send = _sent_message(
        monkeypatch,
        {
            "to": "alice@example.com",
            "subject": "Sale",
            "body_text": "Our spring sale has started.",
            "body_html": HTML,
        },
    )

    message = send.call_args.args[1]
    assert message.get_body(preferencelist=("plain",)).get_content().strip() == (
        "Our spring sale has started."
    )
    assert "<h1>Spring sale</h1>" in message.get_body(preferencelist=("html",)).get_content()


def test_a_plain_text_email_stays_a_single_text_part(monkeypatch) -> None:
    _response, send = _sent_message(
        monkeypatch, {"to": "alice@example.com", "subject": "Hi", "body_text": "Hello"}
    )

    message = send.call_args.args[1]
    assert message.get_content_type() == "text/plain"
    assert message.get_content().strip() == "Hello"


def test_an_html_email_keeps_its_attachments(monkeypatch) -> None:
    monkeypatch.setattr(
        smtp_extension, "stream_artifact_bytes", lambda *args, **kwargs: iter([b"%PDF-1.7"])
    )
    response, send = _sent_message(
        monkeypatch,
        {
            "to": "alice@example.com",
            "subject": "Report",
            "body_html": "<p>See the <b>report</b>.</p>",
            "attachments": [
                {"artifact_id": "art_pdf", "filename": "report.pdf", "content_type": "application/pdf"}
            ],
        },
    )

    assert response["ok"] is True
    assert response["attachment_count"] == 1
    message = send.call_args.args[1]
    assert message.get_content_type() == "multipart/mixed"
    assert "<b>report</b>" in message.get_body(preferencelist=("html",)).get_content()
    assert [part.get_filename() for part in message.iter_attachments()] == ["report.pdf"]


def test_an_html_body_needs_a_subject(monkeypatch) -> None:
    response, send = _sent_message(monkeypatch, {"to": "alice@example.com", "body_html": HTML})

    assert response["error_code"] == "subject_required"
    send.assert_not_called()


def test_an_html_body_and_a_template_are_ambiguous(monkeypatch) -> None:
    response, send = _sent_message(
        monkeypatch,
        {"to": "alice@example.com", "subject": "Hi", "body_html": HTML, "template_id": "welcome"},
    )

    assert response["error_code"] == "body_source_ambiguous"
    send.assert_not_called()


def test_a_saved_template_may_carry_an_html_body(monkeypatch) -> None:
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)
    payload = _payload(
        {"to": "alice@example.com", "template_id": "welcome", "variables": {"name": "Alice"}}
    )
    payload["action"]["target"]["project_state"] = {
        "items": [
            {
                "namespace": "templates",
                "state_key": "template:welcome",
                "value": {"subject": "Welcome {{name}}", "body_html": "<p>Hello <b>{{name}}</b></p>"},
            }
        ]
    }

    response = smtp_extension.handle_payload(payload)

    assert response["ok"] is True
    message = send.call_args.args[1]
    assert message["Subject"] == "Welcome Alice"
    assert "<p>Hello <b>Alice</b></p>" in message.get_body(preferencelist=("html",)).get_content()
    assert message.get_body(preferencelist=("plain",)).get_content().strip() == "Hello Alice"


def test_the_size_limit_counts_the_html_body(monkeypatch) -> None:
    response, send = _sent_message(
        monkeypatch,
        {"to": "alice@example.com", "subject": "Big", "body_html": "<p>" + "x" * 30_000 + "</p>"},
        config={"max_message_bytes": 20_000},
    )

    assert response["error_code"] == "message_size_exceeded"
    send.assert_not_called()


@pytest.mark.parametrize(
    ("mapped", "failing"),
    [
        ({"body_html": "<p>x</p>", "subject": "S"}, []),
        ({"body_text": "x", "body_html": "<p>x</p>", "subject": "S"}, []),
        ({"template_id": "welcome"}, []),
        ({"body_html": "<p>x</p>"}, ["subject_required"]),
        ({"body_html": "<p>x</p>", "template_id": "welcome", "subject": "S"}, ["body_source_ambiguous"]),
        ({"subject": "S"}, ["body_required", "body_source_ambiguous"]),
    ],
)
def test_the_step_mapping_rules_accept_an_html_message(mapped: dict, failing: list[str]) -> None:
    from pathlib import Path

    import yaml

    jsonschema = pytest.importorskip("jsonschema")

    manifest = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "contracts/operation_manifest.yaml").read_text()
    )
    operation = next(op for op in manifest["operations"] if op["operation_id"] == "send_email")
    instance = {
        name: None for name in ("body_text", "body_html", "template_id")
    } | {"to": "a@example.com"} | mapped
    instance = {key: value for key, value in instance.items() if value is not None or key in mapped}
    failed = [
        rule["error"]["code"]
        for rule in operation["input_mapping_rules"]
        if not jsonschema.Draft202012Validator(rule["schema"]).is_valid(instance)
    ]
    assert failed == failing
