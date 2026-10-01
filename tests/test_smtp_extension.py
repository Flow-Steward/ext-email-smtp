from __future__ import annotations

import smtplib
from unittest.mock import MagicMock

import smtp_extension


def _payload(
    input_payload: dict, *, config: dict | None = None, runtime_context: dict | None = None
) -> dict:
    smtp_config = {
        "provider": "custom_smtp",
        "host": "smtp.example.com",
        "port": 587,
        "security": "starttls",
        "username": "mailer",
        "from_email": "robot@example.com",
        "from_name": "Flow Steward",
    }
    smtp_config.update(config or {})
    return {
        "contract_version": "extension_host_v1",
        "mode": "action",
        "runtime_context": runtime_context or {},
        "action": {
            "action_id": "send_email",
            "target": {
                "connection": {
                    "connection_id": "conn_smtp",
                    "config": smtp_config,
                    "secrets": {"password": "secret-password"},
                }
            },
            "input": input_payload,
        },
    }


def test_send_email_rejects_more_than_ten_recipients():
    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": [f"user{i}@example.com" for i in range(11)],
                "subject": "Hello",
                "body_text": "Body",
            }
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "recipient_limit_exceeded"
    assert response["definitely_no_external_effect"] is True


def test_send_email_test_mode_suppresses_without_connection(monkeypatch):
    connection_config = MagicMock(side_effect=AssertionError("connection should not be read"))
    monkeypatch.setattr(smtp_extension, "_connection_config", connection_config)

    response = smtp_extension.handle_payload(
        _payload(
            {"to": "alice@example.com", "subject": "Hello", "body_text": "Body"},
            runtime_context={"test_mode": True},
        )
    )

    assert response["ok"] is True
    assert response["delivered"] is False
    assert response["external_effect_status"] == "suppressed"
    connection_config.assert_not_called()


def test_send_email_rejects_sender_identity_override():
    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": "alice@example.com",
                "from_email": "attacker@example.com",
                "subject": "Hello",
                "body_text": "Body",
            }
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "smtp_config_in_action_payload"


def test_send_email_rejects_password_in_non_secret_config():
    response = smtp_extension.handle_payload(
        _payload(
            {"to": "alice@example.com", "subject": "Hello", "body_text": "Body"},
            config={"password": "not-a-secret-field"},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "smtp_password_in_config"


def test_send_email_template_missing_variable_fails(monkeypatch):
    monkeypatch.setattr(smtp_extension, "_send_smtp", lambda *args, **kwargs: None)
    payload = _payload(
        {
            "to": "alice@example.com",
            "subject": "Welcome {{user.name}}",
            "template_id": "welcome",
            "variables": {"user": {}},
        }
    )
    payload["action"]["target"]["project_state"] = {
        "items": [
            {
                "namespace": "templates",
                "state_key": "template:welcome",
                "value": {"body_text": "Hello {{user.name}}"},
            }
        ]
    }

    response = smtp_extension.handle_payload(payload)

    assert response["ok"] is False
    assert response["error_code"] == "template_variable_missing"


def test_send_email_uses_saved_template_subject_when_request_omits_subject(monkeypatch):
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)
    payload = _payload(
        {
            "to": "alice@example.com",
            "template_id": "welcome",
            "variables": {"user": {"name": "Alice"}},
        }
    )
    payload["action"]["target"]["project_state"] = {
        "items": [
            {
                "namespace": "templates",
                "state_key": "template:welcome",
                "value": {
                    "subject": "Welcome {{user.name}}",
                    "body_text": "Hello {{user.name}}",
                },
            }
        ]
    }

    response = smtp_extension.handle_payload(payload)

    assert response["ok"] is True
    message = send.call_args.args[1]
    assert message["Subject"] == "Welcome Alice"
    assert message.get_content().strip() == "Hello Alice"


def test_send_email_direct_body_without_subject_fails_before_delivery(monkeypatch):
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)

    response = smtp_extension.handle_payload(
        _payload({"to": "alice@example.com", "body_text": "Hello"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "subject_required"
    assert response["definitely_no_external_effect"] is True
    send.assert_not_called()


def test_send_email_rejects_header_injection():
    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": "alice@example.com",
                "subject": "Hello\nBcc: attacker@example.com",
                "body_text": "Body",
            }
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "header_injection"


def test_send_email_rejects_invalid_attachment_source():
    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": "alice@example.com",
                "subject": "Hello",
                "body_text": "Body",
                "attachments": [{"path": "/tmp/report.pdf", "filename": "report.pdf"}],
            }
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "attachment_source_invalid"


def test_send_email_rejects_attachment_path_filename(monkeypatch):
    stream_artifact = MagicMock()
    monkeypatch.setattr(smtp_extension, "stream_artifact_bytes", stream_artifact)

    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": "alice@example.com",
                "subject": "Hello",
                "body_text": "Body",
                "attachments": [{"artifact_id": "art_1", "filename": "../report.pdf"}],
            }
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "attachment_filename_invalid"
    stream_artifact.assert_not_called()


def test_send_email_rejects_disallowed_attachment_type():
    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": "alice@example.com",
                "subject": "Hello",
                "body_text": "Body",
                "attachments": [{"artifact_id": "art_1", "filename": "payload.zip"}],
            }
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "attachment_type_disallowed"


def test_send_email_rejects_attachment_mime_mismatch(monkeypatch):
    stream_artifact = MagicMock()
    monkeypatch.setattr(smtp_extension, "stream_artifact_bytes", stream_artifact)

    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": "alice@example.com",
                "subject": "Hello",
                "body_text": "Body",
                "attachments": [
                    {
                        "artifact_id": "art_1",
                        "filename": "report.pdf",
                        "content_type": "application/json",
                    }
                ],
            }
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "attachment_type_disallowed"
    stream_artifact.assert_not_called()


def test_send_email_sends_valid_pdf_artifact_with_redacted_metadata(monkeypatch):
    send = MagicMock()
    monkeypatch.setattr(
        smtp_extension,
        "stream_artifact_bytes",
        lambda *args, **kwargs: iter([b"%PDF-1.7"]),
    )
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)

    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": "alice@example.com",
                "subject": "Hello",
                "body_text": "Body",
                "attachments": [
                    {
                        "artifact_id": "art_pdf",
                        "filename": "report.pdf",
                        "content_type": "application/pdf",
                    }
                ],
            }
        )
    )

    assert response["ok"] is True
    assert response["delivered"] is True
    assert response["attachment_count"] == 1
    assert response["recipient_count"] == 1
    assert "Body" not in response.values()
    send.assert_called_once()


def test_deliver_notification_reads_connection_from_action_payload(monkeypatch):
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)
    payload = {
        "action": "deliver_notification",
        "action_payload": {
            "action_id": "deliver_notification",
            "target": {
                "connection": {
                    "connection_id": "conn_smtp",
                    "config": {
                        "provider": "custom_smtp",
                        "host": "smtp.route.example",
                        "port": 587,
                        "security": "starttls",
                        "username": "mailer",
                        "from_email": "robot@example.com",
                    },
                    "secrets": {"password": "secret-password"},
                }
            },
        },
        "event": {
            "event_type": "job.failed",
            "severity": "error",
            "summary": "Job failed",
            "payload": {"summary": "Job failed"},
        },
        "route": {"route_config": {"to": "ops@example.com"}},
    }

    response = smtp_extension.handle_payload(payload)

    assert response["ok"] is True
    assert response["delivered"] is True
    sent_config = send.call_args.args[0]
    assert sent_config.host == "smtp.route.example"
    assert sent_config.password == "secret-password"


def test_send_email_rejects_final_mime_size_over_connection_cap(monkeypatch):
    monkeypatch.setattr(
        smtp_extension,
        "stream_artifact_bytes",
        lambda *args, **kwargs: iter([b"x" * 2000]),
    )
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)

    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": "alice@example.com",
                "subject": "Hello",
                "body_text": "Body",
                "attachments": [{"artifact_id": "art_pdf", "filename": "report.pdf"}],
            },
            config={"max_message_bytes": 1024},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "message_size_exceeded"
    send.assert_not_called()


def test_send_email_rejects_oversized_attachment_descriptor_before_download(monkeypatch):
    stream_artifact = MagicMock(side_effect=AssertionError("download should not start"))
    monkeypatch.setattr(smtp_extension, "stream_artifact_bytes", stream_artifact)
    send = MagicMock()
    monkeypatch.setattr(smtp_extension, "_send_smtp", send)
    payload = _payload(
        {
            "to": "alice@example.com",
            "subject": "Hello",
            "body_text": "Body",
            "attachments": [{"artifact_id": "art_pdf", "filename": "report.pdf"}],
        },
        config={"max_message_bytes": 1024},
    )
    payload["artifacts"] = {
        "inputs": [
            {
                "artifact_id": "art_pdf",
                "artifact_handle": "artifact:art_pdf",
                "binding_key": "attachments",
                "size_bytes": 2000,
                "access": {"download_url": "https://signed.example/report.pdf?method=GET"},
            }
        ]
    }

    response = smtp_extension.handle_payload(payload)

    assert response["ok"] is False
    assert response["error_code"] == "message_size_exceeded"
    stream_artifact.assert_not_called()
    send.assert_not_called()


def test_send_email_rejects_plaintext_auth_even_with_dev_override(monkeypatch):
    monkeypatch.setenv("FS_ALLOW_PRIVATE_REMOTE_URLS", "1")

    response = smtp_extension.handle_payload(
        _payload(
            {"to": "alice@example.com", "subject": "Hello", "body_text": "Body"},
            config={"security": "none"},
        )
    )

    assert response["ok"] is False
    assert response["error_code"] == "plaintext_auth_forbidden"


def test_mailpit_connection_is_representable_only_with_the_dev_private_override(monkeypatch):
    payload = _payload(
        {"to": "alice@example.com", "subject": "Hello", "body_text": "Body"},
        config={
            "host": "mailpit",
            "port": 1025,
            "security": "none",
            "username": "",
        },
    )
    payload["action"]["target"]["connection"]["secrets"] = {}

    denied = smtp_extension.handle_payload(payload)
    assert denied["ok"] is False
    assert denied["error_code"] == "plaintext_smtp_disabled"

    monkeypatch.setenv("FS_ALLOW_PRIVATE_REMOTE_URLS", "1")
    monkeypatch.setattr(smtp_extension, "_send_smtp", lambda *_args, **_kwargs: None)
    accepted = smtp_extension.handle_payload(payload)

    assert accepted["ok"] is True
    assert accepted["delivered"] is True


def test_send_email_rejects_unsafe_smtp_dns(monkeypatch):
    def _blocked(*args, **kwargs):
        raise smtp_extension.PinnedPeerError("SMTP server resolves to disallowed address")

    monkeypatch.setattr(smtp_extension, "resolve_pinned_ips", _blocked)

    response = smtp_extension.handle_payload(
        _payload({"to": "alice@example.com", "subject": "Hello", "body_text": "Body"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "smtp_host_disallowed"
    assert response["external_effect_status"] == "failed"


def test_starttls_unavailable_fails_before_auth(monkeypatch):
    class FakeSMTP:
        login_called = False

        def __init__(self, *args, **kwargs):
            pass

        def ehlo(self):
            return None

        def has_extn(self, name):
            return False

        def close(self):
            return None

        def login(self, *args, **kwargs):
            FakeSMTP.login_called = True

    monkeypatch.setattr(
        smtp_extension, "resolve_pinned_ips", lambda *args, **kwargs: ["203.0.113.10"]
    )
    monkeypatch.setattr(smtp_extension, "_PinnedSMTP", FakeSMTP)

    response = smtp_extension.handle_payload(
        _payload({"to": "alice@example.com", "subject": "Hello", "body_text": "Body"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "starttls_unavailable"
    assert FakeSMTP.login_called is False


def test_smtp_auth_failure_is_definitive_no_effect(monkeypatch):
    class FakeSMTP:
        def login(self, *args, **kwargs):
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

        def quit(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(smtp_extension, "_smtp_client", lambda _config: FakeSMTP())

    response = smtp_extension.handle_payload(
        _payload({"to": "alice@example.com", "subject": "Hello", "body_text": "Body"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "smtp_auth_failed"
    assert response["external_effect_status"] == "failed"
    assert response["definitely_no_external_effect"] is True


def test_smtp_connect_failure_is_definitive_no_effect(monkeypatch):
    def _connect_failed(_config):
        raise OSError("network unreachable")

    monkeypatch.setattr(smtp_extension, "_smtp_client", _connect_failed)

    response = smtp_extension.handle_payload(
        _payload({"to": "alice@example.com", "subject": "Hello", "body_text": "Body"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "smtp_connect_failed"
    assert response["external_effect_status"] == "failed"
    assert response["definitely_no_external_effect"] is True


def test_smtp_send_disconnect_remains_timeout_unknown(monkeypatch):
    class FakeSMTP:
        def login(self, *args, **kwargs):
            return None

        def send_message(self, *args, **kwargs):
            raise smtplib.SMTPServerDisconnected("lost during DATA")

        def quit(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(smtp_extension, "_smtp_client", lambda _config: FakeSMTP())

    response = smtp_extension.handle_payload(
        _payload({"to": "alice@example.com", "subject": "Hello", "body_text": "Body"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "smtp_send_failed"
    assert response["external_effect_status"] == "timeout_unknown"
    assert "definitely_no_external_effect" not in response


def test_unclassified_failure_after_send_boundary_remains_timeout_unknown(monkeypatch):
    def _accepted_then_failed(*_args, **_kwargs):
        raise RuntimeError("server accepted DATA, local parser crashed before returning")

    monkeypatch.setattr(smtp_extension, "_send_smtp", _accepted_then_failed)

    response = smtp_extension.handle_payload(
        _payload({"to": "alice@example.com", "subject": "Hello", "body_text": "Body"})
    )

    assert response["ok"] is False
    assert response["error_code"] == "smtp_send_failed"
    assert response["external_effect_status"] == "timeout_unknown"
    assert "definitely_no_external_effect" not in response


def test_smtp_cleanup_failure_after_send_preserves_success(monkeypatch):
    class FakeSMTP:
        def login(self, *args, **kwargs):
            return None

        def send_message(self, *args, **kwargs):
            return {}

        def quit(self):
            raise OSError("disconnect during quit")

        def close(self):
            raise OSError("close failed")

    monkeypatch.setattr(smtp_extension, "_smtp_client", lambda _config: FakeSMTP())

    response = smtp_extension.handle_payload(
        _payload({"to": "alice@example.com", "subject": "Hello", "body_text": "Body"})
    )

    assert response["ok"] is True
    assert response["delivered"] is True
    assert response["external_effect_status"] == "succeeded"


def test_smtp_partial_recipient_refusal_fails_partial(monkeypatch):
    class FakeSMTP:
        def login(self, *args, **kwargs):
            return None

        def send_message(self, *args, **kwargs):
            return {"bad@example.com": (550, b"no such user")}

        def quit(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(smtp_extension, "_smtp_client", lambda _config: FakeSMTP())

    response = smtp_extension.handle_payload(
        _payload(
            {
                "to": ["good@example.com", "bad@example.com"],
                "subject": "Hello",
                "body_text": "Body",
            }
        )
    )

    assert response["ok"] is False
    assert response["delivered"] is False
    assert response["error_code"] == "smtp_recipients_partially_refused"
    assert response["external_effect_status"] == "timeout_unknown"
    assert "bad@example.com" not in str(response)
