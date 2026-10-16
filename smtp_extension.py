from __future__ import annotations

import contextlib
import math
import mimetypes
import os
import re
import smtplib
import socket
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from html.parser import HTMLParser
from email.policy import SMTP
from email.utils import formataddr, getaddresses, make_msgid, parseaddr
from typing import Any

from flowsteward_extension_sdk import (
    ArtifactAccessError,
    PinnedPeerError,
    find_artifact_descriptor,
    report_progress,
    resolve_pinned_ips,
    runtime_context_from_payload,
    stream_artifact_bytes,
)

_MESSAGE_ESTIMATED_MIME_MESSAGE_EXCEEDS_SIZE_LIMIT = "Estimated MIME message exceeds size limit"
_MESSAGE_SMTP_SERVER = "SMTP server"

EXTENSION_ID = "flowsteward.outgoing-email"
MAX_RECIPIENTS = 10
MAX_MESSAGE_BYTES = 25 * 1024 * 1024
ATTACHMENT_STREAM_CHUNK_BYTES = 1024 * 1024
ALLOWED_PORTS = {25, 465, 587, 1025, 2525}
ALLOWED_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".odt",
    ".ods",
    ".odp",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".txt",
    ".csv",
}
DISALLOWED_EXTENSIONS = {".json", ".zip", ".docm", ".xlsm", ".pptm"}
MAX_ATTACHMENT_FILENAME_BYTES = 255
ALLOWED_EXTENSION_MIME_TYPES = {
    ".pdf": {"application/pdf"},
    ".doc": {"application/msword"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".xls": {"application/vnd.ms-excel"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    ".ppt": {"application/vnd.ms-powerpoint"},
    ".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    ".odt": {"application/vnd.oasis.opendocument.text"},
    ".ods": {"application/vnd.oasis.opendocument.spreadsheet"},
    ".odp": {"application/vnd.oasis.opendocument.presentation"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".webp": {"image/webp"},
    ".gif": {"image/gif"},
    ".txt": {"text/plain"},
    ".csv": {"text/csv"},
}
DISALLOWED_ATTACHMENT_KEYS = {
    "base64",
    "content",
    "data",
    "download_url",
    "file",
    "file_path",
    "local_path",
    "path",
    "raw",
    "url",
}
TEMPLATE_PATTERN = re.compile(r"{{\s*((?a:\w)+(?:\.(?a:\w)+)*)\s*}}")


class EmailExtensionError(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        definitive_no_effect: bool = True,
        external_effect_status: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.definitive_no_effect = bool(definitive_no_effect)
        self.external_effect_status = external_effect_status or (
            "failed" if self.definitive_no_effect else "timeout_unknown"
        )


@dataclass(frozen=True)
class SmtpConfig:
    provider: str
    host: str
    port: int
    security: str
    username: str
    password: str
    from_email: str
    from_name: str
    reply_to: str
    timeout: float
    max_message_bytes: int


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    if value in (None, ""):
        return []
    return [value]


def _as_str(value: Any) -> str:
    return str(value or "").strip()


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _as_str(value).lower() in {"1", "true", "yes", "on"}


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _has_crlf(value: Any) -> bool:
    text = str(value or "")
    return "\r" in text or "\n" in text


def _require_header_safe(label: str, value: Any) -> str:
    text = _as_str(value)
    if _has_crlf(text):
        raise EmailExtensionError("header_injection", f"{label} must not contain CR/LF")
    return text


def _private_override_enabled() -> bool:
    return _as_str(os.getenv("FS_ALLOW_PRIVATE_REMOTE_URLS")).lower() in {"1", "true", "yes", "on"}


def _connection_payload(payload: dict[str, Any]) -> dict[str, Any]:
    action = _as_dict(payload.get("action"))
    target = _as_dict(action.get("target"))
    connection = _as_dict(target.get("connection"))
    if connection:
        return connection
    action_payload = _as_dict(payload.get("action_payload"))
    action_payload_target = _as_dict(action_payload.get("target"))
    connection = _as_dict(action_payload_target.get("connection"))
    if connection:
        return connection
    top_level_target = _as_dict(payload.get("target"))
    connection = _as_dict(top_level_target.get("connection"))
    if connection:
        return connection
    provider = _as_dict(payload.get("provider"))
    return {
        "config": _as_dict(provider.get("provider_config") or provider.get("config")),
        "secrets": _as_dict(provider.get("secrets")),
    }


def _connection_config(payload: dict[str, Any]) -> SmtpConfig:
    connection = _connection_payload(payload)
    config = _as_dict(
        connection.get("config")
        or connection.get("connection_config")
        or connection.get("provider_config")
    )
    secrets = _as_dict(connection.get("secrets"))
    provider = _as_str(config.get("provider") or "custom_smtp").lower()
    host = _require_header_safe("host", config.get("host"))
    port = _as_int(config.get("port"), 587)
    security = _as_str(config.get("security") or "starttls").lower()
    username = _require_header_safe("username", config.get("username"))
    if _as_str(config.get("password")):
        raise EmailExtensionError(
            "smtp_password_in_config",
            "SMTP password must be supplied as a connection secret",
        )
    password = _as_str(secrets.get("password"))
    from_email = _require_header_safe("from_email", config.get("from_email"))
    from_name = _require_header_safe("from_name", config.get("from_name"))
    reply_to = _require_header_safe("reply_to", config.get("reply_to"))
    timeout = float(config.get("timeout") or 15)
    max_message_bytes = _as_int(config.get("max_message_bytes"), MAX_MESSAGE_BYTES)
    max_message_bytes = max(1, min(max_message_bytes, MAX_MESSAGE_BYTES))

    if provider != "custom_smtp":
        raise EmailExtensionError("unsupported_provider", "Only provider custom_smtp is supported")
    if not host:
        raise EmailExtensionError("smtp_host_required", "SMTP host is required")
    if port not in ALLOWED_PORTS:
        raise EmailExtensionError("smtp_port_not_allowed", "SMTP port is not allowed")
    if security not in {"ssl", "starttls", "none"}:
        raise EmailExtensionError(
            "smtp_security_invalid", "SMTP security must be ssl, starttls, or none"
        )
    if port == 1025 and security != "none":
        raise EmailExtensionError(
            "mailpit_mode_invalid",
            "SMTP port 1025 is reserved for development Mailpit mode with security none",
        )
    if not from_email:
        raise EmailExtensionError(
            "from_email_required", "from_email is required in connection config"
        )
    if not _valid_email_address(from_email):
        raise EmailExtensionError("from_email_invalid", "from_email is invalid")
    if reply_to and not _valid_email_address(reply_to):
        raise EmailExtensionError("reply_to_invalid", "reply_to is invalid")
    if security == "none":
        if not _private_override_enabled():
            raise EmailExtensionError(
                "plaintext_smtp_disabled", "security none requires dev/test override"
            )
        if username or password:
            raise EmailExtensionError(
                "plaintext_auth_forbidden", "Plaintext SMTP AUTH is forbidden"
            )
    if bool(username) != bool(password):
        raise EmailExtensionError(
            "smtp_auth_incomplete", "SMTP username and password must both be configured"
        )
    return SmtpConfig(
        provider=provider,
        host=host,
        port=port,
        security=security,
        username=username,
        password=password,
        from_email=from_email,
        from_name=from_name,
        reply_to=reply_to,
        timeout=timeout,
        max_message_bytes=max_message_bytes,
    )


def _valid_email_address(value: str) -> bool:
    if _has_crlf(value):
        return False
    name, addr = parseaddr(value)
    _ = name
    return bool(addr and "@" in addr and addr == value.strip())


def _recipient_values(value: Any) -> list[str]:
    if isinstance(value, str):
        rows = getaddresses([value])
    else:
        rows = getaddresses([str(item or "") for item in _as_list(value)])
    recipients: list[str] = []
    for name, address in rows:
        if _has_crlf(name) or _has_crlf(address) or not address:
            raise EmailExtensionError("recipient_invalid", "Recipients must not contain CR/LF")
        if not _valid_email_address(address):
            raise EmailExtensionError("recipient_invalid", "Recipient address is invalid")
        recipients.append(address)
    return list(dict.fromkeys(recipients))


def _recipients(input_payload: dict[str, Any]) -> tuple[dict[str, list[str]], list[str]]:
    grouped = {
        "to": _recipient_values(input_payload.get("to")),
        "cc": _recipient_values(input_payload.get("cc")),
        "bcc": _recipient_values(input_payload.get("bcc")),
    }
    flat = [item for group in grouped.values() for item in group]
    if not flat:
        raise EmailExtensionError("recipient_required", "At least one recipient is required")
    if len(flat) > MAX_RECIPIENTS:
        raise EmailExtensionError("recipient_limit_exceeded", "At most 10 recipients are allowed")
    return grouped, flat


def _lookup_path(root: dict[str, Any], path: str) -> Any:
    current: Any = root
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise EmailExtensionError(
                "template_variable_missing", f"Missing template variable '{path}'"
            )
        current = current[part]
    if not isinstance(current, str | int | float | bool):
        raise EmailExtensionError(
            "template_variable_not_scalar",
            f"Template variable '{path}' must be a scalar",
        )
    return current


def _render_template(template: str, variables: dict[str, Any]) -> str:
    text = str(template or "")
    rebuilt = TEMPLATE_PATTERN.sub(lambda match: str(_lookup_path(variables, match.group(1))), text)
    leftover = re.search(r"{{|}}", rebuilt)
    if leftover:
        raise EmailExtensionError("template_syntax_invalid", "Template placeholders are invalid")
    return rebuilt


_BLOCK_TAGS = frozenset(
    {
        "p",
        "div",
        "section",
        "article",
        "header",
        "footer",
        "table",
        "tr",
        "ul",
        "ol",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "blockquote",
        "pre",
        "hr",
    }
)


class _PlainTextFromHtml(HTMLParser):
    """The readable text of an HTML body, for clients that show no HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip = 0
        self._links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "head", "title"}:
            self._skip += 1
        elif tag == "br":
            self._parts.append("\n")
        elif tag == "li":
            self._parts.append("\n- ")
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n\n")
        elif tag in {"td", "th"}:
            self._parts.append("\t")
        if tag == "a":
            self._links.append(next((value or "" for name, value in attrs if name == "href"), ""))

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "head", "title"}:
            self._skip = max(0, self._skip - 1)
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n\n")
        elif tag == "a" and self._links:
            href = self._links.pop()
            if href.startswith(("http://", "https://", "mailto:")):
                self._parts.append(f" ({href})")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self._parts.append(re.sub(r"\s+", " ", data))

    def text(self) -> str:
        lines = [line.strip() for line in "".join(self._parts).splitlines()]
        return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip() + "\n"


def _plain_text_from_html(body_html: str) -> str:
    parser = _PlainTextFromHtml()
    parser.feed(body_html)
    parser.close()
    return parser.text()


def _project_state_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    action = _as_dict(payload.get("action"))
    target = _as_dict(action.get("target"))
    state = _as_dict(target.get("project_state"))
    return [_as_dict(item) for item in _as_list(state.get("items"))]


def _template_value(payload: dict[str, Any], template_id: str) -> dict[str, Any]:
    state_key = f"template:{template_id}"
    for item in _project_state_items(payload):
        if item.get("namespace") == "templates" and item.get("state_key") == state_key:
            value = _as_dict(item.get("value") or item.get("value_jsonb"))
            if value:
                return value
    raise EmailExtensionError("template_not_found", f"Template '{template_id}' was not found")


def _message_text(payload: dict[str, Any], input_payload: dict[str, Any]) -> tuple[str, str, str]:
    """``(subject, plain text, html)``; html is empty for a plain-text email.

    An HTML body may come alone, and its plain-text alternative is derived from
    it, or with ``body_text`` as that alternative written by hand.
    """
    variables = _as_dict(input_payload.get("variables"))
    template_id = _as_str(input_payload.get("template_id"))
    direct_body = input_payload.get("body_text")
    direct_html = input_payload.get("body_html")
    subject = _as_str(input_payload.get("subject"))
    if template_id and (direct_body not in (None, "") or direct_html not in (None, "")):
        raise EmailExtensionError(
            "body_source_ambiguous",
            "Use either a message (body_text or body_html) or template_id, not both",
        )
    if template_id:
        template = _template_value(payload, template_id)
        template_body = (
            template.get("body_text")
            or template.get("template_text")
            or template.get("body")
            or template.get("text")
        )
        template_html = template.get("body_html")
        if template_body in (None, "") and template_html in (None, ""):
            raise EmailExtensionError("template_body_missing", "Template body_text is required")
        body_html = _render_template(str(template_html), variables) if template_html else ""
        body = (
            _render_template(str(template_body), variables)
            if template_body not in (None, "")
            else _plain_text_from_html(body_html)
        )
        subject_template = template.get("subject")
        if subject:
            rendered_subject = _render_template(subject, variables)
        elif subject_template not in (None, ""):
            rendered_subject = _render_template(str(subject_template), variables)
        else:
            raise EmailExtensionError("subject_required", "subject is required")
    else:
        if direct_body in (None, "") and direct_html in (None, ""):
            raise EmailExtensionError(
                "body_required", "body_text, body_html or template_id is required"
            )
        body_html = str(direct_html) if direct_html not in (None, "") else ""
        body = (
            str(direct_body) if direct_body not in (None, "") else _plain_text_from_html(body_html)
        )
        rendered_subject = _render_template(subject, variables)
    rendered_subject = _require_header_safe("subject", rendered_subject)
    if not rendered_subject:
        raise EmailExtensionError("subject_required", "subject is required")
    return rendered_subject, body, body_html


def _reject_config_overrides(input_payload: dict[str, Any]) -> None:
    forbidden = {
        "from",
        "from_email",
        "from_name",
        "host",
        "password",
        "reply_to",
        "security",
        "smtp_host",
        "username",
    }
    present = sorted(key for key in forbidden if key in input_payload)
    if present:
        raise EmailExtensionError(
            "smtp_config_in_action_payload",
            "SMTP connection and sender identity must come from the selected connection",
        )


def _attachment_filename(row: dict[str, Any]) -> str:
    return _as_str(row.get("filename") or row.get("name") or row.get("title"))


def _normalized_content_type(value: Any) -> str:
    return _as_str(value).lower().split(";", 1)[0].strip()


def _validate_attachment_filename(filename: str) -> None:
    if (
        not filename
        or _has_crlf(filename)
        or any(ord(char) < 32 for char in filename)
        or "/" in filename
        or "\\" in filename
        or filename != os.path.basename(filename)
        or len(filename.encode("utf-8")) > MAX_ATTACHMENT_FILENAME_BYTES
    ):
        raise EmailExtensionError("attachment_filename_invalid", "Attachment filename is invalid")


def _attachment_mime_type(filename: str, row: dict[str, Any]) -> str:
    _, ext = os.path.splitext(filename.lower())
    allowed_types = ALLOWED_EXTENSION_MIME_TYPES.get(ext, set())
    supplied_type = _normalized_content_type(row.get("content_type") or row.get("mime_type"))
    guessed_type = _normalized_content_type(mimetypes.guess_type(filename)[0])
    if supplied_type:
        if supplied_type not in allowed_types:
            raise EmailExtensionError(
                "attachment_type_disallowed",
                "Attachment MIME type is not allowed for this file type",
            )
        return supplied_type
    if guessed_type and guessed_type in allowed_types:
        return guessed_type
    if allowed_types:
        return min(allowed_types)
    raise EmailExtensionError("attachment_type_disallowed", "Attachment file type is not allowed")


def _validate_attachment_descriptor(row: dict[str, Any]) -> None:
    bad_keys = sorted(DISALLOWED_ATTACHMENT_KEYS & set(row))
    if bad_keys:
        raise EmailExtensionError(
            "attachment_source_invalid", "Attachments must use artifact descriptors"
        )
    artifact_id = _as_str(row.get("artifact_id") or row.get("artifact_handle"))
    binding_key = _as_str(row.get("binding_key"))
    if not artifact_id and not binding_key:
        raise EmailExtensionError(
            "attachment_artifact_required", "Attachment artifact_id is required"
        )
    filename = _attachment_filename(row)
    _validate_attachment_filename(filename)
    _, ext = os.path.splitext(filename.lower())
    if ext in DISALLOWED_EXTENSIONS or ext not in ALLOWED_EXTENSIONS:
        raise EmailExtensionError(
            "attachment_type_disallowed", "Attachment file type is not allowed"
        )
    _attachment_mime_type(filename, row)


def _mime_overhead_size(raw_size: int) -> int:
    encoded = 4 * math.ceil(max(0, raw_size) / 3)
    line_breaks = 2 * math.ceil(encoded / 76)
    return encoded + line_breaks + 512


def _base_message_estimate(body_text: str) -> int:
    return len(body_text.encode("utf-8")) + 4096


def _max_raw_bytes_for_mime_budget(mime_budget: int) -> int:
    if mime_budget <= 0:
        return 0
    low = 0
    high = max(0, mime_budget)
    while low < high:
        mid = (low + high + 1) // 2
        if _mime_overhead_size(mid) <= mime_budget:
            low = mid
        else:
            high = mid - 1
    return low


def _non_negative_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except Exception:
        return None
    return parsed if parsed >= 0 else None


def _attachment_size_hint(
    payload: dict[str, Any],
    row: dict[str, Any],
    *,
    artifact_id: str,
    binding_key: str,
) -> int | None:
    try:
        descriptor = find_artifact_descriptor(
            payload,
            artifact_id=artifact_id,
            binding_key=binding_key,
            role="input",
        )
    except ArtifactAccessError:
        descriptor = {}
    for source in (descriptor, row):
        for key in ("size_bytes", "size"):
            value = _non_negative_int(_as_dict(source).get(key))
            if value is not None:
                return value
    return None


def _read_attachment_body(
    payload: dict[str, Any],
    *,
    artifact_id: str,
    binding_key: str,
    max_raw_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        stream = stream_artifact_bytes(
            payload,
            artifact_id=artifact_id,
            binding_key=binding_key,
            chunk_size=ATTACHMENT_STREAM_CHUNK_BYTES,
        )
        for chunk in stream:
            total += len(chunk)
            if total > max_raw_bytes:
                raise EmailExtensionError(
                    "message_size_exceeded",
                    "Attachment exceeds MIME message size limit",
                )
            chunks.append(bytes(chunk))
    except EmailExtensionError:
        raise
    except ArtifactAccessError as exc:
        raise EmailExtensionError(
            "attachment_artifact_unavailable",
            "Attachment artifact could not be read",
        ) from exc
    return b"".join(chunks)


def _size_text(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{max(1, round(size_bytes / 1024))} KB"


def _load_attachments(
    payload: dict[str, Any],
    input_payload: dict[str, Any],
    *,
    config: SmtpConfig,
    body_text: str,
) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    estimated_message_bytes = _base_message_estimate(body_text)
    rows = _as_list(input_payload.get("attachments"))
    for index, raw in enumerate(rows):
        row = _as_dict(raw)
        _validate_attachment_descriptor(row)
        artifact_id = _as_str(row.get("artifact_id") or row.get("artifact_handle"))
        binding_key = _as_str(row.get("binding_key"))
        filename = _attachment_filename(row)
        report_progress(f"Reading attachment {filename}", done=index, total=len(rows))
        mime_type = _attachment_mime_type(filename, row)
        size_hint = _attachment_size_hint(
            payload,
            row,
            artifact_id=artifact_id,
            binding_key=binding_key,
        )
        if size_hint is not None:
            next_estimate = estimated_message_bytes + _mime_overhead_size(size_hint)
            if next_estimate > config.max_message_bytes:
                raise EmailExtensionError(
                    "message_size_exceeded",
                    _MESSAGE_ESTIMATED_MIME_MESSAGE_EXCEEDS_SIZE_LIMIT,
                )
        remaining_mime_budget = config.max_message_bytes - estimated_message_bytes
        max_raw_bytes = _max_raw_bytes_for_mime_budget(remaining_mime_budget)
        body = _read_attachment_body(
            payload,
            artifact_id=artifact_id,
            binding_key=binding_key,
            max_raw_bytes=max_raw_bytes,
        )
        estimated_message_bytes += _mime_overhead_size(len(body))
        if estimated_message_bytes > config.max_message_bytes:
            raise EmailExtensionError(
                "message_size_exceeded", _MESSAGE_ESTIMATED_MIME_MESSAGE_EXCEEDS_SIZE_LIMIT
            )
        main_type, _, sub_type = mime_type.partition("/")
        attachments.append(
            {
                "body": body,
                "filename": filename,
                "content_type": mime_type,
                "maintype": main_type or "application",
                "subtype": sub_type or "octet-stream",
                "size_bytes": len(body),
                "artifact_id": artifact_id or binding_key,
            }
        )
    return attachments


def _build_email_message(
    *,
    config: SmtpConfig,
    recipients: dict[str, list[str]],
    subject: str,
    body_text: str,
    attachments: list[dict[str, Any]],
    body_html: str = "",
) -> EmailMessage:
    message = EmailMessage(policy=SMTP)
    message["From"] = (
        formataddr((config.from_name, config.from_email)) if config.from_name else config.from_email
    )
    message["To"] = ", ".join(recipients["to"])
    if recipients["cc"]:
        message["Cc"] = ", ".join(recipients["cc"])
    if config.reply_to:
        message["Reply-To"] = config.reply_to
    message["Subject"] = subject
    message["Message-ID"] = make_msgid(domain=config.host)
    message.set_content(body_text)
    if body_html:
        # multipart/alternative: clients that show HTML pick it, the rest read the text.
        message.add_alternative(body_html, subtype="html")
    for attachment in attachments:
        message.add_attachment(
            attachment["body"],
            maintype=attachment["maintype"],
            subtype=attachment["subtype"],
            filename=attachment["filename"],
        )
    return message


def _message_size(message: EmailMessage) -> int:
    return len(message.as_bytes(policy=SMTP))


def _check_message_size(
    message: EmailMessage,
    *,
    config: SmtpConfig,
    body_text: str,
    attachments: list[dict[str, Any]],
) -> int:
    estimate = _base_message_estimate(body_text)
    for attachment in attachments:
        estimate += _mime_overhead_size(int(attachment["size_bytes"]))
    if estimate > config.max_message_bytes:
        raise EmailExtensionError(
            "message_size_exceeded", _MESSAGE_ESTIMATED_MIME_MESSAGE_EXCEEDS_SIZE_LIMIT
        )
    actual = _message_size(message)
    if actual > config.max_message_bytes:
        raise EmailExtensionError("message_size_exceeded", "MIME message exceeds size limit")
    return actual


def _assert_connected_peer(sock: socket.socket, purpose: str) -> None:
    if _private_override_enabled():
        return
    peer = sock.getpeername()
    peer_host = str((peer or ("",))[0] or "").strip()
    if peer_host:
        import ipaddress

        if not ipaddress.ip_address(peer_host.split("%", 1)[0]).is_global:
            raise PinnedPeerError(
                f"{purpose}: connection resolved to disallowed address '{peer_host}'"
            )


class _PinnedSMTP(smtplib.SMTP):
    def __init__(self, host: str, port: int, timeout: float, pinned_ip: str) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(host=host, port=port, timeout=timeout)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        sock = socket.create_connection((self._pinned_ip, port), timeout)
        _assert_connected_peer(sock, _MESSAGE_SMTP_SERVER)
        return sock


class _PinnedSmtpSsl(smtplib.SMTP_SSL):
    def __init__(
        self,
        host: str,
        port: int,
        timeout: float,
        pinned_ip: str,
        context: ssl.SSLContext,
    ) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(host=host, port=port, timeout=timeout, context=context)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        sock = socket.create_connection((self._pinned_ip, port), timeout)
        _assert_connected_peer(sock, _MESSAGE_SMTP_SERVER)
        return self.context.wrap_socket(sock, server_hostname=host)


def _smtp_client(config: SmtpConfig):
    ips = resolve_pinned_ips(config.host, port=config.port, purpose=_MESSAGE_SMTP_SERVER)
    context = ssl.create_default_context()
    last_error: Exception | None = None
    for ip in ips:
        try:
            client: smtplib.SMTP
            if config.security == "ssl":
                client = _PinnedSmtpSsl(config.host, config.port, config.timeout, ip, context)
            else:
                client = _PinnedSMTP(config.host, config.port, config.timeout, ip)
            if config.security == "starttls":
                client.ehlo()
                if not client.has_extn("starttls"):
                    client.close()
                    raise EmailExtensionError(
                        "starttls_unavailable",
                        "SMTP server does not advertise STARTTLS",
                    )
                client.starttls(context=context)
                client.ehlo()
            return client
        except Exception as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise EmailExtensionError("smtp_connect_failed", "SMTP connection failed")


def _operation_id(payload: dict[str, Any]) -> str:
    action = payload.get("action")
    if isinstance(action, dict):
        return _as_str(
            action.get("action_id")
            or action.get("operation_id")
            or action.get("id")
            or payload.get("action_id")
            or payload.get("operation_id")
        )
    action_payload = _as_dict(payload.get("action_payload"))
    return _as_str(
        action
        or action_payload.get("action_id")
        or action_payload.get("operation_id")
        or payload.get("action_id")
        or payload.get("operation_id")
    )


def _send_smtp(config: SmtpConfig, message: EmailMessage, recipients: list[str]) -> None:
    try:
        client = _smtp_client(config)
    except EmailExtensionError:
        raise
    except PinnedPeerError:
        raise
    except Exception as exc:
        raise EmailExtensionError("smtp_connect_failed", "SMTP connection failed") from exc
    try:
        if config.username:
            try:
                client.login(config.username, config.password)
            except smtplib.SMTPAuthenticationError as exc:
                raise EmailExtensionError("smtp_auth_failed", "SMTP authentication failed") from exc
            except smtplib.SMTPNotSupportedError as exc:
                raise EmailExtensionError(
                    "smtp_auth_unavailable",
                    "SMTP authentication is not available",
                ) from exc
            except (smtplib.SMTPException, OSError) as exc:
                raise EmailExtensionError("smtp_auth_failed", "SMTP authentication failed") from exc
        try:
            refused = client.send_message(
                message,
                from_addr=config.from_email,
                to_addrs=recipients,
            )
            if refused:
                raise EmailExtensionError(
                    "smtp_recipients_partially_refused",
                    "SMTP refused one or more recipients",
                    definitive_no_effect=False,
                    external_effect_status="timeout_unknown",
                )
        except smtplib.SMTPSenderRefused as exc:
            raise EmailExtensionError("smtp_sender_refused", "SMTP sender was rejected") from exc
        except smtplib.SMTPRecipientsRefused as exc:
            raise EmailExtensionError(
                "smtp_recipients_refused",
                "SMTP recipients were rejected",
            ) from exc
        except smtplib.SMTPHeloError as exc:
            raise EmailExtensionError("smtp_helo_failed", "SMTP HELO/EHLO failed") from exc
        except OSError as exc:
            raise EmailExtensionError(
                "smtp_send_failed",
                "SMTP send outcome is unknown",
                definitive_no_effect=False,
                external_effect_status="timeout_unknown",
            ) from exc
        except smtplib.SMTPException as exc:
            raise EmailExtensionError(
                "smtp_send_failed",
                "SMTP send failed",
                definitive_no_effect=False,
                external_effect_status="timeout_unknown",
            ) from exc
    finally:
        with contextlib.suppress(Exception):
            client.quit()
        with contextlib.suppress(Exception):
            client.close()


def _input_payload(payload: dict[str, Any]) -> dict[str, Any]:
    action = _as_dict(payload.get("action"))
    if _as_str(payload.get("mode")) == "action" or action.get("input") is not None:
        return _as_dict(action.get("input"))
    return _as_dict(payload.get("input") or payload.get("request"))


def _is_test_mode(payload: dict[str, Any]) -> bool:
    runtime = _as_dict(payload.get("runtime_context"))
    action = _as_dict(payload.get("action"))
    context = _as_dict(action.get("context"))
    return _as_bool(runtime.get("test_mode")) or _as_bool(context.get("test_mode"))


def _notification_scope_lines(event: dict[str, Any], event_payload: dict[str, Any]) -> list[str]:
    """The workflow and execution scope of one event, as Core's standard email names them.

    A Group line only for a real group, a For each line only for a For each,
    a Step line only for a step; the root of a workflow has no label of its own.
    """

    def scope_id(key: str) -> str:
        return _as_str(event.get(key)) or _as_str(event_payload.get(key))

    group_id = scope_id("group_id")
    for_each_id = scope_id("for_each_id")
    step_id = scope_id("step_id")
    details = [
        (
            "Workflow",
            _as_str(event_payload.get("workflow_display_name"))
            or _as_str(event_payload.get("workflow_name"))
            or _as_str(event.get("workflow_id")),
        ),
        ("Group", (_as_str(event_payload.get("group_label")) or group_id) if group_id else ""),
        (
            "For each",
            (_as_str(event_payload.get("for_each_label")) or for_each_id) if for_each_id else "",
        ),
        ("Step", (_as_str(event_payload.get("step_label")) or step_id) if step_id else ""),
    ]
    return [f"{label}: {value}" for label, value in details if value]


def _notification_body(event: dict[str, Any], event_payload: dict[str, Any]) -> str:
    message = (
        _as_str(event_payload.get("message"))
        or _as_str(event_payload.get("summary"))
        or _as_str(event.get("summary"))
        or _as_str(event.get("event_type"))
        or "notification"
    )
    # Core's standard email already carries these lines; never repeat one.
    scope_lines = [
        line for line in _notification_scope_lines(event, event_payload) if line not in message
    ]
    return "\n".join([message, "", *scope_lines]) if scope_lines else message


def _notification_input(payload: dict[str, Any]) -> dict[str, Any]:
    event = _as_dict(payload.get("event"))
    route = _as_dict(payload.get("route"))
    route_config = _as_dict(route.get("route_config"))
    event_payload = _as_dict(event.get("payload"))
    event_type = _as_str(event.get("event_type")) or "notification"
    severity = _as_str(event.get("severity") or "info").upper()
    subject = _as_str(route_config.get("subject")) or f"[{severity}] {event_type}"
    body = _notification_body(event, event_payload)
    return {
        "to": route_config.get("to") or route_config.get("recipients"),
        "cc": route_config.get("cc"),
        "bcc": route_config.get("bcc"),
        "subject": subject,
        "body_text": body,
        "variables": {},
        "attachments": [],
    }


def _result(
    *,
    ok: bool,
    delivered: bool,
    provider_message_id: str = "",
    error_code: str = "",
    error: str = "",
    external_effect_status: str = "",
    definitely_no_external_effect: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "ok": bool(ok),
        "delivered": bool(delivered),
        "provider_message_id": provider_message_id,
        "recipient_count": int((metadata or {}).get("recipient_count") or 0),
        "attachment_count": int((metadata or {}).get("attachment_count") or 0),
        "estimated_message_bytes": int((metadata or {}).get("estimated_message_bytes") or 0),
    }
    if error_code:
        payload["error_code"] = error_code
    if error:
        payload["error"] = error
    if not ok and error_code and error:
        payload["errors"] = [{"code": error_code, "message": error}]
    if external_effect_status:
        payload["external_effect_status"] = external_effect_status
    if definitely_no_external_effect:
        payload["definitely_no_external_effect"] = True
    return payload


def send_email(payload: dict[str, Any]) -> dict[str, Any]:
    if _is_test_mode(payload):
        return _result(
            ok=True,
            delivered=False,
            external_effect_status="suppressed",
            metadata={},
        )
    config = _connection_config(payload)
    input_payload = _input_payload(payload)
    if _operation_id(payload) == "deliver_notification":
        input_payload = _notification_input(payload)
    _reject_config_overrides(input_payload)
    grouped_recipients, flat_recipients = _recipients(input_payload)
    subject, body_text, body_html = _message_text(payload, input_payload)
    # Size estimates count both bodies; the built message is measured exactly.
    sized_body = body_text + body_html
    attachments = _load_attachments(
        payload,
        input_payload,
        config=config,
        body_text=sized_body,
    )
    message = _build_email_message(
        config=config,
        recipients=grouped_recipients,
        subject=subject,
        body_text=body_text,
        attachments=attachments,
        body_html=body_html,
    )
    message_size = _check_message_size(
        message,
        config=config,
        body_text=sized_body,
        attachments=attachments,
    )
    if attachments:
        # A message with attachments can take a while to reach the mail server.
        report_progress(f"Sending the message ({_size_text(message_size)}) to the mail server")
    try:
        _send_smtp(config, message, flat_recipients)
    except EmailExtensionError:
        raise
    except PinnedPeerError as exc:
        raise EmailExtensionError("smtp_host_disallowed", str(exc)) from exc
    except Exception as exc:
        raise EmailExtensionError(
            "smtp_send_failed",
            "SMTP send outcome is unknown",
            definitive_no_effect=False,
            external_effect_status="timeout_unknown",
        ) from exc
    return _result(
        ok=True,
        delivered=True,
        provider_message_id=_as_str(message.get("Message-ID")),
        external_effect_status="succeeded",
        metadata={
            "recipient_count": len(flat_recipients),
            "attachment_count": len(attachments),
            "estimated_message_bytes": message_size,
        },
    )


def handle_payload(payload: dict[str, Any]) -> dict[str, Any]:
    root = _as_dict(payload)
    # The host envelope is checked before anything is read or sent: another
    # contract, a missing execution-scope key or two owners is refused here.
    try:
        runtime_context_from_payload(root)
    except ValueError as exc:
        return _result(
            ok=False,
            delivered=False,
            error_code="invalid_host_envelope",
            error=str(exc),
            external_effect_status="failed",
            definitely_no_external_effect=True,
            metadata={},
        )
    try:
        return send_email(root)
    except EmailExtensionError as exc:
        return _result(
            ok=False,
            delivered=False,
            error_code=exc.code,
            error=str(exc),
            external_effect_status=exc.external_effect_status,
            definitely_no_external_effect=exc.definitive_no_effect,
            metadata={},
        )
