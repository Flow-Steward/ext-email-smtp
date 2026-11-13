# Workflow actions

Create an SMTP server project connection with the host, port, security mode, sender address and any required login credentials, then select it for this step.

Select the connection in the workflow step. Map returned message IDs, file handles or dataset handles into later steps rather than pasting credentials or local paths.

## Send email via SMTP (`send_email`)

Send one plain-text, HTML or template-backed email through the selected SMTP connection. Create an SMTP server project connection with the host, port, security mode, sender address and any required login credentials, then select it for this step. Example: Email a generated PDF report to reports@example.com, mapping its artifact into an attachment descriptor.

Inputs:

- `to`: Recipient address, comma-separated addresses, or a mapped JSON array of addresses.
- `cc`: Optional visible copy recipients: email addresses separated by commas, or a mapped array.
- `bcc`: Optional blind copy recipients: email addresses separated by commas, or a mapped array.
- `subject`: Required for a direct message; optional when the selected saved template provides its own subject.
- `body_text`: Plain text. With an HTML message it is the text shown by clients that do not display HTML.
- `body_html`: An HTML email body; a Template step in HTML format fits here. Without a plain Message the text version is made from it.
- `template_id`: ID of a saved project email template. Supply template variables and leave direct message bodies empty when using a template.
- `variables`: JSON object mapping the selected template's placeholder names to values.
- `attachments`: JSON array of workflow artifact descriptors, each with artifact_handle (or artifact_id or binding_key) and a safe filename. Use supported file types such as PDF; URLs, paths and inline content are not accepted.

Result fields: `delivered`, `provider_message_id`, `recipient_count`, `attachment_count`, `estimated_message_bytes`, `external_effect_status`, `definitely_no_external_effect`.
