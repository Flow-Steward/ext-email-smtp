# Outgoing Email

Sends email from workflow steps (`send_email`) and project notifications
(`deliver_notification`) through a project's custom SMTP connection.

Logo: `icon.png` (the Flow Steward wave mark, PNG 128x128) next to
`extension.yaml`.

## Requirements

This release (0.3.2) speaks the host contract `extension_host_v2` with its final
execution scope (`group_id`, `for_each_id`, `step_id`, `step_execution_id`)
and is built on `flowsteward-extension-sdk` 0.4.0. A request with another
contract, a missing scope key, both a Group and a For each as its owner, or a
step without its execution is refused (`invalid_host_envelope`) before any
attachment is read or any mail is sent. Install it on a Flow Steward Core that
speaks this contract; an older Core does not run it.

## Notifications

A notification email carries the event's message, followed by the lines Core's
standard email uses that the message does not already contain: `Workflow:`, a
`Group:` line only for a step or event in a Group, a `For each:` line only for
one in a For each, and a `Step:` line only for a step. There is no phase.

## SMTP security and development fixtures

Use **STARTTLS** (the default) or **SSL/TLS**, with the server's matching TLS
port. SMTP authentication always requires TLS. Port 1025 is reserved for the
separately provisioned no-TLS Mailpit development/test fixture; it cannot be
used with the default STARTTLS setting.

The ordinary connection form keeps **None / no TLS** visible but unavailable.
A saved no-TLS connection still displays its actual setting and saves that
value until you explicitly choose TLS; saving does not authorize plaintext or
check delivery. The connection's **Environment** is metadata only. Selecting
`development` does not change deployment SMTP or network policy. The form
requires a Core host that honors literal `disabled` select options; deploy this
UI correction together with that host support.

If a saved or programmatic connection reports `plaintext_smtp_disabled`, use
TLS or ask the operator to provision a trusted development/test fixture. The
backend retains `security: none` for those explicit fixtures, with **no username
and no password**. It still rejects any SMTP AUTH over plaintext.

For operators only: the existing supported deployment setting is
`FS_ALLOW_PRIVATE_REMOTE_URLS=1`, confined to a **disposable trusted development
or test stack**. This is a process policy affecting broader outbound network
protections, not a per-connection SMTP switch. Keep it off in production. Set
up the fixture through the deployment's supported environment configuration;
do not add a form field or reuse connection Environment to grant permission.
The default backend rejects plaintext before DNS or dispatch, while TLS,
DNS/address validation, pinned peers, and certificate/hostname verification
remain enforced on their existing paths.

Mocked extension tests establish configuration and failure behavior. Proving
real delivery requires the operator to run the separately provisioned fixture
and verify receipt in Mailpit; saving a connection or a suppressed workflow
Test Run is not delivery proof.
