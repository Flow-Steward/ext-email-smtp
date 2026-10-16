# Outgoing Email

Sends email from workflow steps (`send_email`) and project notifications
(`deliver_notification`) through a project's custom SMTP connection.

Logo: `icon.png` (the Flow Steward wave mark, PNG 128x128) next to
`extension.yaml`.

## Requirements

This release (0.3.0) speaks the host contract `extension_host_v2` with its final
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
