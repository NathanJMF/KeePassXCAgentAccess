## 1. Durable edit requests

- [x] 1.1 Validate typed proposals, enforce token isolation, save state and audit, and make retries idempotent across restarts.
- [x] 1.2 Guard approval and publication against stale vault revisions, locks and token revocation.

## 2. Desktop and runner

- [x] 2.1 Add an Access review and decision flow with exact target, field changes and group effects.
- [x] 2.2 Add CLI and runner tools for submission and status and update the agent skill.

## 3. Operations and acceptance

- [x] 3.1 Verify creation and metadata edits on entries and groups.
- [x] 3.2 Verify moves, recycling and owner or Keeper-generated password replacement with action revision invalidation.
- [x] 3.3 Test a disposable vault through the isolated runner and GNOME review, including stale, denied and successful outcomes in Activity.
