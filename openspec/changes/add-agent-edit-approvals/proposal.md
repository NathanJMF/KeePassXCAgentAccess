## Why

Keeper can edit local vaults from its desktop and can grant agents scoped read and credential use. Agents need a way to propose exact writes for the owner to review and apply.

## What Changes

- Add one-time edit requests and status to the CLI and isolated runner.
- Show edit requests in Access. The owner reviews the exact target, proposed values, and effect before approving or denying.
- Support entry creation and metadata updates, group creation and renaming, moving and recycling entries or groups, and separately approved password replacement.
- Recheck the token, locks, and vault revision at save time. Persist outcomes across retries and record decisions in Activity.

## Capabilities

### New Capabilities

- **`agent-edit-approvals`** covers one-time edit proposals, owner review, guarded apply, and results.

### Modified Capabilities

## Impact

The change extends the desktop workspace, local broker, agent CLI and runner, and Activity. It reuses the encrypted vault worker to perform the approved write. Existing read and credential-use scopes retain their meaning.
