# Proposal

## Why

The desktop app currently manages one vault through separate dialogs. The owner needs a workspace for several databases and a way to approve an agent's request for specific secrets through a revocable access token.

## What Changes

- Show vaults and their nested groups in a persistent left sidebar. Selecting a group shows its entries in the main pane. Each vault has its own unlock state and saved keyring reference.
- Put **Activity** and **Access** at the bottom right. Both replace the main pane. Activity shows the audit history. Access shows pending requests above approved tokens in one table with status and last used.
- Require each agent access request to name the secrets and uses it needs. Double-click a request to review the exact entries and uses, then approve or deny it.
- Use the approved scope of each token for entry discovery and credential use. Provide controls to disable, re-enable, or remove a token and a global lock to pause all agent access.
- Move Actions into entry details. Keep the built-in HTTPS Basic-auth GET type and let the owner configure its credential and destination.
- **BREAKING** Existing broker clients must obtain a scoped token before accessing vault metadata or using a credential. The current approval modes and per-entry review flags are retired from access decisions.

## Capabilities

### New Capabilities

- **`multi-vault-workspace`** covers vault registration, independent sessions, and navigation.
- **`agent-access-grants`** covers secret-specific requests, token approval, and the Access table.
- **`token-scoped-access`** covers scope enforcement, vault routing, and the global agent lock.
- **`workspace-activity`** covers the main Activity view and its vault and token audit context.
- **`entry-action-bindings`** covers built-in action types and their configuration in entry details.

### Modified Capabilities

## Impact

Extends the owner app, keyring references, broker, CLI, and KeePass skill. Imports the existing vault, action bindings, and activity history into the new workspace. This change covers browsing and broker administration. KeePass entry and group editing remains a follow-up.
