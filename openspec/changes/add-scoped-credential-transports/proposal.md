# Proposal

## Why

Keeper grants agents scoped access and records credential use, but its existing HTTPS GET actions cannot authenticate a Git push, call a typed API operation, or establish a browser session. The owner wants to approve a scope once and see every use in Activity.

## What Changes

- Introduce credential transports for approved CLI, API, and browser operations. Each transport defines where the credential goes, which inputs the agent can supply, and which results it can see.
- Start with a Git HTTPS action for a fast-forward push to an owner-selected repository and branch. An agent can submit a Git bundle from any checkout using the installed runner.
- Preserve existing entry grants, review settings, and HTTPS GET actions. The owner can reuse an approved transport grant when its scope and configuration remain valid.
- Record requested operation, entry, destination, safe target details, decision, and outcome in Activity.

## Capabilities

### Modified Capabilities

- **`agent-credential-use`** adds operation-specific transports, reusable approval scopes, and audit requirements.

## Impact

Extends the local broker, trusted runtime, desktop action editor, agent CLI, and Activity view. API writes and browser adapters ship as separately reviewed operations. Plaintext credentials stay with the trusted transport and approved destination.
