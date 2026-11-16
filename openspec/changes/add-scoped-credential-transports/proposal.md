# Proposal

## Why

An agent needs a reusable way to use a saved credential with tools without learning its value. The owner needs to approve a scope once and see each use in Activity. Keeper currently has two fixed HTTPS GET actions.

## What Changes

- Add a reusable interface that pairs an opaque credential reference with an owner-approved delivery policy.
- Start with private stdin for local CLI programs. The owner configures the executable and literal arguments. The agent supplies the same argument vector and the approved credential reference.
- Extend the same interface with separately reviewed network, API, and browser delivery policies. Git is an end-to-end use case for a future network-enabled profile, using a reusable credential delivery method.
- Record each operation, credential entry, approved destination or command, decision, and outcome in Activity.

## Capabilities

### Modified Capabilities

- **`agent-credential-use`** covers reusable credential delivery, approved operation scopes, and audit requirements.

## Impact

Extends desktop credential actions, the agent CLI and stdio runner, the broker, and the trusted vault worker. The first profile uses Linux sandboxing and returns status only. Existing HTTPS actions retain their behaviour.
