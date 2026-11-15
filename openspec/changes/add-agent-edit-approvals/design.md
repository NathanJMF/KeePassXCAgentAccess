## Context

Keeper already has a UID-restricted broker, revocable scoped tokens, Activity, and an encrypted owner-side vault write path. Agent edit requests extend those components.

## Goals / Non-Goals

**Goals**

- Give the owner one decision for a specific mutation and exact set of values.
- Reuse local vault and entry identities and preserve existing token scope.
- Fail safely on stale reviews, revoked tokens, and interrupted publication.

**Non-Goals**

Permanent deletion, cross-vault moves, and broad standing write grants are outside this change.

## Decisions

### Separate write proposals from enrollment

An active token submits a bounded typed payload with one operation and one UUID. The owner reviews it in Access. The request resolves against the owner workspace. Existing read access is independent from the ability to ask the owner to approve a write. The broker accepts exact references and reports request state without describing the target.

### Bind owner approval to the displayed snapshot

Store the proposal and its state durably. The review identifies the vault revision and exact existing item, requested fields, and destination. Keeper marks the request as applying before write work and checks the review, token, and locks through the vault worker's publication gate. Requests interrupted between that claim and durable outcome stay interrupted. The same token and request ID cannot run a second write.

### Preserve the credential boundary

Create and edit use an explicit field set. Password replacement has a separate request type. Keeper accepts the replacement from the owner dialog or generates it inside the owner boundary. Credentials and metadata values are omitted from Activity. An applied username or password change invalidates existing credential action approvals for the affected entry.

### Reuse the encrypted edit worker

Owner-approved moves stay in the named vault. Recycling uses the configured recycle bin. Existing encrypted save conflict detection and atomic publication remain the file-write path. Keeper exposes terminal results to the submitting token without reading back the entry.

## Risks / Trade-offs

A write may finish after its result is lost. Keeper reports an interrupted outcome and leaves recovery to owner review. Previously approved reads can observe later edits to the fields they were already scoped to read.

## Migration Plan

Existing grants keep their existing scopes. The local edit queue starts empty. Update the agent skill, CLI, and runner with the desktop and broker. Test on disposable vaults before using approved writes against a real vault.
