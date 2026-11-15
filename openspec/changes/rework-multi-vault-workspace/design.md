# Design

## Context

The current app saves one vault and one keyring reference, keeps one worker unlocked, and routes the broker to that worker. Agent access currently combines an admitted OS peer, a session switch, a global approval mode, and per-entry review flags. The owner opens Access, Actions, and Activity in separate dialogs. This change moves browsing and administration into a multi-vault workspace and makes each approved token the source of its access scope.

## Goals / Non-Goals

**Goals**

- Preserve working KeePass files, keyring items, and historical decisions during the upgrade.
- Keep the owner workspace and each vault session independent of agent token availability.
- Let owners see exactly what a token authorizes and revoke it without affecting other tokens.

**Non-Goals**

Editing KeePass entries and groups, additional credential adapters, and cross-device token synchronization belong to later changes.

## Decisions

### Register vaults by a local identity

Store an opaque app-local vault ID, owner display name, verified database path, expected KeePass root identifier, key-file reference, and optional OS keyring reference per registered vault. Check candidate files for duplicate registrations through aliases and use the local vault ID to distinguish independent copies that share KeePass IDs. Every group, entry, action binding, and token scope is qualified by that local vault ID. Rebinding a registration to a moved file requires owner verification. A different vault receives a new local ID and its own scope.

Use one disposable unlocked worker and session generation per vault. The owner can open several simultaneously. Build the sidebar from owner-side group data, keeping locked nodes at the vault level and showing the direct entries of the selected group in the main table. Entry details show owner browse fields and the entry's configured actions. A locked, removed, or changed session invalidates its worker data and pending operations while other ready vaults stay available.

### Issue a token for a reviewed request

Keep the Unix socket and verified OS peer admission as the boundary for accepting enrollment traffic. The trusted runner generates a high-entropy opaque credential separately for each token request. The broker stores its verifier and binds it to the admitted OS identity. Caller-provided identity and project labels are descriptive and shown as reported unless a trusted source establishes their provenance. Runner credentials live in isolated runner storage and travel only in broker authentication, outside model context, command arguments, repos, and logs. A shared OS account requires runtime isolation that keeps one runner's credential out of the others' reach.

A request has a bounded list of entries and explicit operations. The agent can use an owner-provided entry reference or supply a name for owner resolution. Name resolution occurs in the desktop review, with the owner confirming the exact vault, group, and entry. If use is requested, the owner also sees the enabled action binding and its exact destination. Before approval, the agent can check the request state and sees no vault search or match information. A pending request can stay in the Access table when the desktop does not have a live agent command waiting.

Approve or deny the complete displayed scope. Persist the resolved references and approved permissions with the token. A revised or broader scope uses a new token request. Disable preserves the scope and suspends its use. Remove revokes the credential, removes the active row, and leaves the audit record and a local verifier tombstone so the old credential cannot silently enroll again. Deduplicate enrollment retries for the same credential and request and bound pending requests per OS peer.

### Apply the token scope to routing and dispatch

Use explicit permissions for entry metadata and for an exact action binding on an entry. A permitted vault catalog is derived from the token's approved references. A metadata listing filters to approved entry IDs before projecting rows. Show only the group ancestry needed for authorized rows. A use-only entry can contribute its vault to the catalog while its metadata stays out of entry listings.

Route with the local vault ID, independent of the owner's selected vault. Retain the existing entry response fields. An omitted vault identifier is accepted only when the token has one registered vault in scope. Extend the CLI and skill with an access request and status workflow, `vaults list`, and `--vault` for entry listing and credential use. The trusted launcher selects the token profile. Each authenticated request uses one token and cannot combine scopes.

Check the active token, vault and operation scope, global lock generation, current worker generation, and action binding immediately before protected output or password dispatch. Approved requests inside scope run under the token's authorization. Treat unavailable and out-of-scope targets uniformly on the agent side. Keep the last-used timestamp on the token itself and advance it only for successfully fulfilled authenticated operations.

### Keep the global lock separate from vault sessions

Use the global lock to stop agent discovery and protected work across all vaults. The owner can still browse open vaults and review token requests. Enrollment and status traffic can remain available to admitted OS peers while the global lock is engaged. Startup and locking the desktop begin with agent access paused. Desktop lock also closes all unlocked workers. A vault lock closes its one worker and revokes affected work. Resuming agent access never unlocks a vault or activates a disabled token. Record the actual outcome for work already sent before a lock took effect.

### Put Actions, Access, and Activity where the owner uses them

Replace the standalone Actions dialog with a small binding editor on the selected entry. Start with the existing HTTPS Basic-auth GET adapter as a built-in type. Preserve existing binding identifiers and owner destinations. Scope each binding by vault and entry. Pin the security-relevant action revision in the token authorization, so changing the type or destination needs fresh approval. Keep TLS verification, fixed routing, bounded status results, and credential confinement in the existing HTTPS worker path.

Keep the two bottom-right buttons and swap only the main pane. Access shows pending and approved rows in one table, including disabled tokens in the approved group. Double-click opens either request review or token management. Activity preserves the agreed five columns. Store token and vault references, decision context, and display snapshots in the local audit store so older rows remain readable after removals or renames. Keep the existing durable recording gate before protected work.

## Risks / Trade-offs

- **Token scope is broader than intended.** Require a list of individual entries and uses, show resolved references and destinations at review, and issue a separate token for any expansion.
- **A relink, action edit, or concurrent revocation races with dispatch.** Invalidate affected generations and recheck at the point of delivery.
- **A request reveals what exists in a vault.** Keep matching and ambiguity in the owner review and expose only request status before approval.
- **Two clients share one account or compromise a runner.** Protect each credential with per-runtime isolation and keep the OS peer check. Remove the affected token without broadening other tokens.

## Migration Plan

1. Import the existing verified vault into the registry with its current keyring reference and optional key file. Migrate matching action bindings to that vault's entries. Retain unresolved bindings for owner review.
2. Preserve existing Activity and let older rows show unavailable token or vault attribution where necessary. Keep a local rollback copy of the legacy app settings through successful migration.
3. Start in the global locked state with no active tokens. Legacy OS admission settings can admit enrollment. Existing approval modes and review flags confer no token scope.
4. Update the trusted runner, CLI, and skill together. Rehearse migration and the complete request, approval, scoped-use, and revocation flow using two synthetic vaults before applying the workflow to real credentials.
