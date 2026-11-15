# Tasks

## 1. Vault registry and workspace

- [x] 1.1 Add a versioned owner-side registry with local vault IDs, per-vault keyring references, and independent worker sessions. Verify migration of the existing registration, duplicate path aliases, two vaults with matching internal IDs, relinking, and keyring cleanup on removal.
- [ ] 1.2 Build the persistent vault and group tree, entry table, entry details, and bottom-right view controls. Verify nested navigation, direct entries, locked nodes, selection restoration, and locking one vault while the other stays usable.

## 2. Token enrollment and management

- [ ] 2.1 Implement isolated runner credentials, bounded enrollment and status, and token persistence. Verify requests list individual entries and operations, repeats deduplicate, and pending or denied clients receive no vault or entry information.
- [ ] 2.2 Build the single Access table and request review. Verify requested time, identity, project, status, and last-used columns, ordering within both groups, exact entry resolution in duplicate-name cases, and approval or denial of the displayed scope.
- [ ] 2.3 Add token disable, re-enable, and removal. Verify one token's revocation leaves the other usable, scope cannot expand in place, and removed credentials cannot enroll again or authorize requests.

## 3. Scoped broker and global lock

- [ ] 3.1 Enforce the active token's vault, entry, and operation scope in every broker path. Verify partial discovery, use-only and metadata-only scopes, two-vault routing, single-vault compatibility, and generic rejection of out-of-scope references.
- [ ] 3.2 Add the global agent lock and generation checks. Verify startup pause, pause and resume while the owner browses, desktop lock, vault-specific lock, and revocation before protected output and dispatch.
- [ ] 3.3 Extend the CLI and skill with scoped enrollment, status, vault discovery, and explicit vault selection. Verify an isolated runtime can request access, wait for an owner decision, and use only its approved token without credentials appearing in arguments or output.

## 4. Entry actions and local Activity

- [ ] 4.1 Move action binding controls into entry details and expose the existing HTTPS Basic-auth GET as a built-in type. Verify imported bindings retain their identifiers, duplicate entry IDs stay vault-qualified, and destination edits invalidate authorization for the prior revision.
- [ ] 4.2 Move Activity into the main pane. Preserve local history and verify the five-column order, vault and token details, filters, lifecycle events, and last-used updates from successful broker requests. Check captured output and local records for synthetic token and password sentinels.

## 5. Upgrade and acceptance

- [ ] 5.1 Rehearse upgrading from the current app in a private GNOME session with two disposable vaults and the isolated runner. Verify the old vault, keyring, bindings, and Activity survive, authorization starts globally paused, no old mode creates a grant, and one scoped token can be approved and revoked without gaining access to another entry.
