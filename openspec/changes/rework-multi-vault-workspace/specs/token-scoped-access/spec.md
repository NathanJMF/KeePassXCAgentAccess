# Token-Scoped Access

## Purpose

Use the approved token scope to govern all agent access to vault metadata and registered credential actions.

## ADDED Requirements

### Requirement: Enforce only the specific operations approved on a token

The broker SHALL require an authenticated active token, the global agent lock released, and an eligible operation on the approved vault and entry. Discovery and password use SHALL be separate permissions. An approved operation SHALL proceed under that token while the required vault is unlocked and the action binding remains valid.

#### Scenario: Metadata-only token tries to use a password
- **WHEN** a token has metadata access to an entry and requests a configured credential action
- **THEN** the broker denies use without exposing the credential and the agent needs a new token with that operation approved

#### Scenario: Token can run an approved action repeatedly
- **WHEN** an active token requests an exact approved action and all availability checks pass
- **THEN** the broker runs it and records the result under that token without a new approval

#### Scenario: Client uses legacy mode-based access
- **WHEN** an existing UID-only client tries to use the broker after the upgrade
- **THEN** it must complete token approval before it can access any vault data

### Requirement: Disclose only scoped vaults and entries

An authenticated token's catalog SHALL show only vaults with at least one approved permission, using local vault IDs and display names. Entry listings SHALL include only entries for which the token has metadata permission. Group paths SHALL use only the ancestors needed for those entries. Requests outside scope SHALL fail without confirming that the target exists.

#### Scenario: Token scope crosses two vaults
- **WHEN** a token has access to one entry in each of two vaults
- **THEN** discovery can show those two vaults and each targeted listing shows only its authorized entry metadata

#### Scenario: Use-only permission
- **WHEN** a token has permission to use an action for a particular entry and no metadata permission for it
- **THEN** its vault appears in the catalog and the entry is omitted from metadata listings

### Requirement: Route by the token's explicit vault selection

Broker operations that address an entry or group SHALL use its registered vault identity. A command without a vault selector SHALL default only when the token has exactly one registered vault in scope. Vault aliases and the owner's current selection SHALL confer no additional scope.

#### Scenario: Token covers several vaults
- **WHEN** an agent omits a vault ID while making an entry request with a multi-vault token
- **THEN** the broker asks for a vault selection and releases no entry data

### Requirement: Globally pause agent access

The main window SHALL offer a global agent lock. Locking SHALL suspend vault discovery and protected operations for all tokens and invalidate pending deliveries. The owner SHALL be able to keep browsing and review enrollment while agent access is locked. Resuming SHALL use the existing active scopes and vault states. Startup and desktop lock SHALL engage the global agent lock.

#### Scenario: Pause while a request is in flight
- **WHEN** the owner engages the global lock before a protected operation is dispatched or metadata is released
- **THEN** it is revoked and the owner keeps their unlocked vault browsing sessions

#### Scenario: Resume with a locked vault or a disabled token
- **WHEN** the owner resumes agent access
- **THEN** a disabled token remains disabled and any separately locked vault remains locked

### Requirement: Keep owner controls in the owner desktop window

The exported tray menu SHALL allow opening the Keeper window only. Access policy, settings, approval decisions, and application shutdown controls SHALL live in the desktop window. The agent deployment SHALL keep shell, filesystem, desktop, and escalation capabilities outside the owner's account and session.

#### Scenario: A session-bus caller opens Keeper from the tray
- **WHEN** the caller invokes the exported tray menu item
- **THEN** Keeper opens its window and preserves the current access state, settings, and approvals

### Requirement: Recheck token scope before every protected delivery

The broker SHALL bind pending work to its token, vault session, entry, operation, and action configuration. It SHALL recheck those conditions immediately before protected output or credential dispatch. Locking a vault, disabling or removing a token, or replacing an approved action SHALL invalidate the affected work.

#### Scenario: Disable a token while work is pending
- **WHEN** the owner disables a token before its request reaches protected output
- **THEN** the broker withholds the protected work and unrelated tokens retain their scope
