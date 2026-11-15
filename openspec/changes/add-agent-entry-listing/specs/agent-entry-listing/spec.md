# Agent Entry Listing

## Purpose

Let an isolated local agent list basic metadata from an unlocked KeePass vault with the desktop owner's authorization.

## ADDED Requirements

### Requirement: Authorize listing for a separate agent account

Agent listing SHALL start disabled. The owner SHALL be able to enable or stop listing from the tray for one configured, unprivileged agent account during an unlocked session. The broker SHALL verify the connecting account's OS identity before processing a request.

#### Scenario: Owner starts listing
- **WHEN** the owner unlocks the vault and enables listing for the configured agent account
- **THEN** the tray indicates that listing is enabled and the account can list entries

#### Scenario: Default access is disabled
- **WHEN** the app starts, or the owner unlocks the vault for a new session
- **THEN** listing stays disabled until the owner enables it

#### Scenario: A different account connects
- **WHEN** a process from a different OS account connects to the endpoint
- **THEN** the broker denies it and releases no vault metadata

### Requirement: End listing when access is revoked

Disabling listing, changing the vault configuration, locking the vault or desktop, logging out, or exiting SHALL revoke listing. A request revoked before response delivery SHALL return no entry data.

#### Scenario: Vault locks during a list request
- **WHEN** the vault locks after the agent requests a listing and before the broker begins delivering a response
- **THEN** the agent receives no listing and needs the owner to enable listing in a later unlocked session

#### Scenario: Owner stops listing
- **WHEN** the owner stops listing while the vault remains unlocked
- **THEN** pending responses are revoked and new requests return no entry data

### Requirement: Return only approved entry metadata

The CLI SHALL expose `keepassxc-agent entries list --json` with JSON rows containing only `id`, `title`, and `group_path`. The ID SHALL stay the same when an entry is renamed or moved. The group path SHALL be an ordered list of names relative to the database root. Entries in the configured recycle bin SHALL be excluded.

#### Scenario: List active entries in a synthetic vault
- **WHEN** a permitted agent lists a vault containing duplicate titles, nested groups, a root entry, and a recycled entry
- **THEN** active entries include distinct IDs and their correct group paths, the root entry has an empty group path, and the recycled entry is excluded

#### Scenario: Vault contains credential and note fields
- **WHEN** a permitted agent lists entries with passwords, URLs, usernames, notes, or attachments
- **THEN** output and application diagnostics omit those fields and the CLI writes only the documented JSON object to standard output

#### Scenario: Vault is empty
- **WHEN** a permitted agent lists a vault without active entries
- **THEN** the CLI exits successfully with an empty entries array

### Requirement: Fail without leaking vault data

The CLI SHALL exit nonzero on unavailable access, request failure, or an incomplete response. It SHALL show a brief diagnostic without vault data or unlock material. The broker SHALL reject operations outside the listing contract and bound request and response sizes and time.

#### Scenario: Broker is inaccessible or vault access is off
- **WHEN** the CLI cannot complete a listing because the broker is unavailable, the vault is locked, or listing has been disabled
- **THEN** the CLI reports that listing is unavailable and tells the caller to check with the owner

#### Scenario: Client requests an unsupported operation or sends an oversized message
- **WHEN** an authorized peer submits an invalid or unsupported request
- **THEN** the request fails and the broker remains usable for a later valid listing
