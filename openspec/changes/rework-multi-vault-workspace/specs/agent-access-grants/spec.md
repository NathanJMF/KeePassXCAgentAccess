# Agent Access Grants

## Purpose

Give the owner a token management view where each approval covers a specific set of secrets and allowed operations.

## ADDED Requirements

### Requirement: Request a specific set of secrets and uses

An eligible isolated runtime SHALL be able to submit a pending token request listing one or more entries and the requested operations for each. An item SHALL identify an entry with an owner-provided reference or a label for owner resolution. Pending requests SHALL expose no vault data. Repeating the same pending request with the same runner identity SHALL return its current state without creating a duplicate.

#### Scenario: Agent requests the entries it needs
- **WHEN** an agent requests metadata for one known reference and password use for another entry by name
- **THEN** Access displays both requested items and uses and the agent receives a pending status

#### Scenario: A name is ambiguous
- **WHEN** a request gives an entry name shared by multiple entries
- **THEN** the agent receives no match information and the owner must choose a specific entry before approving

### Requirement: Review and decide the exact token scope

Double-clicking a pending row SHALL show the request time, requesting identity, project, resolved vault and entry paths, and requested operations. The owner SHALL be able to confirm name-to-entry matches and use **Approve** or **Deny**. Approval SHALL fix the exact scope for that token. A broader scope SHALL require a new request and token.

#### Scenario: Approve a token for specific entries
- **WHEN** the owner approves a request for one entry's metadata and one configured action on another entry
- **THEN** the token can perform only those approved operations, and other entries remain outside its scope

#### Scenario: Requested action is unavailable
- **WHEN** a named binding cannot be resolved or changes before the owner confirms
- **THEN** the app requires fresh review of the exact binding before granting any access

#### Scenario: Owner denies the request
- **WHEN** the owner chooses Deny
- **THEN** the request leaves the Access table, Activity records the denial, and the denied credential gains no access

### Requirement: Authenticate each token and disclose identity provenance

The broker SHALL bind each token to its admitted OS peer and use a distinct unguessable runner credential. The approved scope SHALL be tied to that credential. The UI SHALL distinguish the verified OS identity from reported agent and project labels. Token credentials SHALL be excluded from prompts, command arguments, and Activity.

#### Scenario: Another client copies a display label
- **WHEN** a different peer provides the same identity and project labels
- **THEN** it gains none of the existing token's access

### Requirement: Manage tokens in one Access table

The Access pane SHALL show **Requested**, **Identity**, **Project**, **Status**, and **Last used** in one table. Pending requests SHALL appear above approved tokens, with newest requested times first within each group. Disabled tokens SHALL remain in the approved group until removed.

#### Scenario: Pending and approved rows are mixed
- **WHEN** the owner opens Access with pending, active, and disabled rows
- **THEN** Pending appears first, followed by Active and Disabled, ordered by request time within each group

### Requirement: Disable, re-enable, or remove an individual token

Double-clicking an approved token SHALL show its scope and the applicable **Disable**, **Re-enable**, or **Remove** controls. Disable and Remove SHALL revoke live use for that token. Re-enable SHALL restore its approved scope subject to current availability. A removed credential SHALL require replacement and fresh approval.

#### Scenario: Disable one of two tokens
- **WHEN** an agent has two active tokens and the owner disables one
- **THEN** only the selected token loses access and the other keeps its own scope

### Requirement: Advance last used on successful broker use

The broker SHALL record the latest successful authenticated operation for each token, including scoped vault discovery. Pending, denied, and failed requests SHALL leave it unchanged. A token with no successful operation SHALL show an empty last-used value.

#### Scenario: First successful listing after approval
- **WHEN** an approved token successfully lists its available vaults
- **THEN** Last used displays the time of that operation and Requested retains the original request time
