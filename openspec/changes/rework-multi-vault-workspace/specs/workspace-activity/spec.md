# Workspace Activity

## Purpose

Give the owner one local audit view for token decisions and agent requests across registered vaults.

## ADDED Requirements

### Requirement: Show Activity in the main pane

The Activity view SHALL present **Time**, **Model**, **Chat**, **Action**, **Vault**, **Target**, and **Outcome**, newest requests first. It SHALL support filtering by vault, agent, model, chat, action, and outcome. The Target column SHALL use recorded folder and entry names when available.

#### Scenario: Inspect a recorded action
- **WHEN** the owner opens an Activity row
- **THEN** details lead with the action, outcome, and time, show available Vault, Folder, and Entry values separately, and collapse technical identifiers and scope

#### Scenario: Similar entry names in two vaults
- **WHEN** two requests refer to entries with the same title in different vaults
- **THEN** each Activity row displays its recorded vault and target beside the action, with the agent available in row details and filters

#### Scenario: Historical record has an entry ID but no entry name
- **WHEN** an owner opens an older record whose exact vault and entry match an existing unlocked owner session
- **THEN** the details can show the available current name and folder labelled as current, preserving the original audit record

#### Scenario: Historical record has no available current vault session
- **WHEN** a record predates target snapshots and the named vault is locked or unavailable
- **THEN** the action and outcome remain readable and any recorded identifiers stay available under Technical details

### Requirement: Record token decisions and protected operations

Activity SHALL record token requests, decisions, disables, re-enables, removals, and operation outcomes. The history SHALL persist independently of the active Access rows. Model and chat labels SHALL show their provenance or be marked unavailable.

#### Scenario: Removed token is absent from Access
- **WHEN** the owner removes a token
- **THEN** its removal and past requests remain visible in Activity for the configured retention period

#### Scenario: Agent request revoked by a lock
- **WHEN** the app invalidates an operation before delivery because a vault or global lock intervenes
- **THEN** Activity shows the revoked outcome without recording a successful use

### Requirement: Keep audit data owner-only across upgrades

Existing activity SHALL be preserved after migration. Historical detail views SHALL omit unavailable values. The broker SHALL preserve durable authorization recording before protected work. The log SHALL exclude runner credentials, vault passwords, authorization headers, and raw endpoint content.

#### Scenario: Open history created before token-scoped access
- **WHEN** the owner opens the Activity pane after upgrading
- **THEN** older and newer records remain browsable with their available context
