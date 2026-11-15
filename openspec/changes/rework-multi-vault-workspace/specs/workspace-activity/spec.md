# Workspace Activity

## Purpose

Give the owner one local audit view for token decisions and agent requests across registered vaults.

## ADDED Requirements

### Requirement: Show Activity in the main pane

The Activity view SHALL retain the column order **Time**, **Model**, **Chat**, **Action**, **Outcome**. It SHALL show newest requests first by their original timestamp and support filtering by vault, agent, model, chat, action, and outcome. Row details SHALL show the available vault, token record, project, entry, destination, authorization, and timing context.

#### Scenario: Similar entry names in two vaults
- **WHEN** two requests refer to entries with the same title in different vaults
- **THEN** each Activity row can be identified by vault and agent through its details and filters

### Requirement: Record token decisions and protected operations

Activity SHALL record token requests, decisions, disables, re-enables, removals, and operation outcomes. The history SHALL persist independently of the active Access rows. Model and chat labels SHALL show their provenance or be marked unavailable.

#### Scenario: Removed token is absent from Access
- **WHEN** the owner removes a token
- **THEN** its removal and past requests remain visible in Activity for the configured retention period

#### Scenario: Agent request revoked by a lock
- **WHEN** the app invalidates an operation before delivery because a vault or global lock intervenes
- **THEN** Activity shows the revoked outcome without recording a successful use

### Requirement: Keep audit data owner-only across upgrades

Existing activity SHALL be preserved after migration. Historical records without reliable vault or token identifiers SHALL show those fields as unavailable. The broker SHALL preserve durable authorization recording before protected work. The log SHALL exclude runner credentials, vault passwords, authorization headers, and raw endpoint content.

#### Scenario: Open history created before token-scoped access
- **WHEN** the owner opens the Activity pane after upgrading
- **THEN** older and newer records remain browsable, and older rows disclose absent token and vault attribution
