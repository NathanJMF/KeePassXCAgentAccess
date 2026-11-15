# Multi-Vault Workspace

## Purpose

Give the owner a KeePass-style workspace for browsing multiple registered vaults and controlling each vault session independently.

## ADDED Requirements

### Requirement: Register vaults independently

The owner SHALL be able to add, rename, relink, and remove registered KeePass files. Each record SHALL have a stable local vault ID, independent unlock settings, and an optional saved OS keyring credential. Adding a vault SHALL verify its unlock factors and reuse or reject a registration for the same file.

#### Scenario: Add a second vault
- **WHEN** the owner adds and verifies a second database
- **THEN** both vaults appear in the sidebar with independent names and unlock controls

#### Scenario: Remove a vault registration
- **WHEN** the owner removes a vault
- **THEN** the application ends its session, removes its agent scope and app-owned saved credential, and leaves the database file in place

#### Scenario: Relink a moved vault
- **WHEN** the owner selects a new path for a registered vault
- **THEN** the application verifies the expected vault before retaining its local ID and access settings, and requires a new registration for a different vault

### Requirement: Maintain independent vault sessions

The application SHALL support multiple unlocked vaults at once. Locking, removing, or losing one session SHALL cancel work for that vault and clear its unlocked metadata from the owner view. Other unlocked vaults SHALL retain their sessions.

#### Scenario: Lock one of two unlocked vaults
- **WHEN** the owner locks one vault from its sidebar controls
- **THEN** that vault shows as locked and hides its groups while the other remains available

#### Scenario: Desktop session locks
- **WHEN** the owner desktop locks, logs out, or the application exits
- **THEN** all unlocked vault workers are closed and pending vault operations are invalidated

### Requirement: Browse groups and entries in the main pane

The sidebar SHALL display registered vaults and expandable nested groups for unlocked ones. Selecting a vault root or group SHALL show the entries directly in that selection. Selecting an entry SHALL show its owner-side details, including its configured actions.

#### Scenario: Navigate to a nested group
- **WHEN** the owner expands an unlocked vault and selects a nested group
- **THEN** the main pane shows that group's direct entries and identifies the vault and group selection

#### Scenario: Select a locked vault
- **WHEN** the owner selects a locked vault
- **THEN** the main pane offers that vault's unlock controls without exposing its groups or entries

### Requirement: Switch owner views without losing vault navigation

The app SHALL keep the vault tree visible while **Activity** and **Access** at the bottom right replace the main pane with their respective tables. Selecting a vault or group SHALL return to browsing. Switching views SHALL preserve the last valid vault and group selection.

#### Scenario: Open Access and return to entries
- **WHEN** the owner opens Access while browsing a selected group and then selects that group in the sidebar
- **THEN** the main pane returns to its entries with the vault tree and expansion state preserved
