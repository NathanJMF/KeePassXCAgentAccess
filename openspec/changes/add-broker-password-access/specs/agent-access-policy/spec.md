# Agent Access Policy

## Purpose

Let the owner decide which eligible agent requests run automatically and which wait for a desktop decision.

## ADDED Requirements

### Requirement: Owner controls the access mode and per-entry flags

The desktop app SHALL offer **Allow all**, **Review all**, and **Smart access** and default to **Review all** on upgrade or first use. The owner SHALL be able to set **Require approval** for an entry. Unconfigured entries SHALL require approval in Smart access. Entry flags SHALL follow the entry ID within the configured vault.

#### Scenario: Owner changes a setting
- **WHEN** the owner saves an access mode or entry flag in the desktop app
- **THEN** the setting persists across restart and applies to subsequent requests

#### Scenario: Entry has no saved flag
- **WHEN** Smart access evaluates an entry without a saved review flag
- **THEN** a request to use that entry requires approval

### Requirement: Apply the selected mode to eligible operations

The broker SHALL check the authorized OS peer, unlocked vault, enabled agent access, and operation eligibility before applying the selected mode. **Allow all** SHALL run eligible requests automatically. **Review all** SHALL prompt for each eligible listing or credential use. **Smart access** SHALL prompt on credential use when its entry requires approval.

#### Scenario: Allow all still enforces eligibility
- **WHEN** an eligible client names an unregistered credential action in Allow all
- **THEN** the broker declines the action without displaying an approval prompt

#### Scenario: Review all gates a listing
- **WHEN** the agent requests a listing in Review all
- **THEN** one approval covers the bounded set of entries in that request and no entries are released before approval

#### Scenario: Smart access handles flagged and unflagged use
- **WHEN** separate eligible requests use an unflagged entry and an entry requiring approval
- **THEN** the unflagged use runs automatically and the other waits for approval

### Requirement: Smart listing separates automatically available entries

A standard listing in Smart access SHALL return only entries that can be listed automatically. The CLI SHALL support explicitly requesting reviewed entries in the same listing, with one approval for the bounded result. Listing SHALL retain its documented fields and JSON shape.

#### Scenario: Agent lists entries in Smart access
- **WHEN** the vault has entries with both review settings and the agent requests a standard listing
- **THEN** the broker returns the automatically available rows and omits protected rows and their count

#### Scenario: Agent explicitly requests reviewed entries
- **WHEN** the owner approves an eligible request to include protected entries
- **THEN** the broker returns the entries covered by that exact listing request

### Requirement: Desktop approval applies to one exact request

The desktop app SHALL present **Approve once** and **Decline** for a reviewable request. The prompt SHALL show the operation, verified client identity, and affected entry or listing scope. Credential prompts SHALL show the configured action and destination. Approval SHALL authorize at most one execution of that request.

#### Scenario: Owner approves a credential use
- **WHEN** the owner approves a pending use request and its access conditions still hold
- **THEN** the broker dispatches the displayed operation at most once

#### Scenario: Owner declines, closes, or misses a request
- **WHEN** the owner declines, dismisses the prompt, or it expires
- **THEN** the CLI reports the decision and no protected metadata or credential is delivered

### Requirement: Revoke pending decisions when their context changes

Lock, stop access, client disconnect, app exit, or a change to the vault, policy, or destination SHALL invalidate affected pending requests. The broker SHALL recheck the live authorization before delivering a result or dispatching a credential.

#### Scenario: Vault locks before an approval completes
- **WHEN** an approval is pending and the vault locks
- **THEN** the prompt closes and a subsequent approval response cannot dispatch the action

#### Scenario: Owner changes an action after review
- **WHEN** a reviewed destination changes before the credential is dispatched
- **THEN** that request is cancelled and a new request requires a fresh access decision
