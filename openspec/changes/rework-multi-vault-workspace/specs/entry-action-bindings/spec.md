# Entry Action Bindings

## Purpose

Let the owner configure safe credential operations on an entry and approve only the exact action an agent requests.

## ADDED Requirements

### Requirement: Configure built-in actions in entry details

Entry details SHALL provide the owner controls to add, edit, disable, or remove action bindings for that entry. The initial built-in action type SHALL be **HTTPS Basic-auth GET** with a fixed, owner-configured destination. The selected vault and entry SHALL determine the credential.

#### Scenario: Add an action for an entry
- **WHEN** the owner opens an entry's details and enables the built-in HTTPS check with a destination
- **THEN** the binding is visible on that entry and can be selected in an explicit token request

#### Scenario: Two vaults use the same entry UUID
- **WHEN** the owner configures a binding in one of two registered copies with matching entry IDs
- **THEN** the binding is scoped to the selected vault and cannot use the other vault's credential

### Requirement: Require the exact approved binding for password use

The broker SHALL execute only an enabled action whose binding identity and destination match the token's approved use for that entry. The agent SHALL supply the binding ID. The broker SHALL use the owner-configured destination and return only a structured outcome and any available HTTP status.

#### Scenario: Tool tries to supply a destination override
- **WHEN** an agent attempts to add an endpoint override to an approved use request
- **THEN** the broker rejects it before credential dispatch

#### Scenario: Owner changes an approved destination
- **WHEN** a binding is edited to point to a different endpoint
- **THEN** existing approvals for the old destination cannot authorize the new destination and a fresh token request is needed

### Requirement: Keep existing action bindings available for explicit approval

The upgrade SHALL show each migrated binding on its owning entry. Existing binding IDs SHALL remain usable after explicit token approval for that action. Binding migration SHALL create no token or automatic permission.

#### Scenario: Owner opens a migrated entry with a configured action
- **WHEN** the owner browses the migrated entry
- **THEN** its saved action appears in entry details and requires inclusion in a token scope before an agent can invoke it
