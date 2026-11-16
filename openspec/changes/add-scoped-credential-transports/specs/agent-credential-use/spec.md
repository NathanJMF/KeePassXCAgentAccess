# Agent Credential Use

## ADDED Requirements

### Requirement: Owner approves a reusable operation scope

Keeper SHALL bind authorization to an agent token, entry, transport, destination, operation, and binding revision. Existing per-use review and revocation settings SHALL apply to each use. The installed runner SHALL be available independently of the agent's working directory.

#### Scenario: Agent reuses an approved grant
- **WHEN** the agent requests the same enabled operation from another checkout and per-use review is off
- **THEN** Keeper performs the operation within the grant without asking the owner to enter a credential or approve again

#### Scenario: Operation binding changes
- **WHEN** the owner changes the destination, operation, or other authorization-relevant parameters
- **THEN** the prior grant cannot authorize use of the changed binding

### Requirement: Git push uses an approved repository and branch

Keeper SHALL execute a Git HTTPS push from a fresh private bare repository using one validated commit and one owner-bound branch. The repository SHALL have its own object store and SHALL NOT import bundle-provided refs. The broker SHALL accept bounded bundle bytes rather than opening a path supplied by an agent. The authenticated process SHALL use fixed trusted configuration and a private credential exchange.

#### Scenario: Agent submits a valid push
- **WHEN** a granted agent supplies a valid bundle and commit ID
- **THEN** Keeper can push the commit to the bound branch without force and returns a bounded result

#### Scenario: Request exceeds the approved scope
- **WHEN** the request tries to alter the remote or branch, use Git options supplied by the agent, or cross a resource limit
- **THEN** Keeper rejects it before releasing a credential

### Requirement: API and browser results protect credentials and sessions

An API transport SHALL enforce a bound method, endpoint, input schema, and result schema. A browser transport SHALL keep authenticated browser state in a private context and enforce bound origins and typed operations.

#### Scenario: A destination returns sensitive data
- **WHEN** a remote operation echoes its authorization header or creates a new secret or session
- **THEN** the agent receives only the permitted structured result and no credential or session data

### Requirement: Activity records every credential use

Keeper SHALL record the requesting agent, entry, action, destination, authorization decision, and outcome for each use. The broker SHALL persist admission and dispatch state and bind retry identifiers to the token, binding revision, and input digest. It SHALL make ambiguous remote outcomes visible and SHALL NOT automatically retry an authenticated mutation.

#### Scenario: Authorization changes while work is pending
- **WHEN** the token is revoked or the vault locks before credential delivery
- **THEN** Keeper stops the operation and records the denial or revocation

#### Scenario: The connection ends after dispatch
- **WHEN** Keeper cannot establish whether the destination accepted a dispatched mutation
- **THEN** Activity records the outcome as uncertain and the broker does not automatically repeat it

#### Scenario: Agent repeats an earlier request ID
- **WHEN** an agent repeats a request ID with the same binding revision and input
- **THEN** Keeper reports the existing outcome without delivering a credential again
- **AND WHEN** the same ID is used with different input or a different binding revision
- **THEN** Keeper rejects the request
