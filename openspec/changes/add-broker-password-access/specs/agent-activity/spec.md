# Agent Activity

## Purpose

Give the owner a local history of agent requests, decisions, and results with honest model and chat attribution.

## ADDED Requirements

### Requirement: Register an agent session on first request

The broker SHALL create an activity session on an eligible agent's first request without a separate registration prompt. It SHALL record the verified OS identity and any supplied model or chat metadata with its provenance. Reported model or chat details SHALL confer no access.

#### Scenario: Runtime supplies model and chat labels
- **WHEN** the broker receives model and chat fields alongside a request
- **THEN** the Activity view shows the labels and discloses whether their provenance is verified or agent-reported

#### Scenario: Host cannot supply conversation context
- **WHEN** the model or chat label is unavailable
- **THEN** Activity displays it as unavailable while the request follows the same policy

#### Scenario: Model changes in one conversation
- **WHEN** a later request uses a different model in the same reported chat
- **THEN** each activity row retains its own model value

### Requirement: Persist the access decision before protected work

The broker SHALL record each accepted request and its outcome in owner-only local activity storage. It SHALL durably record authorization before dispatching credential use or releasing entry metadata. If that record cannot be saved, the operation SHALL fail closed.

#### Scenario: Policy allows a request automatically
- **WHEN** policy authorizes a valid action
- **THEN** Activity records the automatic decision, action, and observed result

#### Scenario: Owner declines or the request expires
- **WHEN** a request is declined, revoked, or expires without execution
- **THEN** Activity records the corresponding outcome and shows that execution did not start

#### Scenario: Activity storage fails
- **WHEN** the broker cannot persist the authorization
- **THEN** it returns a storage error and withholds the protected operation

### Requirement: Display the agreed Activity columns

The desktop app SHALL present columns in this order **Time**, **Model**, **Chat**, **Action**, **Outcome**. The owner SHALL be able to filter by chat, model, action, or outcome and inspect a row for verified client identity, provenance, authorization source, and available request, decision, and completion times.

#### Scenario: Owner opens Activity
- **WHEN** the owner opens Activity from the desktop app or tray
- **THEN** the rows appear newest first in the agreed column order, with timestamps shown in local time

### Requirement: Keep history local and exclude raw credential data

Activity SHALL store selected request metadata and structured outcomes under the owner's account with configurable retention. It SHALL exclude passwords, authorization headers, raw request payloads, and raw tool or endpoint output.

#### Scenario: Agent action uses a synthetic credential
- **WHEN** a credential-use request is approved and completes
- **THEN** the activity record contains the action and result fields and no secret values or raw output
