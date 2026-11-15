## ADDED Requirements

### Requirement: Request one vault edit

An admitted runtime with an active token SHALL be able to submit a typed request naming a stable vault and exact entry or group references. The request SHALL include a caller-generated UUID. Submission and status SHALL disclose no existing vault content or target matches. Reviewing or applying the request SHALL confer no new standing read or use permission.

#### Scenario: Request an edit with an owner-provided entry ID
- **WHEN** a token submits a metadata edit with an exact entry reference
- **THEN** the token receives pending status and the owner can review it in Access

#### Scenario: Retry a request
- **WHEN** the token repeats the same request with the same UUID
- **THEN** Keeper returns the saved status and applies the operation at most once

### Requirement: Review exact values and effects

Access SHALL show the requester, vault, action, exact target, and destination where applicable. The review SHALL show changed metadata fields and values. Group moves and recycling SHALL disclose the contents affected by the operation. The owner SHALL be able to approve and apply once or deny.

#### Scenario: Review a metadata-only edit
- **WHEN** the owner reviews a request to change the title and URL
- **THEN** Keeper shows the current and proposed values and leaves other fields outside the approval

#### Scenario: Owner denies the edit
- **WHEN** the owner denies the request
- **THEN** the vault stays unchanged and the token sees denied status

### Requirement: Apply approved operations with guarded persistence

Keeper SHALL support creating entries, updating entry metadata, creating or renaming groups, moving and recycling entries or groups within one vault, and explicit password replacement. Before publication it SHALL verify that the approving snapshot still applies, the originating token remains active, and the applicable vault and global access state permit work.

#### Scenario: Vault changes after it is reviewed
- **WHEN** the approved snapshot changes before publication
- **THEN** Keeper leaves the newer state intact and requires fresh review before applying an edit

#### Scenario: The owner revokes the originating token while work is staged
- **WHEN** the token is disabled before publication
- **THEN** the vault worker does not publish the change

#### Scenario: Apply was interrupted
- **WHEN** Keeper restarts and cannot establish whether a previous edit was published
- **THEN** it reports an interrupted outcome and does not replay the edit

### Requirement: Keep credential values within the owner boundary

An edit request SHALL accept only an owner-entered or Keeper-generated password source for password replacement. The runner SHALL neither send nor receive a password through the edit API. A credential change SHALL invalidate affected credential action approvals.

#### Scenario: Replace the password on an entry with an approved action
- **WHEN** the owner applies an approved password replacement
- **THEN** the new value remains inside the owner boundary and the old action approval cannot send it

### Requirement: Audit each edit decision

Activity SHALL record the token, target, operation, changed field names, and outcome. Activity and agent status SHALL omit credential values. A successful create MAY return the new item UUID.

#### Scenario: An agent checks an edit it submitted
- **WHEN** it checks that request with the same token after approval
- **THEN** Keeper returns its saved outcome and the UUID of the new item if one was created
