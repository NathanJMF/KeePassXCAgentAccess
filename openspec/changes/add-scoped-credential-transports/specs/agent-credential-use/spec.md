# Agent Credential Use

## ADDED Requirements

### Requirement: Owner approves a reusable delivery policy

Keeper SHALL bind an agent's authorization to an entry and the revision of an approved delivery policy. Changing the consumer or permitted arguments SHALL require renewed authorization. The runner SHALL accept an opaque credential reference independently of the caller's working directory.

#### Scenario: Agent reuses an approved local command
- **WHEN** an entitled agent requests the exact approved command and per-use review is off
- **THEN** Keeper delivers the credential through the approved channel without further owner input

#### Scenario: Agent supplies a different command
- **WHEN** the supplied executable or arguments differ from the grant
- **THEN** Keeper refuses before releasing the credential

### Requirement: Local command delivery keeps credentials inside its sandbox

Keeper SHALL start the approved system executable in a restricted process environment with read-only system files, private temporary storage, resource and lifetime limits, and no network or host workspace access. Keeper SHALL recheck authorization after sandbox readiness and SHALL send the secret only on the command's private stdin. Keeper SHALL return a bounded, structured outcome.

#### Scenario: Sandbox cannot start
- **WHEN** Keeper cannot establish the required isolation
- **THEN** the command receives no credential and the agent sees a safe failure

#### Scenario: Command echoes its input
- **WHEN** the command writes the received secret to stdout or stderr
- **THEN** the broker returns only its structured outcome and records no output or secret

### Requirement: Activity records credential use

Keeper SHALL record the requesting agent, entry, configured action, destination or exact command binding, authorization decision, and outcome of a credential-use attempt. It SHALL exclude the secret and raw tool output.

#### Scenario: Authorization is revoked while preparing work
- **WHEN** the owner pauses or the token changes before private stdin delivery
- **THEN** Keeper blocks delivery and records the revocation


### Requirement: Networked command delivery is scoped and auditable

Keeper SHALL bind a networked command to a trusted executable and exact argv, a credential prompt policy, and an approved host and port. It SHALL block direct networking and arbitrary host paths. It SHALL verify the length and digest of input artifacts before mounting them read-only. The trusted command SHALL enforce TLS and application-level resource scope.

#### Scenario: Agent pushes a synthetic Git commit
- **WHEN** an entitled agent runs the configured Git command with a valid input artifact
- **THEN** the credential is delivered only inside the job and Activity records the approved operation and outcome

#### Scenario: Networked command chooses another origin
- **WHEN** the command asks the relay to connect to a different host or port
- **THEN** the relay refuses without connecting

#### Scenario: A networked command fails after sending traffic
- **WHEN** Keeper cannot establish whether the remote accepted a dispatched operation
- **THEN** it records an uncertain result and does not retry
