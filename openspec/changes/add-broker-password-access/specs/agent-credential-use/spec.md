# Agent Credential Use

## Purpose

Let an isolated agent request a specific action that uses a KeePass password inside the owner's trusted runtime.

## ADDED Requirements

### Requirement: Owner configures the credential action and destination

The desktop app SHALL let the owner create, edit, disable, and remove an action binding one entry ID to one HTTPS Basic-auth GET endpoint. The agent SHALL identify the action and entry by ID. A request with an unknown, disabled, or mismatched binding SHALL be denied in every access mode.

#### Scenario: Request matches an enabled action
- **WHEN** an eligible agent names an enabled action and its bound entry
- **THEN** the broker evaluates access policy for that exact action and entry

#### Scenario: Agent attempts to alter routing
- **WHEN** the agent supplies a different entry, a URL override, or unsupported request fields
- **THEN** the broker declines the request and sends no authenticated traffic

### Requirement: Credential delivery is limited to the configured destination

The broker SHALL apply the credential only after authorization, over TLS with certificate and hostname verification, to the configured endpoint. Dispatch SHALL use the configured method, host, port, and path. Redirects, proxy discovery from the environment, and automatic retries SHALL be disabled for this action.

#### Scenario: Approved action reaches the configured endpoint
- **WHEN** the owner or policy authorizes a valid action
- **THEN** the configured endpoint receives one authenticated request and the CLI returns a bounded result

#### Scenario: Endpoint redirects or fails TLS verification
- **WHEN** the configured endpoint redirects or TLS verification fails
- **THEN** the CLI reports a safe failure and the broker sends no credential to another destination

### Requirement: Agent receives a bounded result

The broker SHALL expose only an action result and, when received, an HTTP status code. Vault credentials, authorization headers, remote response content, and raw diagnostics SHALL be excluded from agent responses and history.

#### Scenario: Endpoint echoes its received credentials
- **WHEN** a synthetic configured endpoint echoes its authorization material in the response body or headers
- **THEN** the agent and activity log see only the permitted result fields
