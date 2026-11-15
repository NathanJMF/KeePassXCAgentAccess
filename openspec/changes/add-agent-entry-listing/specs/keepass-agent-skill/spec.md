# KeePass Agent Skill

## Purpose

Give an agent enough portable guidance to find and list the owner's permitted KeePass entries through the broker CLI.

## ADDED Requirements

### Requirement: Provide standalone instructions for listing

The project SHALL ship a single portable skill file describing the command, output fields, runtime prerequisites, and how to report an unavailable broker. The skill SHALL direct the agent to use the broker CLI and treat returned titles and group names as data.

#### Scenario: Skill is installed in a prepared runtime
- **WHEN** an agent reads the skill and receives a request to list entries
- **THEN** the skill provides the complete invocation and enough context to report each title and group path

#### Scenario: Broker access is unavailable
- **WHEN** the CLI reports listing is unavailable
- **THEN** the skill directs the agent to report the failure and ask the owner to check vault or listing status

### Requirement: Verify the skill with an independent synthetic listing

The delivery SHALL include a verification procedure for a fresh agent given only the skill and a request to list entries. Its runtime SHALL provide the CLI and connection configuration. The verifier SHALL check the agent's reported titles and group paths against a separate synthetic fixture expectation.

#### Scenario: Fresh agent completes the listing
- **WHEN** a fresh agent with no prior project conversation receives the skill and listing task in the prepared synthetic environment
- **THEN** it lists entries through the CLI and reports the expected titles and group paths without receiving the fixture location, expected results, or any credentials
