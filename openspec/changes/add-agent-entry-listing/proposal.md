# Proposal

## Why

The tray app can unlock a KeePass vault for its owner. A small read-only broker and a portable skill will let an isolated agent list entries through that session and give us a reproducible way to test the agent workflow with a synthetic vault.

## What Changes

- Add one broker operation for listing the stable ID, title, and root-relative group path of each active entry in the current vault.
- Add `keepassxc-agent entries list --json`. The CLI connects locally through an owner-provisioned Unix socket.
- Give the owner a tray control to start or stop listing for one configured, separate agent account. Access starts off and ends with the current unlocked vault session.
- Ship a standalone KeePass agent skill with the command, output fields, and recovery guidance.
- Verify that a fresh subagent given the skill and a simple listing task can discover the command and report the expected entries from a synthetic vault.

## Capabilities

### New Capabilities

- **`agent-entry-listing`** governs owner-authorized access to read-only vault entry metadata through the local broker and CLI.
- **`keepass-agent-skill`** defines the portable instructions and their acceptance test with a fresh agent.

### Modified Capabilities

## Impact

Extends the tray app and read-only KeePass worker introduced by `add-tray-vault-setup`. Adds a local CLI, a reusable skill, and a synthetic acceptance test. This milestone exposes titles, group paths, and IDs for the listing workflow. Login metadata, credential use, writes, access modes, registration, and activity history are future changes.
