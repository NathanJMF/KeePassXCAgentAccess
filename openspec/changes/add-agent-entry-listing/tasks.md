# Tasks

## 1. Owner-side entry listing

- [x] 1.1 Extend the worker and session API with a bounded, read-only listing operation. Verify stable IDs, nested and root group paths, duplicate titles, empty vaults, recycle-bin exclusion, and omission of credential fields with synthetic databases.
- [x] 1.2 Add a Unix socket broker with an authorized UID, strict request validation, size and time limits, and short diagnostics. Verify an allowed UID succeeds, another UID is rejected even if it can connect, and invalid or oversized requests leave the broker available.
- [ ] 1.3 Wire the broker to the tray's current unlocked session and add the listing controls. Verify startup is disabled, explicit enable works, and disable, lock, vault change, and exit revoke access. Exercise revocation during a pending response and verify restart stays disabled.

## 2. Agent-facing command and skill

- [ ] 2.1 Add the CLI entry point and document how to provision the owner-controlled socket path and set `KEEPASSXC_AGENT_SOCKET` in the isolated runtime. Verify the documented command prints exactly the JSON listing on success and exits nonzero with empty standard output on unavailable or malformed replies.
- [ ] 2.2 Write the portable KeePass agent skill with one example command, output field descriptions, and guidance for unavailable access. Read the file on its own to verify it contains the information needed and uses synthetic examples.

## 3. Independent acceptance test

- [ ] 3.1 Prepare a private synthetic vault, enable listing for an isolated runtime, and put the CLI on its PATH. Verify the runtime cannot reach the fixture files, owner's keyring or desktop, and that listing stops after the owner revokes access.
- [ ] 3.2 Give a fresh subagent only the skill and a task to list entry titles and groups. Verify it called the CLI and returned the independently expected titles and group paths from the synthetic vault. Record the result using synthetic data.
