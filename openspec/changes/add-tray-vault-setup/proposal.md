# Proposal

## Why

A plaintext unlock file lets any process with read access attempt to open the KeePass database directly. The first release needs an owner-controlled desktop setup flow that can replace the file with OS keyring storage and provide a safe foundation for future agent access.

## What Changes

- Add a Linux system tray app with a setup or settings window, visible vault lock status, and explicit unlock and lock actions.
- Add first-run setup for one existing KeePass database, with an optional key file. Verify the supplied unlock credentials before completing setup.
- Offer **Remember on this device** to save the verified password in the OS keyring. Support unlocking from the tray after restart and forgetting the saved password from Settings.
- Provide a guided cutover that verifies a fresh unlock using the keyring before the owner retires the legacy plaintext file. Keep the vault and unlock material behind the owner-side process boundary.

## Capabilities

### New Capabilities

- **`keepass-vault-setup`** covers vault selection, unlock verification, keyring storage and removal, and cutover from a plaintext unlock file.
- **`tray-vault-control`** covers tray status, setup and settings access, and the lifetime of an unlocked vault session.

### Modified Capabilities

## Impact

Adds a Linux desktop component, an owner-side KeePass backend, and integrations with the system tray and OS keyring. The existing KeePass database stays the source of truth. Agent requests, approvals, and activity history can build on these controls in later changes.
