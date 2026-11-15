# KeePass Vault Setup

## Purpose

Let the desktop owner connect an existing KeePass vault and use the system keyring to replace a plaintext unlock file.

## ADDED Requirements

### Requirement: Verify the selected vault before saving setup

The desktop app SHALL let the owner select an existing KeePass database and enter its password, with an optional key file. It SHALL verify a successful read-only unlock before saving the configuration or saving the password.

#### Scenario: Valid vault credentials
- **WHEN** the owner selects a supported database and supplies the correct unlock factors
- **THEN** the app verifies the unlock and allows setup to complete without modifying the database

#### Scenario: Vault cannot be opened
- **WHEN** the database or required key file is missing, unreadable, invalid, or unsupported, or the password is rejected
- **THEN** the app gives a recoverable setup error and leaves the previously saved configuration, if any, in place

### Requirement: Remember the password in the OS keyring

The app SHALL persist a database password only in the OS keyring and only after explicit owner opt-in. The app SHALL treat the password as session-only when the owner leaves the option off.

#### Scenario: Remember a verified password
- **WHEN** the owner enables **Remember on this device** and the keyring confirms storage
- **THEN** the saved vault can be unlocked from the tray after a fresh app launch using the saved password and any configured key file

#### Scenario: Configure without remembering
- **WHEN** the owner completes first-run setup with **Remember on this device** off
- **THEN** the next unlock requires password entry in the desktop app

#### Scenario: Keyring storage fails
- **WHEN** the OS keyring is unavailable or rejects the storage request
- **THEN** the app reports that the password was unsaved and lets the owner retry or explicitly finish setup without remembering it

#### Scenario: Saved credential cannot be retrieved
- **WHEN** the keyring denies or cancels retrieval, the item is missing, or the saved password no longer opens the vault
- **THEN** the vault stays locked and the app shows a recovery path to retry or enter and verify the current password

### Requirement: Remove obsolete app-owned keyring items

The app SHALL preserve the active saved credential until a replacement or session-only configuration is committed. It SHALL remove obsolete app-owned items after the commit. If removal fails, the app SHALL keep those items ineligible for unlock, show cleanup as pending across restarts, and let the owner retry from Settings.

#### Scenario: Replace a saved password
- **WHEN** the owner successfully saves a verified replacement password
- **THEN** the app uses the replacement for subsequent unlocks and removes the obsolete item

#### Scenario: Switch an existing configuration to session-only use
- **WHEN** the owner successfully switches from a saved password to session-only use
- **THEN** the app removes the former saved item and asks for the password on the next unlock

#### Scenario: Commit a configuration change fails
- **WHEN** the app cannot save the replacement or session-only configuration
- **THEN** the previously saved configuration and its active item remain available

#### Scenario: Obsolete item deletion fails after save
- **WHEN** the keyring rejects obsolete item deletion after the configuration is saved
- **THEN** the new configuration stays active and Settings shows pending cleanup after restart until deletion succeeds

### Requirement: Forget the saved password

The app SHALL lock the vault and disable the active saved item for unlock when the owner selects **Forget saved password**. It SHALL report success after the active item and any pending obsolete items have been removed or confirmed absent.

#### Scenario: Removal succeeds
- **WHEN** the owner selects **Forget saved password** and the active item and all pending obsolete items are deleted or already absent
- **THEN** the vault is locked, the app shows the password as unsaved, and the next unlock requires password entry

#### Scenario: Removal fails
- **WHEN** the OS keyring rejects deletion
- **THEN** the vault is locked, the next unlock requires password entry, and the app reports pending cleanup and offers a retry

### Requirement: Verify keyring cutover before retiring plaintext

The app SHALL provide a desktop way to verify a fresh unlock from the keyring and show whether it succeeded. Retirement guidance SHALL direct the owner to rotate a password that was stored in plaintext and retire the legacy file only after verifying unlock with the replacement password.

#### Scenario: Keyring-only cutover rehearsal succeeds
- **WHEN** the app restarts and the owner unlocks using the verified keyring item and any configured key file while the legacy plaintext file is unavailable
- **THEN** the app shows the vault as unlocked and confirms the saved credential worked

#### Scenario: Keyring-only cutover rehearsal fails
- **WHEN** the app cannot unlock with the keyring after restart
- **THEN** the app offers manual recovery and leaves retirement pending for the owner

### Requirement: Keep unlock material in the owner session

The app SHALL confine unlock credentials to the owner-side setup, keyring, and vault backend. The supported deployment SHALL run agents under a separate, unprivileged OS account and deny that account direct access to the owner's vault files, keyring session, process memory, and desktop controls. Passwords SHALL be absent from configuration, logs, command arguments, and exported results.

#### Scenario: Inspect a configured deployment from the agent runtime
- **WHEN** a process under the separate agent account attempts to read the vault or key file, retrieve the OS keyring item, inspect the owner process, or use its desktop controls while the owner's desktop and vault are unlocked
- **THEN** the deployment denies those attempts

#### Scenario: Check local data for plaintext after setup
- **WHEN** setup, unlock, and error handling are exercised with a synthetic password
- **THEN** the password is absent from app-generated settings and logs, process arguments, and captured output
