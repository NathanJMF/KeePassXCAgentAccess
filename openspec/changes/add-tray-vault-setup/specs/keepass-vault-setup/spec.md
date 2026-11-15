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

### Requirement: Forget the saved password

The app SHALL provide a desktop action to remove its saved password from the OS keyring and lock the vault. It SHALL report whether removal succeeded.

#### Scenario: Removal succeeds
- **WHEN** the owner selects **Forget saved password** and the item is removed or already absent
- **THEN** the vault is locked, the app shows the password as unsaved, and the next unlock requires password entry

#### Scenario: Removal fails
- **WHEN** the OS keyring rejects deletion
- **THEN** the vault is locked and the app reports that the saved password may still exist and offers a retry

### Requirement: Verify keyring cutover before retiring plaintext

The app SHALL provide a desktop way to verify a fresh unlock from the keyring and show whether it succeeded. Retirement guidance SHALL direct the owner to rotate a password that was stored in plaintext and retire the legacy file only after verifying unlock with the replacement password.

#### Scenario: Keyring-only cutover rehearsal succeeds
- **WHEN** the app restarts and the owner unlocks using the verified keyring item and any configured key file while the legacy plaintext file is unavailable
- **THEN** the app shows the vault as unlocked and confirms the saved credential worked

#### Scenario: Keyring-only cutover rehearsal fails
- **WHEN** the app cannot unlock with the keyring after restart
- **THEN** the app offers manual recovery and leaves retirement pending for the owner

### Requirement: Keep unlock material in the owner session

The app SHALL confine unlock credentials to the owner-side setup, keyring, and vault backend. Agent runtime permissions SHALL exclude direct access to the owner's vault files, keyring session, broker memory, and desktop controls. Passwords SHALL be absent from configuration, logs, command arguments, and exported results.

#### Scenario: Inspect a configured deployment from the agent runtime
- **WHEN** a process in the supported isolated agent runtime attempts to read the vault files, retrieve the OS keyring item, inspect the owner process, or use its desktop controls
- **THEN** the deployment denies those attempts

#### Scenario: Check local data for plaintext after setup
- **WHEN** setup, unlock, and error handling are exercised with a synthetic password
- **THEN** the password is absent from app-generated settings and logs, process arguments, and captured output
