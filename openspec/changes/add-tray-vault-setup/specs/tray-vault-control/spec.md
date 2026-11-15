# Tray Vault Control

## Purpose

Give the desktop owner a persistent place to see vault status and start or end an unlocked session.

## ADDED Requirements

### Requirement: Show vault status in the system tray

The Linux desktop app SHALL provide a system tray item on supported desktops. It SHALL indicate whether setup is required or the vault is locked or unlocked, and expose the actions appropriate to the current state.

#### Scenario: First launch
- **WHEN** the app starts without a saved vault configuration
- **THEN** the tray indicates that setup is required and offers to open setup

#### Scenario: Configured launch
- **WHEN** the app starts with a saved vault configuration
- **THEN** the tray shows the vault as locked and offers **Unlock**, **Settings**, and **Quit**

#### Scenario: Setup or settings window closes
- **WHEN** the owner closes the application window
- **THEN** the tray item remains available and can reopen the window

#### Scenario: Tray integration is unavailable
- **WHEN** the desktop cannot display the tray item
- **THEN** the app keeps setup and vault controls available through its main window

### Requirement: Unlock from the tray

The app SHALL begin unlocking only after an explicit desktop action. It SHALL publish the unlocked state only after the selected database has successfully opened.

#### Scenario: Successful unlock
- **WHEN** the owner selects **Unlock** and the configured unlock factors are accepted
- **THEN** the tray shows the vault as unlocked and offers **Lock now**

#### Scenario: Unlock is cancelled or fails
- **WHEN** unlock is cancelled or the vault cannot be opened
- **THEN** the tray remains locked and the app allows another attempt

### Requirement: End the unlocked session

The app SHALL release its active vault session and session-held unlock material on **Lock now**, desktop session lock, logout, or app exit. A new unlock action SHALL be required before reusing the vault.

#### Scenario: Owner locks the vault
- **WHEN** the owner selects **Lock now**
- **THEN** the app releases the session and the tray shows locked

#### Scenario: Desktop locks during an unlock attempt
- **WHEN** the desktop locks while an unlock is pending
- **THEN** the request cannot open the vault after the lock and the tray remains locked on return

#### Scenario: App starts after quit or logout
- **WHEN** the owner quits or ends the desktop session and later starts the app again
- **THEN** the vault is locked until the owner selects **Unlock**
