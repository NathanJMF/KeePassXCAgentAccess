# Desktop Launcher

## Purpose

Give the owner an application-menu entry for opening the tray app and its vault and access controls.

## ADDED Requirements

### Requirement: Install and open the app from the desktop menu

The project SHALL provide a per-user application launcher named **KeePassXC Agent Access** for the supported GNOME desktop. The launcher SHALL open the owner window without a terminal and reuse the existing tray process when one is running.

#### Scenario: Owner starts the app from GNOME
- **WHEN** the owner selects the installed launcher with the app stopped
- **THEN** the window opens in setup or locked state as appropriate and the tray item becomes available

#### Scenario: Owner opens the launcher again
- **WHEN** the owner selects the launcher while the tray app is running
- **THEN** the existing owner window opens and the app keeps its single active instance

### Requirement: Desktop launch uses saved broker settings

The owner app SHALL let the owner save a validated broker socket path and allowed agent account. A desktop launch SHALL load those settings alongside the existing vault configuration. Agent access SHALL start disabled until the owner enables it in an unlocked session.

#### Scenario: Start from the app menu with broker settings saved
- **WHEN** the owner launches the app from GNOME with a saved vault and broker configuration
- **THEN** they can unlock the vault and enable broker access from the desktop controls

#### Scenario: Broker configuration is invalid or unavailable
- **WHEN** the launcher opens with invalid broker settings
- **THEN** the app opens its owner controls and keeps broker access disabled until the owner corrects them
