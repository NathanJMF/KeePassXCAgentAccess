# KeePassXC Agent Access

A Linux tray app for opening an existing KeePass vault from the owner's desktop. The app opens the database read-only. **Remember on this device** stores the master password in the owner's OS keyring for future unlocks.

## Run on Ubuntu GNOME

Use a Wayland session with the AppIndicator extension enabled. Install the desktop and vault dependencies from Ubuntu.

```sh
sudo apt install python3-gi python3-pykeepass gir1.2-gtk-3.0 \
  gir1.2-secret-1 gir1.2-ayatanaappindicator3-0.1 gnome-keyring
./run-tray
```

The tray icon opens setup, shows the lock state, and offers **Unlock**, **Lock now**, **Settings**, and **Quit** as appropriate. The main window provides the same vault controls if the desktop has no tray. Closing the window with the tray available leaves the app running. Locking the desktop ends any unlocked vault session.

1. Select **Setup** and choose an existing `.kdbx` file.
2. Enter the database password and choose the key file if the vault uses one.
3. Select **Remember on this device** to save the password in the system keyring, then select **Verify and save**.
4. Select **Unlock** from the tray. The status reads **Unlocked · OS keyring** when the app successfully used the saved password.

When saved unlock fails, use **Enter password…** for a one-time unlock or **Change vault or password** to verify and save a replacement. **Forget saved password** locks the vault and removes app-owned saved items. If the keyring cannot delete an item, **Retry keyring cleanup** stays available in Settings. Items pending deletion are disabled for unlock.

## Replace a plaintext unlock file

1. Confirm you have an owner-controlled recovery path, then rotate the master password in KeePassXC.
2. Use **Change vault or password** to verify and remember the new password.
3. Quit and restart the tray app. With the legacy file unavailable to the app, select **Unlock** and confirm **Unlocked · OS keyring**. If the check fails, use manual recovery and retry with the correct saved password.
4. Retire the old plaintext file after verification. Review any backups separately because older database copies can still use the previous password.

## Isolate the agent runtime

Run the tray under the desktop owner's account and start the agent from the login environment of a separate, unprivileged OS account. Give that account access to its own workspace. Keep the vault, key file, and owner settings readable only by their owner, and keep the app's executable and source outside agent-writable directories. Give the agent its own session environment and keep the owner's session bus, Wayland socket, and process memory inaccessible to that account. Agent access through a broker is a later milestone.

## Test with synthetic data

Run from the project root after installing the dependencies above.

```sh
PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v
tests/run-linux-integration
TRAY_TEST_ISOLATION=1 tests/run-linux-integration
```

The integration runner starts a private GNOME Wayland compositor, D-Bus session, and disposable OS keyring. It creates a synthetic password-and-key-file database, rotates the password, and verifies tray unlock after restart with the legacy file removed. It also exercises manual recovery, **Forget saved password**, desktop lock, and the main-window fallback. The isolation option uses a Linux user namespace with subordinate UID and GID mappings to exercise the boundary from a different host identity while the owner vault is open.
