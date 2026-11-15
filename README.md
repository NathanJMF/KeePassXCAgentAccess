# KeePassXC Agent Access

A Linux tray app for opening an existing KeePass vault from the owner's desktop. The app opens the database read-only. **Remember on this device** stores the master password in the owner's OS keyring for future unlocks.

## Run on Ubuntu GNOME

Use a Wayland session with the AppIndicator extension enabled. Install the desktop and vault dependencies from Ubuntu.

```sh
sudo apt install python3-gi python3-pykeepass gir1.2-gtk-3.0 \
  gir1.2-secret-1 gir1.2-ayatanaappindicator3-0.1 gnome-keyring
./run-tray
```

To add an application-menu entry, run `./install-launcher` from the owner-controlled checkout and open **KeePassXC Agent Access** in GNOME. Rerun the installer if the checkout moves.

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

Run the tray under the desktop owner's account and start the agent from the login environment of a separate, unprivileged OS account. Give that account access to its own workspace. Keep the vault, key file, and owner settings readable only by their owner, and keep the app's executable and source outside agent-writable directories. Give the agent its own session environment and keep the owner's session bus, Wayland socket, and process memory inaccessible to that account.

## Enable agent access

Provision a directory for the socket that the owner controls and the agent can traverse. The agent must be able to write to the socket inode to connect. One Ubuntu setup uses a dedicated group shared by the owner and agent. Give the agent a new login session after changing its group membership.

```sh
# The owner and the dedicated agent account are members of vault-listing.
sudo install -d -o "$(id -un)" -g vault-listing -m 2750 /run/keepassxc-agent-access
export KEEPASSXC_AGENT_SOCKET=/run/keepassxc-agent-access/entries.sock
export KEEPASSXC_AGENT_UID="$(id -u agent-runner)"
./run-tray
```

The owner can also save the socket path and allowed account from **Access** in the app. The app-menu launcher loads those settings on startup. Under the owner's account, unlock the vault and select **Enable agent access**. The broker verifies the connecting OS UID. **Stop agent access**, vault lock, a vault configuration change, or exit revokes access. Agent access starts disabled on the next session.

Provide the agent an owner-controlled installation of the `keepassxc-agent` launcher and its adjacent `src/keepassxc_agent_access` package. Put the launcher on its PATH and supply the same socket path as `KEEPASSXC_AGENT_SOCKET` in its environment. Give the agent the [KeePass skill](skills/keepassxc-agent-access/SKILL.md) for usage.

```sh
keepassxc-agent entries list --json
```

Use **Access** to choose **Allow all**, **Review all**, or **Smart access**. Review all is the default. The **Require approval** setting for each entry applies in Smart access, with new entries requiring review. A standard Smart listing includes the entries available automatically. Add `--include-reviewed` to request the protected rows.

In **Actions**, bind a KeePass entry to a fixed, certificate-verified HTTPS Basic-auth GET endpoint. Give the agent the entry UUID and the action ID:

```sh
keepassxc-agent use --entry ENTRY_UUID --action ACTION_ID --json
```

Use **Approve once** or **Decline** when prompted. The CLI reports a structured outcome and, when received, the HTTP status. **Activity** shows time, model, chat, action, and outcome. A runner can supply `KEEPASSXC_AGENT_MODEL`, `KEEPASSXC_AGENT_CHAT`, and `KEEPASSXC_AGENT_CHAT_ID` as optional agent-reported labels.

For a fresh-agent check, first configure a disposable synthetic vault. Give the agent just the skill and ask it to list entry titles and groups. Observe one successful CLI invocation through the broker and compare the agent's report to the expected fixture held by the verifier. Stop listing afterward and check that the command fails without entry data.

## Test with synthetic data

Run from the project root after installing the dependencies above.

```sh
PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v
tests/run-linux-integration
TRAY_TEST_ISOLATION=1 tests/run-linux-integration
```

The integration runner starts a private GNOME Wayland compositor, D-Bus session, and disposable OS keyring. It creates a synthetic password-and-key-file database, rotates the password, and verifies tray unlock after restart with the legacy file removed. It also exercises manual recovery, **Forget saved password**, desktop lock, and the main-window fallback. The isolation option uses a Linux user namespace with subordinate UID and GID mappings and `setfacl` from the `acl` package. It checks broker listing and revocation from a different host identity while a synthetic vault is open.
