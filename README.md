# Keeper

Keeper is a Linux tray app for browsing existing KeePass databases and granting agents access to specific entries and credential actions. The desktop can edit KDBX 4 vaults and independently remember each database password in the owner's OS keyring.

## Run on Ubuntu GNOME

Use a Wayland session with the AppIndicator extension enabled. Install the desktop and vault dependencies from Ubuntu.

```sh
sudo apt install python3-gi python3-pykeepass gir1.2-gtk-3.0 \
  gir1.2-secret-1 gir1.2-ayatanaappindicator3-0.1 gnome-keyring
./run-tray
```

Run `./install-launcher` from the owner-controlled checkout to add **Keeper** to the GNOME application menu. Rerun the installer to refresh an existing launcher or if the checkout moves. Closing the window leaves the app running when the tray icon is available.

1. Select **Add vault…** and choose an existing KeePass file. Enter its password and select its key file if required.
2. Select **Remember on this device** to save the password in the system keyring, then select **Verify and save**.
3. Expand the vault in the sidebar and select a group to browse its direct entries. Double-click an entry for details and credential actions.
4. Use **Lock vault** to close the selected vault independently. To check saved unlock, lock that vault and select **Unlock**.

Use **Enter password…** to unlock manually or update a remembered password after rotating it in KeePassXC. **Forget password** deletes the app's saved credential. **Relink** checks the last verified contents of a moved vault before retaining its local identity and token scopes. **Remove…** removes the registration and its saved credential while keeping the database file.

Existing installations retain their registered vault, keyring reference, broker admission settings, and Activity. Unlock the migrated vault to see its existing action bindings in entry details. Startup pauses agent access, and agent use requires an approved token.

## Edit entries and groups

Open an unlocked vault and use **New** to create an entry or group. Double-click an entry to edit it, move it to another group, or send it to the recycle bin. The vault options menu provides the same controls for the selected group. An entry edit keeps its current password until you select **Replace saved password**.

Keeper checks for external changes before replacing the encrypted file. If Keeper detects an external save, unlock that vault again to load the latest version before editing. Older KDBX formats and files you cannot write remain available for browsing. Recycling requires the vault's recycle bin to be enabled.

## Replace a plaintext unlock file

1. Confirm you have an owner-controlled recovery path, then rotate the master password in KeePassXC.
2. In the workspace, lock the vault, select **Enter password…**, and remember the new password.
3. Quit and restart the tray app. Select the vault, click **Unlock**, and check that its groups and entries appear.
4. Retire the old plaintext file after verifying the keyring unlock. Review any backups separately because older database copies can still use the previous password.

## Isolate the agent runtime

Run the tray under the desktop owner's account and start the agent in a separate, unprivileged OS account. Keep the vault, key file, settings, keyring, desktop session, and process memory inaccessible to the runner. Install the CLI and source in a location the runner can read but cannot change.

Provision a socket directory that the owner controls and the agent can traverse. The agent must be able to write to the socket inode to connect. This example assumes that the owner and dedicated agent account are members of a group called `vault-listing`.

```sh
sudo install -d -o "$(id -un)" -g vault-listing -m 2750 /run/keepassxc-agent-access
export KEEPASSXC_AGENT_SOCKET=/run/keepassxc-agent-access/entries.sock
export KEEPASSXC_AGENT_UID="$(id -u agent-runner)"
./run-tray
```

Save the socket path and runner account in **Broker settings…** for app-menu launches. The broker checks the connecting OS UID before accepting token requests.

Install `keeper-agent-runner`, `keepassxc-agent`, and their adjacent package in `src/keepassxc_agent_access` in an owner-controlled directory. Configure your agent's stdio MCP client to launch the runner under the admitted OS account.

```sh
keeper-agent-runner --socket /run/keepassxc-agent-access/entries.sock \
  --profile-dir /absolute/path/to/private/profile
```

The runner creates a private profile in an existing parent directory and keeps the token inside it. A new profile reports `uninitialized` until an agent submits an access request. Use a separate profile for each token. Processes sharing an OS UID need a runtime boundary that prevents them from reading each other's profiles. The runner exposes only Keeper operations. Give the agent the [KeePass skill](skills/keepassxc-agent-access/SKILL.md).

For direct CLI use under the isolated account, provide `KEEPASSXC_AGENT_SOCKET` and an absolute `KEEPASSXC_AGENT_TOKEN_FILE` inside a private directory owned by that account.

## Review token requests and activity

Open **Access** to review requests. Double-click a pending request to inspect the verified OS identity, reported agent and project labels, and every requested entry and operation. Resolve duplicate entry names before approving. Username and stored URL access require separate approval for each entry. Approved agents can request those fields with `entries list --field username --field url`. Double-click an approved token to disable, re-enable, or remove it. A larger scope requires a separate token request.

Use **Resume agent access** in the tray or main window to let approved tokens run. **Pause agent access** stops broker discovery and credential operations while the owner keeps browsing. Locking the desktop pauses agent access and closes all vault sessions.

Credential use requires an enabled action on the selected entry. **HTTPS Basic-auth GET** uses the entry's username and password. **HTTPS Bearer token GET** uses the password field as the bearer token. Both use fixed HTTPS destinations. Changing the type or destination requires fresh approval. **Activity** shows Time, Model, Chat, Action, and Outcome. Filter by vault, agent, or other columns, and double-click a row for more context. `KEEPASSXC_AGENT_MODEL`, `KEEPASSXC_AGENT_CHAT`, and `KEEPASSXC_AGENT_CHAT_ID` supply optional agent-reported attribution.

## Test with synthetic data

```sh
PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v
tests/run-linux-integration
TRAY_TEST_ISOLATION=1 tests/run-linux-integration
```

The integration runner uses a private GNOME Wayland compositor, D-Bus session, and disposable OS keyring. The isolation option requires Linux subordinate UID/GID mappings and `setfacl` from the `acl` package. It verifies legacy setup and recovery, the GNOME launcher, and the scoped workspace with two disposable vaults that share KeePass IDs. The workspace scenario checks CLI enrollment, metadata-only and use-only grants, destination binding, per-token revocation, desktop lock, and Activity without using personal vaults.
