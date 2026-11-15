# Keeper

Keeper is a Linux tray app for browsing existing KeePass databases and granting agents access to specific entries and credential actions. The desktop can edit KDBX 4 vaults and independently remember each database password in the owner's OS keyring.

## Run on Ubuntu GNOME

Use a Wayland session with the AppIndicator extension enabled. Install the desktop and vault dependencies from Ubuntu.

```sh
sudo apt install python3-gi python3-gi-cairo python3-pykeepass gir1.2-gtk-3.0 \
  gir1.2-secret-1 gir1.2-ayatanaappindicator3-0.1 gnome-keyring
./run-tray
```

Run `./install-launcher` from the owner-controlled checkout to add **Keeper** to the GNOME application menu and install its bundled skill at `Skills/keepassxc-agent-access/SKILL.md` under your Documents directory. Rerun the installer to refresh an existing launcher or if the checkout moves. Existing skill copies are preserved. Closing the window leaves the app running when the tray icon is available.

1. Select **Add vault…** and choose an existing KeePass file. The picker opens the Keeper folder in your Documents directory when that folder exists. Enter its password and select its key file if required.
2. Select **Remember on this device** to save the password in the system keyring, then select **Verify and save**.
3. Select a vault in the sidebar to see all its entries and their folder paths. Expand it and select a folder to browse the entries directly inside. The entry table includes its Created and Modified dates. Double-click an entry for details and credential actions.
4. Use **Lock vault** to close the selected vault independently. To check saved unlock, lock that vault and select **Unlock**.

Use **Enter password…** to unlock manually or update a remembered password after rotating it in KeePassXC. **Forget password** deletes the app's saved credential. **Relink** checks the last verified contents of a moved vault before retaining its local identity and token scopes. **Remove…** removes the registration and its saved credential while keeping the database file.

Existing installations retain their registered vault, keyring reference, broker admission settings, and Activity. Unlock the migrated vault to see its existing action bindings in entry details. Startup pauses agent access, and agent use requires an approved token. With **Vaults → Start unlocked** on, Keeper unlocks vaults that have a working saved keyring password. The toolbar button locks every vault when one is open and offers to unlock them when they are all locked.

## Edit entries and groups

In an unlocked vault, **New** lists **Group** first and **Entry** second. New groups go at the vault root. New entries default to the selected vault and group. The Group dropdown follows the sidebar order and defaults to the first group when you open the form from a vault. The **Vault** dropdown includes locked vaults. Select one and click **Unlock vault** to choose its group and save the entry. Double-click an entry to edit it or move it to another group. **Delete…** permanently deletes an entry or a group and its contents after confirmation. Right-click a vault, folder or entry for its actions. With the row selected, you can also press **Shift+F10**. Click a table heading to cycle through ascending, descending and default order. The arrow marks the active sort. An entry edit keeps its current password until you select **Replace saved password**. Use **Notes** in the entry form to save multiline notes in the encrypted KeePass entry.

Keeper checks for external changes before replacing the encrypted file. If Keeper detects an external save, unlock that vault again to load the latest version before editing. Older KDBX formats and files you cannot write remain available for browsing. Agent-requested recycling requires the vault's recycle bin to be enabled.

## Replace a plaintext unlock file

1. Confirm you have an owner-controlled recovery path, then rotate the master password in KeePassXC.
2. In the workspace, lock the vault, select **Enter password…**, and remember the new password.
3. Quit and restart the tray app. Select the vault, click **Unlock**, and check that its groups and entries appear. Keeper tries the saved keyring password first and prompts you if it needs a new one.
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

Keeper opens its own review window for incoming access and edit requests. Use the mouse to approve or deny a request. Toggle **Request pop-ups** under **Keeper settings → Notifications**. You can also open **Access** and double-click a pending request to inspect the verified OS identity, reported agent and project labels, and every requested entry and operation. Resolve duplicate entry names before approving. Username and stored URL access require separate approval for each entry. Approved agents can request those fields with `entries list --field username --field url`. Expand an approved token row to see each approved entry on one line with its vault, group, and permissions. Double-click the token to open its details and management actions. Unlock a database to see its group and entry names. Use the token dialog or the right-click menu to disable, re-enable, or remove a token. Choose a distinct human-readable identity for each pending, active, or disabled token. Access shows the request’s reported model and chat. An active token can request a complete replacement scope using its existing profile.

Use **Resume agent access** in the tray or main window to let approved tokens run. **Pause agent access** stops broker discovery and credential operations. Agents can still submit requests and Keeper can open their review windows. Use **Deny** to reject an access request or **Approve** to grant the requested scope. While paused, **Resume Access and Approve** grants that scope and resumes access globally for approved agents. Locking the desktop pauses agent access and closes all vault sessions.

The red **Allow usage** and green **Review usage** toggle sits beside **Pause agent access**. Keeper remembers the setting across restarts. Allow runs vault and entry listings, credential actions, and edits within approved token permissions. Review asks for a decision each time. Under **Keeper settings → Reviewals**, individual action switches always require review even in Allow mode. Under **Auto approve**, enable **New access tokens** or **Token permission changes** independently. Both start off. An enabled switch grants an incoming request when Keeper resolves every requested resource to a single match and keeps the decision in Activity. Requests with unresolved or ambiguous targets still appear in Access. Automatic approval leaves the global pause in effect. An active token keeps its current permissions while a permission change awaits review. Requests outside an existing edit scope and changes that need an owner-entered password still use the edit review window.

Credential use requires an enabled action on the selected entry. **HTTPS Basic-auth GET** uses the entry's username and password. **HTTPS Bearer token GET** uses the password field as the bearer token. Both use fixed HTTPS destinations. Changing the type or destination requires fresh approval. **Activity** shows Time, Action, Identity, Vault, Group, Key, and Outcome. Filter by identity or resource, then double-click any row to see its details and audit note. Use the chevron to expand or collapse related actions. `KEEPASSXC_AGENT_MODEL`, `KEEPASSXC_AGENT_CHAT`, and `KEEPASSXC_AGENT_CHAT_ID` supply optional agent-reported attribution. Send a short audit reason as the tool’s `note` argument or set `KEEPASSXC_AGENT_NOTE` for a direct CLI call.

## Review agent edit requests

An active runner token can submit one edit request with a new UUID and exact vault, entry or group references. In **Access**, open the pending edit to see its target, destination, and changed fields. Choose **Approve and apply** or **Deny**. If agent access is paused, you can explicitly resume it from the review first. Keeper requires a fresh request if the reviewed vault state changes.

Right-click a folder and choose **Copy group reference**, or right-click an entry and choose **Copy entry reference**, to give the agent the exact target.

The CLI submits proposals with `keepassxc-agent edits request --json` and checks their status with `keepassxc-agent edits status --request REQUEST_UUID --json`. The stdio runner offers `request_edit` and `edit_status`. See the KeePass skill for the request format. Reuse the same UUID for transport retries. Each approval applies to a single change.

Supported requests create entries or groups, edit entry metadata or rename groups, move or recycle an item within its vault, and replace an entry password. A password request selects **Keeper-generated** or **owner-entered** in the request. Keeper handles the actual password inside the owner account. Changes to an entry's username or password invalidate its existing credential action approvals. Edit outcomes and changed field names are recorded in **Activity**. The Vault, Group, and Key columns identify the affected resource. Related events show their latest outcome in a summary row. Expand it to see the full history, and double-click an event for details.

## Test with synthetic data

```sh
PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v
tests/run-linux-integration
TRAY_TEST_ISOLATION=1 tests/run-linux-integration
```

The integration runner uses a private GNOME Wayland compositor, D-Bus session, and disposable OS keyring. The isolation option requires Linux subordinate UID/GID mappings and `setfacl` from the `acl` package. It verifies legacy setup and recovery, the GNOME launcher, and the scoped workspace with two disposable vaults that share KeePass IDs. The workspace scenario checks CLI enrollment, metadata-only and use-only grants, destination binding, per-token revocation, desktop lock, and Activity without using personal vaults.
