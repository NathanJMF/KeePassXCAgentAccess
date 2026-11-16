# Keeper User Guide

[Back to Keeper](../README.md)

Keeper is a Linux tray app for browsing existing KeePass databases and granting agents access to specific entries and credential actions. The desktop can edit KDBX 4 vaults and independently remember each database password in the owner's OS keyring.

## Install on Ubuntu GNOME

From this checkout, run:

```sh
./install
```

Keeper installs the missing Ubuntu packages, adds **Keeper** to the application menu, and opens it. The bundled skill is installed at `Documents/Skills/Keeper/SKILL.md`. On upgrade, Keeper removes the old copy if it matches the bundled skill or the previous installation record. Keeper keeps locally edited copies. The installed app runs from a per-user copy, so you can move the checkout. To update, open **Keeper Settings → Updates**, select **Check for Updates**, then **Apply Update**. Keeper records the trusted checkout’s upstream URL and branch at install time. It checks and applies fast-forward updates in its private installation directory. For a private upstream, use SSH authentication in your desktop account. You can also install manually from a trusted, up-to-date checkout. Close the window to keep Keeper running in the tray when GNOME has an AppIndicator host.

To set up the isolated agent runner and start Keeper’s broker at sign-in, run:

```sh
./install --agent
```

Run as your desktop user. Setup asks for sudo if it needs Ubuntu packages. Agent setup also needs a systemd user session and subordinate UID/GID mappings for your account. Use the command printed by the installer for your agent client’s stdio server. Choose a separate `--profile` name for each independent agent. Agent access starts paused. If you already have a separately managed broker service, use `./install` and configure that service and its runner to start from your protected installation. For the default Ubuntu data location, use `~/.local/share/keeper/app/run-tray` for the service and `~/.local/share/keeper/app/keeper-run-agent` for the runner.

To remove the managed installation, use `./uninstall` or the uninstall command printed by setup. It removes the installed app, launcher and managed broker service, and any unmodified skill installed by setup. It keeps your vaults, remembered credentials, settings, tokens, runner profiles, Activity and shared Ubuntu packages.

1. Select **Add Vault…** and choose an existing KeePass file. The picker opens the Keeper folder in your Documents directory when that folder exists. Enter its password and select its key file if required.
2. Select **Remember on This Device** to save the password in the system keyring, then select **Verify and Save**.
3. Select a vault in the sidebar to see all its entries and their folder paths. Expand it and select a folder to browse the entries directly inside. The entry table includes its Created and Modified dates. Double-click an entry for details and credential actions.
4. Use **Lock Vault** to close the selected vault independently. To check saved unlock, lock that vault and select **Unlock**.

Use **Unlock** to open a vault. Keeper tries the saved keyring password and prompts when it needs a password. **Forget Saved Password…** deletes the app's saved credential. **Relink Vault…** checks the last verified contents of a moved vault before retaining its local identity and token scopes. **Remove from Keeper…** removes the registration and its saved credential while keeping the database file.

Existing installations retain their registered vault, keyring reference, broker admission settings, and Activity. Unlock the migrated vault to see its existing action bindings in entry details. Startup pauses agent access, and agent use requires an approved token. With **Vaults → Start Unlocked** on, Keeper unlocks vaults that have a working saved keyring password. The toolbar button locks every vault when one is open and offers to unlock them when they are all locked.

## Edit entries and groups

In an unlocked vault, **New** lists **Group** first and **Entry** second. New groups go at the vault root. New entries default to the selected vault and group. The Group dropdown follows the sidebar order and defaults to the first group when you open the form from a vault. The **Vault** dropdown includes locked vaults. Select one and click **Unlock Vault** to choose its group and save the entry. Double-click an entry to edit it or move it to another group. **Delete…** permanently deletes an entry or a group and its contents after confirmation. Right-click a vault, folder or entry for its actions. With the row selected, you can also press **Shift+F10**. Click a table heading to cycle through ascending, descending and default order. The arrow marks the active sort. An entry edit keeps its current password until you select **Replace Saved Password**. Use **Notes** in the entry form to save multiline notes in the encrypted KeePass entry.

Keeper checks for external changes before replacing the encrypted file. If Keeper detects an external save, unlock that vault again to load the latest version before editing. Older KDBX formats and files you cannot write remain available for browsing. Agent-requested recycling requires the vault's recycle bin to be enabled.

## Replace a plaintext unlock file

1. Confirm you have an owner-controlled recovery path, then rotate the master password in KeePassXC.
2. In the workspace, lock the vault and select **Unlock**. Enter the new password when prompted and select **Remember in the OS Keyring**.
3. Quit and restart the tray app. Select the vault, click **Unlock**, and check that its groups and entries appear. Keeper tries the saved keyring password first and prompts you if it needs a new one.
4. Retire the old plaintext file after verifying the keyring unlock. Review any backups separately because older database copies can still use the previous password.

## Isolate the agent runtime

Keep Keeper’s installation, update files, desktop and keyring sockets, startup configuration, and owner settings outside the agent’s writable or controllable environment. The bundled runner changes the OS identity of the Keeper MCP subprocess. Keep agents tools-only, or isolate their shell, filesystem, and desktop tools separately from the desktop owner, using a separate unprivileged OS account or an independently enforced sandbox. The MCP host must control the runner command, profile, and startup environment. Approve installs and software updates from a trusted owner session.

## Configure a custom agent runtime

For a separately managed runner, run the tray under the desktop owner's account and start the agent in a separate, unprivileged OS account. Keep the vault, key file, settings, keyring, desktop session, and process memory inaccessible to the runner. Install the CLI and source in a location the runner can read but cannot change.

Provision a socket directory that the owner controls and the agent can traverse. The agent must be able to write to the socket inode to connect. This example assumes that the owner and dedicated agent account are members of a group called `vault-listing`.

```sh
sudo install -d -o "$(id -un)" -g vault-listing -m 2750 /run/keepassxc-agent-access
export KEEPASSXC_AGENT_SOCKET=/run/keepassxc-agent-access/entries.sock
export KEEPASSXC_AGENT_UID="$(id -u agent-runner)"
./run-tray
```

Save the socket path and runner account in **Broker Settings** for app-menu launches. The broker checks the connecting OS UID before accepting token requests.

Use the installed `keeper-agent-runner` and `keepassxc-agent` from an owner-controlled directory. For a manual deployment, keep both executables beside the full `src` directory, including the startup bootstrap. Configure your agent's stdio MCP client to launch the runner under the admitted OS account.

```sh
keeper-agent-runner --socket /run/keepassxc-agent-access/entries.sock \
  --profile-dir /absolute/path/to/private/profile
```

The runner creates a private profile in an existing parent directory and keeps the token inside it. A new profile reports `uninitialized` until an agent submits an access request. Use a separate profile for each token. Processes sharing an OS UID need a runtime boundary that prevents them from reading each other's profiles. The runner exposes only Keeper operations. Give the agent the [KeePass skill](../skills/keepassxc-agent-access/SKILL.md).

For direct CLI use under the isolated account, provide `KEEPASSXC_AGENT_SOCKET` and an absolute `KEEPASSXC_AGENT_TOKEN_FILE` inside a private directory owned by that account.

## Review token requests and activity

Keeper opens its own review window for incoming access and edit requests. Use the mouse to approve or deny a request. Toggle **Request Pop-Ups** under **Keeper Settings → Notifications**. You can also open **Access** and double-click a pending request to inspect the verified OS identity, reported agent and project labels, and every requested entry and operation. Resolve duplicate entry names before approving. Username and stored URL access require separate approval for each entry. Approved agents can request those fields with `entries list --field username --field url`. Expand an approved token row to see each approved entry on one line with its vault, group, and permissions. Double-click the token to open its details and management actions. Unlock a database to see its group and entry names. Use the token dialog or the right-click menu to disable, re-enable, or remove a token. Choose a distinct human-readable identity for each pending, active, or disabled token. Access shows the request’s reported model and chat. An active token can request a complete replacement scope using its existing profile.

Use **Resume Agent Access** in the tray or main window to let approved tokens run. **Pause Agent Access** stops broker discovery and credential operations. Agents can still submit requests and Keeper can open their review windows. Use **Deny** to reject an access request or **Approve** to grant the requested scope. While paused, **Resume Access and Approve** grants that scope and resumes access globally for approved agents. Locking the desktop pauses agent access and closes all vault sessions.

The **Auto Approve: On / Off** button sits beside **Pause Agent Access**. Keeper remembers the setting across restarts. When on, enabled vault and entry listings, credential actions, and edits run within approved token permissions. When off, those actions need review. Under **Keeper Settings → Auto Approve**, turn an action’s switch off to always require a decision. **Access Tokens - Create** and **Access Tokens - Update Permissions** are at the bottom of the same list. Their switches apply independently of the toolbar button and both start off. An enabled token switch grants a request when Keeper resolves every requested resource to a single match. Keeper records the decision in Activity. Requests with unresolved or ambiguous targets still appear in Access. Automatic approval leaves the global pause in effect. An active token keeps its current permissions while a permission change awaits review. Requests outside an existing edit scope and changes that need an owner-entered password still use the edit review window.

Credential use requires an enabled action on the selected entry. **HTTPS Basic-auth GET** uses the entry's username and password. **HTTPS Bearer token GET** uses the password field as the bearer token. Both use fixed HTTPS destinations. Changing the type or destination requires fresh approval. **Activity** shows Time, Action, Identity, Vault, Group, Key, and Outcome for the latest 1,000 events. The broker rate-limits bursts of agent requests and records when it starts throttling. Filter by identity or resource, then double-click any row to see its details and audit note. Use the chevron to expand or collapse related actions. `KEEPASSXC_AGENT_MODEL`, `KEEPASSXC_AGENT_CHAT`, and `KEEPASSXC_AGENT_CHAT_ID` supply optional agent-reported attribution. Send a short audit reason as the tool’s `note` argument or set `KEEPASSXC_AGENT_NOTE` for a direct CLI call.

## Use a credential with a local command

Open the entry and add an **Isolated command stdin** action. Enter the executable in `/usr/bin` and its literal arguments. Shell quoting groups arguments in the editor. Keeper pins the executable's digest and shows the exact invocation when you review access. Approve the agent's grant for that action. Saving a changed command or executable digest requires a fresh grant.

The CLI uses the same vault, entry and action references as HTTPS actions. Use `keepassxc-agent run --vault VAULT_UUID --entry ENTRY_UUID --action ACTION_ID --json -- /usr/bin/example --read-stdin`. The MCP client can pass the arguments as a `command` array on `use_password`. Keeper writes the entry's password to stdin as UTF-8 bytes and closes the pipe. Activity records the command binding and outcome. Keep private values out of the configured argument list.

This profile requires Bubblewrap, libseccomp, and the systemd user manager. Keeper gives the command a private filesystem and process environment with networking disabled and returns success or failure. Use a trusted system executable that accepts stdin. Use the networked command profile for tools that need an approved HTTPS origin.

## Use a credential with a networked command

Add a **Networked command prompt** action on the credential entry. Set the exact trusted executable and arguments, the approved HTTPS origin, and the program's password prompt variable. The variable must end in `_ASKPASS`. Configure any username in the command. Keeper answers one password prompt per run and keeps the answer inside that job. Keep credentials out of the arguments and input file.

The sandbox supplies an origin-bound SOCKS5 Unix-socket proxy to programs that support it. It verifies the requested host and port. The approved command is responsible for TLS verification and for restricting HTTPS paths, repositories, and branches. Use the system trust bundle or a CA file selected through the trusted desktop startup environment. The command can use the mounted bundle at `/keeper/trust.pem`. Keeper discards subprocess output. Once a command receives the credential, work already dispatched to the remote can complete. Activity reports an uncertain result if Keeper cannot confirm it. Check the remote before retrying an uncertain mutation.

For a Git action, an owner can approve a command like the following. Replace the repository and username once before granting access, and enable the input file option.

```sh
/usr/bin/sh -c '/usr/bin/git clone --bare /input /tmp/repository && /usr/bin/git -C /tmp/repository -c credential.helper= -c credential.username=YOUR_USERNAME -c core.hooksPath=/dev/null -c http.sslCAInfo=/keeper/trust.pem -c http.followRedirects=false -c push.recurseSubmodules=no push "$1" refs/heads/main:refs/heads/main' keeper https://github.com/OWNER/REPOSITORY.git
```

Enter the command on one line in the editor. Set the origin to `https://github.com` and the prompt variable to `GIT_ASKPASS`. The agent supplies a Git bundle of the branch it needs to push using `keepassxc-agent run --input ... < bundle`. With stdio, the agent sends the artifact as `input_base64` on `use_password`. Keeper checks the file size and digest before delivery and mounts only that file as read-only at `/input`. The limit is 8 MiB. The fixture uses a fresh bare repo and a fixed non-force refspec.

## Review agent edit requests

An active runner token can submit one edit request with a new UUID and exact vault, entry or group references. In **Access**, open the pending edit to see its target, destination, and changed fields. Choose **Approve and Apply** or **Deny**. If agent access is paused, you can explicitly resume it from the review first. Keeper requires a fresh request if the reviewed vault state changes.

Right-click a folder and choose **Copy Group Reference**, or right-click an entry and choose **Copy Entry Reference**, to give the agent the exact target.

The CLI submits proposals with `keepassxc-agent edits request --json` and checks their status with `keepassxc-agent edits status --request REQUEST_UUID --json`. The stdio runner offers `request_edit` and `edit_status`. See the KeePass skill for the request format. Reuse the same UUID for transport retries. Each approval applies to a single change.

Supported requests create entries or groups, edit entry metadata or rename groups, move or recycle an item within its vault, and replace an entry password. A password request selects **Keeper-generated** or **owner-entered** in the request. Keeper handles the actual password inside the owner account. Changes through Keeper to an entry's username or password invalidate its credential action approvals. Reopening a vault saved by another KeePass client invalidates all credential action approvals for that vault. Keeper refuses vaults with duplicate entry or group IDs. Edit outcomes and changed field names are recorded in **Activity**. The Vault, Group, and Key columns identify the affected resource. Related events show their latest outcome in a summary row. Expand it to see the full history, and double-click an event for details.

## Test with synthetic data

```sh
PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v
tests/run-linux-integration
TRAY_TEST_ISOLATION=1 tests/run-linux-integration
```

The integration runner uses a private GNOME Wayland compositor, D-Bus session, and disposable OS keyring. The isolation option requires Linux subordinate UID/GID mappings and `setfacl` from the `acl` package. It verifies legacy setup and recovery, the GNOME launcher, and the scoped workspace with two disposable vaults that share KeePass IDs. The workspace scenario checks CLI enrollment, metadata-only and use-only grants, destination binding, per-token revocation, desktop lock, and Activity without using personal vaults. The runner scenario exercises all seven stdio tools with a disposable vault and local HTTPS service.
