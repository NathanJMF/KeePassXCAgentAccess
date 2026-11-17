# Keeper User Guide

[Back to Keeper](../README.md)

Keeper is a Linux tray app for browsing existing KeePass databases and granting agents access to specific entries and credential actions. The desktop can edit KDBX 4 vaults and independently remember each database password in the owner's OS keyring.

## Install on Ubuntu GNOME

From this checkout, run:

```sh
./install
```

Keeper installs the missing Ubuntu packages, adds **Keeper** to the application menu, and opens it. The bundled skill is installed at `Documents/Skills/Keeper/SKILL.md`, with an executable `keeper-agent` beside it. The helper points to the installed application, so agents do not need to locate the broker socket or token files. Customized helper files must be moved aside before setup replaces them. On upgrade, Keeper removes the old copy if it matches the bundled skill or the previous installation record. Keeper keeps locally edited copies. The installed app runs from a per-user copy, so you can move the checkout. To update, open **Keeper Settings → Updates**, select **Check for Updates**, then **Apply Update**. Keeper records the trusted checkout’s upstream URL and branch at install time. It checks and applies fast-forward updates in its private installation directory. An installation containing local source changes asks for a clean reinstall before updates. Agent updates include the agent dependency set. If package installation needs a terminal, run `./install --agent` from a trusted Keeper checkout. For a private upstream, use SSH authentication in your desktop account. You can also install manually from a trusted, up-to-date checkout.

Minimize the window to keep Keeper running in the tray. On Ubuntu GNOME with legacy tray icons enabled, left-click the tray icon to reopen Keeper. Right-click for **Open Keeper**. When only AppIndicator is available, select **Open Keeper** from its menu or middle-click the icon. **X** and **Ctrl+Q** both quit Keeper.

To set up the isolated agent runner and start Keeper’s broker at sign-in, run:

```sh
./install --agent
```

Run as your desktop user. Setup asks for sudo if it needs Ubuntu packages. Agent setup also needs a systemd user session and subordinate UID/GID mappings for your account. Give each agent the installed Keeper skill. It runs the adjacent `keeper-agent begin --identity "Readable Agent Role" --project "Task Project"` command, then uses the returned profile handle for discovery, registration and approved operations. Each task starts with a fresh profile; the broker binds its identity and project at enrollment and attributes protected operations to that grant. Detailed status reports the registered identity and currently approved scope separately from pending changes. If an identity is already in use, start a fresh profile with a different readable identity. No client restart or shared MCP connection is needed for this workflow. Agent access starts paused. If you already have a separately managed broker service, use `./install` and configure that service and its runner to start from your protected installation. For the default Ubuntu data location, use `~/.local/share/keeper/app/run-tray` for the service and `~/.local/share/keeper/app/keeper-run-agent` for the runner.

To remove the managed installation, use `./uninstall` or the uninstall command printed by setup. It removes the installed app, launcher and managed broker service, and any unmodified skill and companion helper installed by setup. It keeps your vaults, remembered credentials, settings, tokens, runner profiles, Activity and shared Ubuntu packages.

1. Select **Add Vault…** and choose an existing KeePass file. The picker opens the Keeper folder in your Documents directory when that folder exists. Enter its password and select its key file if required.
2. Select **Remember on This Device** to save the password in the system keyring, then select **Verify and Save**.
3. Select a vault in the sidebar to see all its entries and their folder paths. Expand it and select a folder to browse the entries directly inside. The entry table includes its Created and Modified dates. Double-click an entry for details and credential actions.
4. Use **Lock Vault** to close the selected vault independently. To check saved unlock, lock that vault and select **Unlock**.

Use **Unlock** to open a vault. Keeper tries the saved keyring password and prompts when it needs a password. **Forget Saved Password…** deletes the app's saved credential. **Relink Vault…** checks the last verified contents of a moved vault before retaining its local identity and token scopes. **Remove from Keeper…** removes the registration and its saved credential while keeping the database file.

Existing installations retain their registered vault, keyring reference, broker admission settings, and Activity. Unlock the migrated vault to see its existing action bindings in entry details. Startup pauses agent access, and agent use requires an approved token. If desktop lock monitoring is unavailable, Keeper keeps vaults locked and displays a status message until monitoring recovers. With **Vaults → Start Unlocked** on, Keeper unlocks vaults that have a working saved keyring password. The toolbar button locks every vault when one is open and offers to unlock them when they are all locked.

## Edit entries and groups

In an unlocked vault, **New** lists **Group** first and **Entry** second. New groups go at the vault root. New entries default to the selected vault and group. The Group dropdown follows the sidebar order and defaults to the first group when you open the form from a vault. The **Vault** dropdown includes locked vaults. Select one and click **Unlock Vault** to choose its group and save the entry. Double-click an entry to edit it or move it to another group. **Delete…** permanently deletes an entry or a group and its contents after confirmation. Right-click a vault, folder or entry for its actions. With the row selected, you can also press **Shift+F10**. Click a table heading to cycle through ascending, descending and default order. The arrow marks the active sort. An entry edit keeps its current password until you select **Replace Saved Password**. Use **Notes** in the entry form to save multiline notes in the encrypted KeePass entry.

Keeper checks for external changes before replacing the encrypted file. If Keeper detects an external save, unlock that vault again to load the latest version before editing. Older KDBX formats and files you cannot write remain available for browsing. Agent-requested recycling requires the vault's recycle bin to be enabled.

## Replace a plaintext unlock file

1. Confirm you have an owner-controlled recovery path, then rotate the master password in KeePassXC.
2. In the workspace, lock the vault and select **Unlock**. Enter the new password when prompted and select **Remember in the OS Keyring**.
3. Quit and restart the tray app. Select the vault, click **Unlock**, and check that its groups and entries appear. Keeper tries the saved keyring password first and prompts you if it needs a new one.
4. Retire the old plaintext file after verifying the keyring unlock. Review any backups separately because older database copies can still use the previous password.

## Isolate the agent runtime

Keep Keeper’s installation, update files, desktop and keyring sockets, startup configuration, and owner settings outside the agent’s writable or controllable environment. Expose only the scoped Keeper tools, or isolate every other agent capability using a separate unprivileged OS account or an independently enforced sandbox. This includes shell execution, filesystem access, desktop and accessibility automation, and any escalation path. An agent that can act as the desktop owner has authority over Keeper’s settings, approvals, and installed code. The runner isolates its own CLI or MCP subprocess. The installed task command pins its broker endpoint and task storage to the desktop account rather than accepting socket or profile-directory overrides from callers. Task handles separate registration and tokens; they do not isolate unrestricted processes sharing a host account. A custom MCP host must control its runner command, profile, and startup environment. Approve installs and software updates from a trusted owner session.

## Discover names before requesting access

After `begin`, agents use the installed helper as `keeper-agent --profile PROFILE --note "Find task resources" discover --json` to list all registered vaults, groups, and entry titles with their UUIDs. A dedicated MCP runtime can expose the equivalent `discover` tool. Discovery works before token registration and is logged in Activity. It requires the admitted broker account and resumed agent access. Auto Approve and individual token status govern protected operations; discovery exposes this same catalog to every admitted agent account, including a profile whose token has been disabled or removed.

Keeper stores a private names-only catalog at each successful unlock and edit. Locked vaults return that last-known structure with `cached: true`. A vault that has never been unlocked shows `available: false`. Cached names can be stale until the vault is unlocked again. Usernames, URLs, credentials and edits require scoped access. Discovery contains no notes or configured actions. Use discovered vault and entry IDs in access requests. For large catalogs, use `discover --summary --json` for vault names, then `discover --vault VAULT_UUID --json` for each vault’s structure. Existing `list_vaults` and `list_entries` retain their token-scoped behavior.

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

The runner creates a private profile in an existing parent directory and keeps the token inside it. A new profile reports `uninitialized` until an agent submits an access request. Use a separate profile for each token. Processes sharing an OS UID need a runtime boundary that prevents them from reading each other's profiles. The runner exposes only Keeper operations. This custom endpoint flow is separate from the installed helper's fixed desktop endpoint. Give the agent the [Keeper skill](../skills/keepassxc-agent-access/SKILL.md) and use its advanced stdio instructions with a host-assigned profile.

For direct CLI use under the isolated account, provide `KEEPASSXC_AGENT_SOCKET` and an absolute `KEEPASSXC_AGENT_TOKEN_FILE` inside a private directory owned by that account.

## Review token requests and activity

Incoming agent requests open a review dialog on its own, including while Keeper is in the tray. Use the mouse to approve or deny a request. Toggle **Request Pop-Ups** at the top of **Keeper Settings → Auto Approve**. You can also open **Access** and double-click a pending request to inspect the verified OS identity, reported agent and project labels, and every requested entry and operation. Resolve duplicate entry names before approving. Username and stored URL access require separate approval for each entry. Approved agents can request those fields with `entries list --field username --field url`. Expand an approved token row to see each approved entry on one line with its vault, group, and permissions. Double-click the token to open its details and management actions. Unlock a database to see its group and entry names. Use the token dialog or the right-click menu to disable, re-enable, or remove a token. Choose a distinct human-readable identity for each pending, active, or disabled token. Access shows the request’s reported model and chat. An active token can request a complete replacement scope using its existing profile.

Use **Resume Agent Access** in the Keeper window to let approved tokens run. The tray shows access status and opens Keeper. **Pause Agent Access** stops broker discovery and credential operations. Agents can still submit requests and Keeper can open their review windows. Use **Deny** to reject an access request or **Approve** to grant the requested scope. While paused, **Resume Access and Approve** grants that scope and resumes access globally for approved agents. Locking the desktop pauses agent access and closes all vault sessions.

The **Auto Approve: On / Off** button sits beside **Pause Agent Access**. Keeper remembers the setting across restarts. When on, enabled vault and entry listings, credential actions, and edits run within approved token permissions. When off, those actions need review. Under **Keeper Settings → Auto Approve**, turn an action’s switch off to always require a decision. HTTPS requests, local commands, networked commands, and browser sign-ins have separate switches. The legacy combined password-use setting carries over to each credential type. At the bottom of that page, turn on **I Understand** to reveal **Access Tokens - Create** and **Access Tokens - Update Permissions** under **Danger**. Both switches start off. The toolbar’s Auto Approve must be on for either switch to take effect. When it is off, new token requests and permission changes await your review. Turning the acknowledgement off disables both switches for future requests. To end an existing token’s access, disable or remove it in Access. Upgrades suspend previously enabled token switches until the owner acknowledges the warning and enables them again. An enabled token switch grants an ordinary metadata/edit request when Keeper resolves every requested resource to a single match. Token requests containing reusable credential permissions always await owner review, including permission replacements; these permissions explicitly approve the recipient destinations. After approval, each use follows the existing transport-specific Auto Approve settings. Keeper records the decision in Activity. Requests with unresolved or ambiguous targets still appear in Access. Automatic approval leaves the global pause in effect. An active token keeps its current permissions while a permission change awaits review. Requests outside an existing edit scope and changes that need an owner-entered password still use the edit review window.

Credential use requires an approved transport permission on the selected entry and an independently approved destination for network use. No saved action is required. Existing action-specific grants remain supported without gaining broader reusable permissions. **Activity** shows Time, Action, Identity, Vault, Group, Key, and Outcome for the latest 1,000 events. The broker rate-limits bursts of agent requests and records when it starts throttling. Filter by identity or resource, then double-click any row to see its details and audit note. Use the chevron to expand or collapse related actions. `KEEPASSXC_AGENT_MODEL`, `KEEPASSXC_AGENT_CHAT`, and `KEEPASSXC_AGENT_CHAT_ID` supply optional agent-reported attribution. Send a short audit reason as the tool’s `note` argument or set `KEEPASSXC_AGENT_NOTE` for a direct CLI call.

## Use approved credentials without preconfigured actions

For a task that needs returned inventory or other data, grant **Read Selected HTTPS Results** (`https_results`), plus `https_body` when a private password login is required, and use the protected workflow in the [Keeper skill](../skills/keepassxc-agent-access/SKILL.md). Keeper can log in using a form or JSON request, capture session tickets privately, make the declared resource request, and release only selected scalar fields. The agent receives usable JSON without handling passwords, cookies or tickets. Result-read permission covers GET, HEAD and OPTIONS; a resource write additionally needs the existing `https` permission on that same entry and origin. There is no service-specific handler or preconfigured action.

**Results - Read** starts with automatic approval off, including upgrades. The owner reviews the exact authentication endpoint, resource request, destination/certificate and fields released. Enabling that switch explicitly trusts approved endpoints and agent-selected result fields; recognized-credential filtering is defense in depth, not a guarantee against a malicious service. Arbitrary commands that receive a password still return a dispatch receipt. For data-dependent tasks, use the protected API workflow and process its returned noncredential JSON with normal agent tools.

Private certificates require an initial **Approve and Trust Certificate** decision. Keeper remembers the verified fingerprint only for that token, entry, credential revision and HTTPS destination. Later reads follow the Auto Approve switches, including after restarting Keeper. A changed certificate requires review and replaces the previous fingerprint; token permission changes reset certificate trust. Failed TLS connections, denied requests and expired requests cannot establish trust. Requests using ordinary system-trusted TLS continue to require CA and hostname verification. Each operation is still logged in Activity.

An agent with protected results access can request **Approve Write Once** for a specific HTTPS mutation. Keeper shows the destination, method, path, payload and result selection. Approval applies to that call even with Auto Approve enabled. It adds no ongoing write permission or certificate trust to the token. A write can return a named scalar result, such as a job ID the agent can use for a status read. Activity records the write and its decision without storing response values or private authentication data.

Reusable permissions are bound to the approved credential revision. Replacing an entry's username or password invalidates its credential-use permissions until fresh owner review. An external database rewrite invalidates reusable credential grants for that vault when it is reopened. Ordinary lock/unlock, noncredential edits and another entry's credential changes preserve the unaffected grant. Metadata permissions remain separate.

An agent requests an entry's `uses` capabilities and the exact network `origins` it needs. Keeper's Access popup shows both. Supported uses are `local_command`, `networked_command`, `https` and `browser`. A separate `https_body` permission, together with `https`, permits placing a credential in an API request body. That can store or publish the credential at the receiving service, and the permission is labeled accordingly. Metadata, username and stored URL permissions remain separate.

Network origins are normalized HTTPS authorities such as `https://service.example.test:443/`, with no path or query. They are pinned into the approved token; changing the entry's stored URL cannot redirect its permission. A different recipient requires an owner-reviewed permission change. Requests containing reusable use permissions always await owner review, including replacements that retain those permissions. Once approved, individual uses follow **Auto Approve** and the corresponding HTTPS, local-command, networked-command or browser switch.

The installed [Keeper skill](../skills/keepassxc-agent-access/SKILL.md) contains the complete agent workflow and usage descriptors. Start a task with the companion `keeper-agent begin`, retain its profile handle, and request narrowly scoped access. Agents supply a command, API request or form descriptor on each use rather than asking the owner for an action ID.

## Use a credential with an HTTPS API

An agent calls the installed helper's `use --vault VAULT_UUID --entry ENTRY_UUID --json` with a descriptor on stdin, for example:

```json
{"type":"https","url":"https://service.example.test/status","auth":"bearer"}
```

Use `basic` for the stored username/password or `bearer` for a bearer token. The agent chooses GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS with `method`, and can supply `json` as an object or JSON string for a write. Nonsecret query parameters go in a `query` string map. For other authentication headers, `auth: "template"` accepts `headers` such as `{"X-API-Key":"{{password}}"}`. Only `{{password}}` and `{{username}}` are substituted in the trusted worker. Credential placeholders are forbidden in URLs and query parameters. A JSON body containing either placeholder also requires `https_body`; fixed nonsecret JSON does not.

Keeper checks the approved origin, uses verified TLS, and does not follow API redirects. It returns only the outcome and HTTP status when available, never the response body or credential. Activity records the destination, method and a digest for the request. Inspect the destination before retrying a write reported as `uncertain`.

## Use a credential with a browser form

The agent supplies a `browser` descriptor with the login `url`, exact `submit_url`, `form_id`, HTML input names `username_field` and `password_field`, and `success_id`. For a post-login redirect, include the exact `success_url`. Every URL must share the approved HTTPS origin.

Keeper's offline browser validates a single-step URL-encoded HTML form with scripts disabled, supplies the stored username and password privately, and submits through verified TLS. It checks the success element and discards the temporary session and cookies. This is brokered form submission; it does not expose an ongoing authenticated browser session. JavaScript-only sign-ins, MFA and multi-site sign-ins need another flow.

The browser worker requires Bubblewrap, the systemd user manager, WebKitGTK 4.1 and Xvfb. `./install --agent` installs these dependencies on Ubuntu.

For an interactive VM installer, **Review Guest Console** can authorize a session to an exact RFB console over a TLS WebSocket. Keeper performs login and ticket exchange in the vault worker. The agent can request a PNG and send keyboard or mouse input through `keeper-agent console`. The session is bound to the token that opened it and lasts up to 15 minutes. Pausing access, locking the vault or changing the token closes that session. Console pixels and keystrokes stay out of Activity. The installed skill includes a Proxmox QEMU descriptor. RFB console delivery does not create a general signed-in browser session.

## Use a credential with a local command

The agent calls `keeper-agent --profile PROFILE run --vault VAULT_UUID --entry ENTRY_UUID --json -- /usr/bin/example --read-stdin`. No saved command or action ID is needed. Keeper checks the installed system executable and pins its digest for that use, creates a disposable sandbox, and delivers the password as UTF-8 bytes on private stdin followed by EOF. Local jobs have no network or writable host files; `/usr` is mounted read-only.

Dynamic commands return `{"outcome":"dispatched"}` after authorized handoff. This confirms dispatch, not command success. Subprocess output and exit status remain private so agent-supplied programs cannot return the credential through those channels. The owner's Activity records execution separately. Verify external effects independently before retrying a mutation. An arbitrary program receiving a credential can disclose it to an approved recipient; this is why the owner approves capabilities and destinations explicitly.

## Use a credential with a networked command

The same `run` command accepts `--origin https://service.example.test/ --prompt-variable GIT_ASKPASS` before `--` and the executable/arguments. The prompt variable must end in `_ASKPASS`. Keeper answers the first prompt privately, regardless of its wording. Set any nonsecret username and other answers beforehand so that this first prompt expects the selected secret. Keeper does not embed the credential in the host command or agent-visible environment.

The sandbox provides a SOCKS5 Unix-socket relay restricted to the approved TCP peer and port. The command controls its protocol, TLS validation, and paths or repositories; a shared address can host multiple services or tenants. This is a TCP recipient restriction, not an HTTPS-aware command firewall. Use a program supporting the supplied proxy and credential prompt. The system CA bundle is mounted at `/keeper/trust.pem`. Use Keeper's direct HTTPS or browser transport for broker-verified TLS.

A networked command can receive one nonsecret artifact with `--input < artifact`, mounted read-only at `/input`, up to 8 MiB. Keeper checks its size and digest. MCP callers provide the same command descriptor under `usage` and the artifact under `input_base64`. No command output or authenticated session returns to the agent. Existing preconfigured actions and their exact-command grants remain available for compatibility, but reusable delivery does not require creating them.

## Review agent edit requests

An active runner token can submit one edit request with a new UUID and exact vault, entry or group references. In **Access**, open the pending edit to see its target, destination, and changed fields. Choose **Approve and Apply** or **Deny**. If agent access is paused, you can explicitly resume it from the review first. Keeper requires a fresh request if the reviewed vault state changes.

Agent-created entries must go in a named group. Agents can request a top-level group and can move an existing root entry into a group. To save a login in one review, include the password source in the create-entry request. With the owner source, enter the account's current password directly in Keeper and save it with the rest of the entry. **Save Password in Keeper** updates a vault entry for an existing login. The service's password remains the same.

Right-click a folder and choose **Copy Group Reference**, or right-click an entry and choose **Copy Entry Reference**, to give the agent the exact target.

The CLI submits proposals with `keepassxc-agent edits request --json` and checks their status with `keepassxc-agent edits status --request REQUEST_UUID --json`. The stdio runner offers `request_edit` and `edit_status`. See the KeePass skill for the request format. Reuse the same UUID for transport retries. Each approval applies to a single change. Completed edit records lose identity and project details after the Activity retention period. Keeper keeps request IDs, digests, and outcomes to prevent replay and return consistent results for retries.

Supported requests create entries or groups, edit entry metadata or rename groups, move or recycle an item within its vault, and replace an entry password. A password request selects **Keeper-generated** or **owner-entered** in the request. Keeper handles the actual password inside the owner account. Changes through Keeper to an entry's username or password invalidate its credential action approvals. Reopening a vault saved by another KeePass client invalidates all credential action approvals for that vault. Keeper refuses vaults with duplicate entry or group IDs. Edit outcomes and changed field names are recorded in **Activity**. The Vault, Group, and Key columns identify the affected resource. Related events show their latest outcome in a summary row. Expand it to see the full history, and double-click an event for details.

## Test with synthetic data

```sh
PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v
tests/run-linux-integration
TRAY_TEST_ISOLATION=1 tests/run-linux-integration
```

The integration runner uses a private GNOME Wayland compositor, D-Bus session, and disposable OS keyring. The isolation option requires Linux subordinate UID/GID mappings and `setfacl` from the `acl` package. It verifies legacy setup and recovery, the GNOME launcher, and the scoped workspace with two disposable vaults that share KeePass IDs. The workspace scenario checks CLI enrollment, metadata-only and use-only grants, destination binding, per-token revocation, desktop lock, and Activity without using personal vaults. The runner scenario exercises all eight stdio tools with a disposable vault and local HTTPS service. From the desktop session, run `PYTHONPATH=src /usr/bin/python3 tests/browser_scenarios.py` to check a synthetic sign-in, exact form and redirect scope, credential and cookie privacy, and Activity.
