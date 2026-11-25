# Keeper User Guide

[Back to Keeper](../README.md)

Keeper is a Linux tray app for browsing existing KeePass databases and granting agents access to specific entries and credential actions. The desktop can edit KDBX 4 vaults and independently remember each database password in the owner's OS keyring.

## Install on Ubuntu GNOME

From this checkout, run as your desktop user and approve the administrator prompt:

```sh
./install
```

By default, `./install` sets up Keeper together with the dedicated MCP runner (`--connect-agent` remains a compatible alias). Use `./install --app-only` for a desktop-only installation without an administrator prompt, or `./install --agent` to install the legacy runner. Keeper installs the missing Ubuntu packages, enables `keeper.service` autostart, adds **Keeper** to the application menu while preserving custom `.desktop` icons (such as theme overrides), and opens Keeper. The bundled skill is installed at `Documents/Skills/Keeper/SKILL.md`, with an executable `keeper-agent` beside it. The helper points to the installed application, so agents do not need to locate the broker socket or token files. Customized helper files must be moved aside before setup replaces them. On upgrade, Keeper removes the old copy if it matches the bundled skill or the previous installation record. Keeper keeps locally edited copies. The installed app runs from a per-user copy, so you can move the checkout. To update, open **Keeper Settings → Updates**, select **Check for Updates**, then **Apply Update**. Keeper records the trusted checkout’s upstream URL and branch at install time. It checks and applies fast-forward updates in its private installation directory. An installation containing local source changes asks for a clean reinstall before updates. Agent updates include the agent dependency set. If package installation needs a terminal, run `./install --agent` from a trusted Keeper checkout. For a private upstream, use SSH authentication in your desktop account. You can also install manually from a trusted, up-to-date checkout.

Minimize the window to keep Keeper running in the tray. On Ubuntu GNOME with legacy tray icons enabled, left-click the tray icon to reopen Keeper. Right-click for **Open Keeper**. When only AppIndicator is available, select **Open Keeper** from its menu or middle-click the icon. **X** and **Ctrl+Q** both quit Keeper.

Open **Settings → Connect an Agent** to inspect the skill and connection details. When Antigravity (`~/.gemini/config`) is present, setup automatically installs the skill at `~/.gemini/config/skills/keeper/SKILL.md` and registers `keeper` in `~/.gemini/config/mcp_config.json`. For other local (stdio) MCP clients, copy the MCP command or the **MCP Config JSON** snippet shown on that page and give your agent the skill shown there. Clients that send a thread ID get one profile per thread. Other clients get a profile for the lifetime of their connection, or one per `profile` argument supplied by the agent. To reuse a connection's grant without per-call `profile` arguments, add `--profile WORKSPACE_NAME` to the command in that client. Use a different profile name for each workspace. Resume Agent Access in Keeper when you're ready to accept requests.

The setup can reuse a saved broker endpoint with a Keeper-only, non-login runner account and a socket outside home directories. Use an agent client that isolates its shell and desktop tools from the owner account. The local MCP socket gives that client the Keeper tools, and the client needs its own boundary around other host capabilities. Existing `./install --agent` installations continue to use their legacy runner and the `keeper-agent` CLI. Uninstall the legacy app before switching to the dedicated connection. Changing the broker account requires new grants. When **Settings → Connect an Agent** reports a runner update, select **Settings → Connect an Agent → Update Local Runner…** (or run `./install` again from a trusted Keeper release).

To remove the managed installation completely, run `./uninstall` or the uninstall command printed by setup. It removes the installed app, desktop launcher, managed services and runner account/files, unmodified skills and Antigravity MCP registration, runtime/state directories, local Keeper settings and Activity, and Keeper's saved OS keyring entries, leaving your `.kdbx` vault files, key files, and shared Ubuntu packages untouched. Pass `./uninstall --keep-data` if you want to remove the app while keeping your settings, Activity, and remembered vault passwords for a future reinstall.

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

Keeper stores a private names-only catalog at each successful unlock and edit. Locked vaults return that last-known structure with `cached: true`. A vault that has never been unlocked shows `available: false`. Cached names can be stale until the vault is unlocked again. Usernames, URLs, notes, credentials and edits require scoped access. Discovery contains no notes or configured actions, though entry rows may expose nonsecret capability hints (`has_totp`, `custom_attribute_keys`, `attachments`) for TOTP, custom attributes, and SSH keys. Use discovered vault and entry IDs in access requests. For large catalogs, use `discover --summary --json` for vault names, then `discover --vault VAULT_UUID --json` for each vault’s structure, or filter with `discover --query TEXT --json` (`query` and `vault` in MCP `discover`). Existing `list_vaults` and `list_entries` retain their token-scoped behavior.

Agents can give up their own access to an individual entry with `keeper-agent --profile PROFILE access release --vault VAULT_UUID --entry ENTRY_UUID --json`, or with the runner's `release_entry` tool. An agent can decide when to release, and Keeper applies it immediately without a review prompt. A release is recorded in Activity, preserves the entry and other tokens, and cancels any pending permission change for the releasing token. The agent needs a fresh owner approval to regain the entry, even with token Auto Approve enabled. For incremental scope additions on an active token without dropping unchanged entries or invalidating `revocation_generation`-tracked permits (such as SSH reuse windows, workflows, and consoles), agents can submit `mode: "add"` (`--mode add`) with a `change_id`.

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

### Connect a single Codex project

The owner can expose Keeper MCP tools in one trusted Codex workspace through the project's local `.codex/config.toml`. Keep machine-specific connector settings out of version control. With a dedicated Linux account admitted in Keeper's Broker Settings, run the runner as that account from an administrator-controlled installation. Use a private, runner-owned state directory and the fixed owner-controlled broker socket.

```sh
keeper-agent-runner --socket /absolute/owner/broker.sock \
  --project-profiles /absolute/runner/project-profiles
```

For example, a systemd connection service can launch that command with socket input and output, protected home directories, and only Unix sockets. Bind the listening socket to the desktop owner with mode `0600`. Set a private state directory for the runner account. Point the Codex project at the local relay.

```toml
[mcp_servers.keeper_project]
command = "/usr/bin/socat"
args = ["STDIO", "UNIX-CONNECT:/run/keeper-project-example.sock"]
tool_timeout_sec = 100
```

The owner must trust the checkout in Codex before it loads project-local MCP settings. Trust is recorded for that checkout in the user's Codex configuration. Open a fresh chat in the trusted project and give the agent the installed Keeper skill. The connector uses the thread ID from MCP tool metadata to select the profile. Projects sharing the listening socket share its trust boundary. A client able to connect directly can claim another thread ID, so use this only for mutually trusted agents. Keeper continues to apply the token's resource scope and the owner's review settings. Keep the socket and service configuration outside agent-writable locations.

The runner creates a private profile in an existing parent directory and keeps the token inside it. A new profile reports `uninitialized` until an agent submits an access request. Use a separate profile for each token. Processes sharing an OS UID need a runtime boundary that prevents them from reading each other's profiles. The runner exposes only Keeper operations. This custom endpoint flow is separate from the installed helper's fixed desktop endpoint. Give the agent the [Keeper skill](../skills/keepassxc-agent-access/SKILL.md) and use its advanced stdio instructions with a host-assigned profile.

For direct CLI use under the isolated account, provide `KEEPASSXC_AGENT_SOCKET` and an absolute `KEEPASSXC_AGENT_TOKEN_FILE` inside a private directory owned by that account.

## Review token requests and activity

Incoming agent requests open a review dialog on its own, including while Keeper is in the tray. Use the mouse to approve or deny a request. Toggle **Request Pop-Ups** at the top of **Keeper Settings → Auto Approve**. You can also open **Access** and double-click a pending request to inspect the verified OS identity, reported agent and project labels, and every requested entry and operation. Resolve duplicate entry names before approving. Username, stored URL, and notes access require separate approval for each entry. Approved agents can request those fields with `entries list --field username --field url --field notes`. Expand an approved token row to see each approved entry on one line with its vault, group, and permissions. Double-click the token to open its details and management actions. Unlock a database to see its group and entry names. Use the token dialog or the right-click menu to disable, re-enable, or remove a token. Choose a distinct human-readable identity for each pending, active, or disabled token. Access shows the request’s reported model and chat. An active token can request a complete replacement scope (`mode: "replace"`) or an incremental addition (`mode: "add"`) using its existing profile.

Use **Resume Agent Access** in the Keeper window to let approved tokens run. The tray shows access status and opens Keeper. **Pause Agent Access** stops broker discovery and credential operations. Agents can still submit requests and Keeper can open their review windows. Use **Deny** to reject an access request or **Approve** to grant the requested scope. While paused, **Resume Access and Approve** grants that scope and resumes access globally for approved agents. Locking the desktop pauses agent access and closes all vault sessions.

The **Auto Approve: On / Off** button sits beside **Pause Agent Access**. Keeper remembers the setting across restarts. When on, enabled vault and entry listings, credential actions, and edits run within approved token permissions. When off, those actions need review. Under **Keeper Settings → Auto Approve**, turn an action’s switch off to always require a decision. HTTPS requests, local commands, networked commands, browser sign-ins, SSH commands (**Passwords - SSH Commands**), and SFTP transfers (**Passwords - SSH File Transfers**) have separate switches. The legacy combined password-use setting carries over to each credential type. At the bottom of that page, turn on **I Understand** to reveal **Access Tokens - Create**, **Access Tokens - Update Permissions**, and **Access Tokens - Extend Life Span** under **Danger**. Both creation/update switches and the extension switch start off. The toolbar’s Auto Approve must be on for any of them to take effect. When it is off, new token requests, permission changes, and life span extensions await your review. Turning the acknowledgement off disables those switches for future requests. To end an existing token’s access, disable or remove it in Access. Upgrades suspend previously enabled token switches until the owner acknowledges the warning and enables them again. An enabled token switch grants an ordinary metadata/edit request when Keeper resolves every requested resource to a single match. Token requests containing reusable credential permissions always await owner review, including permission replacements; these permissions explicitly approve the recipient destinations. After approval, each use follows the existing transport-specific Auto Approve settings. Keeper records the decision in Activity. Requests with unresolved or ambiguous targets still appear in Access. Automatic approval leaves the global pause in effect. An active token keeps its current permissions while a permission change or life span extension awaits review. Requests outside an existing edit scope and changes that need an owner-entered password still use the edit review window.

Every token has a finite life span (default **3 days**, configurable between 1 and 365 days). Keeper automatically expires tokens whose life span ends—clearing their live scope, removing them from the active Access list, and recording **Expire token** in Activity—and purges old historical terminal records (`expired`, `removed`, `denied`) after the Activity retention period. Active or disabled non-expired tokens can be extended directly from Access—resetting their expiry window from the approval timestamp without interrupting running workflows, consoles, or SSH reuse permits—and agents can request extensions with `access extend` (`extend_access` in MCP). When **Access Tokens - Extend Life Span** is enabled with Auto Approve, agent extension requests up to the configured default life span are granted automatically as a sliding window from the current time.

Credential use requires an approved transport permission on the selected entry and an independently approved destination for network use. No saved action is required. Existing action-specific grants remain supported without gaining broader reusable permissions. **Activity** shows Time, Action, Identity, Vault, Group, Key, and Outcome for the latest 1,000 events. The broker rate-limits bursts of agent requests and records when it starts throttling. Filter by identity or resource, then double-click any row to see its details and audit note. Use the chevron to expand or collapse related actions. `KEEPASSXC_AGENT_MODEL`, `KEEPASSXC_AGENT_CHAT`, and `KEEPASSXC_AGENT_CHAT_ID` supply optional agent-reported attribution. Send a short audit reason as the tool’s `note` argument or set `KEEPASSXC_AGENT_NOTE` for a direct CLI call.

## Use approved credentials without preconfigured actions

For a task that needs returned inventory or other data, grant **Read Selected HTTPS Results** (`https_results`), plus `https_body` when a private credential login is required, and use the protected workflow in the [Keeper skill](../skills/keepassxc-agent-access/SKILL.md). Keeper can log in using a form, JSON body, or headers (supporting `{{password}}`, `{{username}}`, `{{totp}}`, and `{{attr.<name>}}`), capture session tickets privately from JSON pointers, `header:<Name>`, or `cookie:<Name>`, decompress `gzip`/`deflate` responses up to 2 MiB (`204 No Content` returns `data: []`), and release only selected scalar fields (up to 32 dot-path columns, 512 rows, 64-item scalar arrays, 4096-character cell truncation, and up to 8 safe non-credential response headers). Errors return a sanitized, secret-scrubbed `error_detail`. The agent receives usable JSON without handling passwords, TOTP secrets, custom attributes, cookies or tickets. Result-read permission covers GET, HEAD and OPTIONS; a resource write additionally needs the existing `https` permission on that same entry and origin. There is no service-specific handler or preconfigured action.

**Results - Read** starts with automatic approval off, including upgrades. The owner reviews the exact authentication endpoint, resource request, destination/certificate and fields released. Enabling that switch explicitly trusts approved endpoints and agent-selected result fields; recognized-credential filtering is defense in depth, not a guarantee against a malicious service. Arbitrary commands that receive a password still return a dispatch receipt. For data-dependent tasks, use the protected API workflow and process its returned noncredential JSON with normal agent tools.

Private certificates require an initial **Approve and Trust Certificate** decision by default. **TLS Certificates - First Use** lets Keeper accept the first fingerprint after a verified connection within an approved grant. Keeper remembers the fingerprint only for that token, entry, credential revision and HTTPS destination. Later reads follow the Auto Approve switches, including after restarting Keeper. A changed certificate requires review unless **TLS Certificates - Accept Changed Fingerprint** is enabled. Token permission replacements reset certificate trust. Requests using ordinary system-trusted TLS continue to require CA and hostname verification. Keeper records each decision in Activity.

An agent with protected results access can request **Approve Write Once** for a specific HTTPS mutation. Keeper shows the destination, method, path, payload and result selection. Approval applies to that call. With **HTTPS - One-Time Writes** and standing HTTPS permission for that entry and origin, the flagged write can be auto approved. This changes neither the token scope nor its certificate trust. A write can return a named scalar result, such as a job ID the agent can use for a status read. Activity records the decision without storing response values or private authentication data.

**Use Approved Access** contains optional switches for first certificate trust, changed TLS fingerprints, SSH host keys (first use, changed keys, and reuse windows), one-time writes, workflows, new guest connections, and account provisioning. They start off and require Auto Approve and the corresponding transport switches. Workflows and new guest connections need standing HTTPS write permission and an already trusted pin. Guest operations also need their own guest switch enabled. Workflow-only enrollment still requires owner review.

The agent can pass `use --receipt UUID` to track a protected write and check it later with `results status --receipt UUID --json`. Keeper records the main write's dispatch and HTTP status, where available, and refuses duplicate submissions under the same ID and token. A 2xx response with unavailable output is shown as **Acknowledged · result unavailable**. Check remote state before retrying an acknowledged or uncertain write. A receipt survives restarts and holds progress and HTTP status only. Viewing it requires the original active grant and an unlocked vault. Each token can track up to 512 writes over its lifetime. Receipt IDs stay reserved for that token after the corresponding Activity rows age out.

**Review Workflow** covers up to eight known writes, guest commands, and console opens on one entry and pinned destination. The owner sees the shared sign-in and every operation in one review. Later steps can use a positive integer captured from an earlier approved response, with an explicit expected ID when known. The agent runs approved steps by name. Writes and commands have individual durable receipts, and Activity groups the actions under the workflow. A fresh agent can use **Register and Review Workflow** to have the owner approve the exact plan and a workflow-only token together. If agent access is paused, the owner can deny the request or explicitly resume access and approve it.

**Review Account Provisioning** lets the owner approve a single pinned API write that uses one scoped administrative entry and sends a second account entry’s password in named HTTPS body fields. Both entries must be in the same unlocked vault. The owner sees both entries and where the account data will go. The agent receives the projected result, or can check the receipt for historical status. The additional credential authorization expires with that operation. Releasing the account entry blocks later provisioning requests for that entry from the same token until the owner grants access again.

With **Accounts - Provision** enabled, Keeper can use the token’s standing HTTPS write and result permissions for the administrator and its credential body permission for the account entry. Both grants must cover the same destination and current credential revisions. The administrator’s certificate pin must already be trusted. The decision and write receipt remain in Activity.

Reusable permissions are bound to the approved credential revision. Replacing an entry's username or password invalidates its credential-use permissions until fresh owner review. An external database rewrite invalidates reusable credential grants for that vault when it is reopened. Ordinary lock/unlock, noncredential edits and another entry's credential changes preserve the unaffected grant. Metadata permissions remain separate.

An agent requests an entry's `uses` capabilities and the exact network `origins` it needs. Keeper's Access popup shows both. Supported uses are `local_command`, `networked_command`, `https`, `https_results`, `browser`, `ssh_exec`, `ssh_sftp`, and `ssh_sudo`. A separate `https_body` permission, together with `https` or `https_results`, permits placing a credential in an API request body. That can store or publish the credential at the receiving service, and the permission is labeled accordingly. Metadata, username, stored URL, and notes permissions remain separate.

Network origins are normalized `https://` authorities (such as `https://service.example.test:443/`), `tcp://host:port` endpoints for `networked_command`, or `ssh://host:port` endpoints for brokered SSH/SFTP, with no path or query. They are pinned into the approved token; changing the entry's stored URL cannot redirect its permission. A different recipient requires an owner-reviewed permission change. Requests containing reusable use permissions always await owner review, including replacements that retain those permissions. Once approved, individual uses follow **Auto Approve** and the corresponding transport switch.

The installed [Keeper skill](../skills/keepassxc-agent-access/SKILL.md) contains the complete agent workflow and usage descriptors. Start a task with the companion `keeper-agent begin`, retain its profile handle, and request narrowly scoped access. Agents supply a command, API request, SSH operation, or form descriptor on each use rather than asking the owner for an action ID.

## Use a credential with an HTTPS API

An agent calls the installed helper's `use --vault VAULT_UUID --entry ENTRY_UUID --json` with a descriptor on stdin, for example:

```json
{"type":"https","url":"https://service.example.test/status","auth":"bearer"}
```

Use `basic` for the stored username/password or `bearer` for a bearer token. The agent chooses GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS with `method`, and can supply `json` as an object or JSON string (up to 64 KiB) for a write. Nonsecret query parameters go in a `query` string map. Optional `certificate_sha256` pins a private-CA or self-signed server certificate on plain `https` requests as well. For other authentication headers, `auth: "template"` accepts `headers` such as `{"X-API-Key":"{{attr.api_key}}","X-OTP":"{{totp}}"}`. Supported placeholders are `{{password}}`, `{{username}}`, `{{totp}}`, and `{{attr.<name>}}` (substituted inside the trusted worker and scrubbed from diagnostics). Credential placeholders are forbidden in URLs, query parameters, and JSON object keys. A JSON body containing a credential placeholder also requires `https_body`; fixed nonsecret JSON does not.

Keeper checks the approved origin, uses verified TLS, and does not follow API redirects. It returns only the outcome and HTTP status when available (plus a sanitized, secret-scrubbed `error_detail` on failures), never the response body or credential. Activity records the destination, method and a digest for the request. Inspect the destination before retrying a write reported as `uncertain`.

## Use a credential with a browser form

The agent supplies a `browser` descriptor with the login `url`, exact `submit_url`, `form_id`, HTML input names `username_field` and `password_field`, and `success_id`. For a post-login redirect, include the exact `success_url`. Every URL must share the approved HTTPS origin.

Keeper's offline browser validates a single-step URL-encoded HTML form with scripts disabled, supplies the stored username and password privately, and submits through verified TLS. It checks the success element and discards the temporary session and cookies. This is brokered form submission; it does not expose an ongoing authenticated browser session. JavaScript-only sign-ins, MFA and multi-site sign-ins need another flow.

The browser worker requires Bubblewrap, the systemd user manager, WebKitGTK 4.1 and Xvfb. `./install --agent` installs these dependencies on Ubuntu.

For an interactive VM installer, **Review Guest Console** can authorize a session to an exact RFB console over a TLS WebSocket. Keeper performs login and ticket exchange in the vault worker. The agent can request a PNG and send keyboard or mouse input through `keeper-agent console`. The session is bound to the token that opened it and lasts up to 15 minutes. Pausing access, locking the vault or changing the token closes that session. Console pixels and keystrokes stay out of Activity. The installed skill includes a Proxmox QEMU descriptor. RFB console delivery does not create a general signed-in browser session.

With **Auto Approve** and **Guest Consoles - Open and Reconnect** enabled, the owner can approve an exact, certificate-pinned console connection for up to 60 minutes. Within that window, the same agent can reopen the connection without another popup, and each session ends by the approved deadline. The console switch starts off. Pause access or lock the vault before reassigning the console endpoint to a replacement guest.

Open **Access → Review Next** to get back to pending requests, including ones whose popups you dismissed. Keeper opens the timed request that expires first when one is waiting, and the popup shows its remaining time. Access and edit requests for a locked vault offer **Unlock** and return to the same pending review after unlocking. Unlocking and approving are separate steps.

`keeper-agent console view --console HANDLE --status` reports whether the console pixels changed since the previous view or check. The agent decides whether to request an image with `--png` or `--json`. Status checks are listed separately from image views in Activity.

`console wait --console HANDLE --timeout 30 --json` waits for a frame change and returns status only. The first observed frame can count as a change. A frame change does not establish that the guest is ready. Use a structured guest job status when available.

**Guest Commands - Run** governs command APIs with a separate status endpoint. The review shows the pinned destination, credential, exact POST and GET requests, command field, and results the agent can see. One approval covers submitting a command and checking its job. With the switch and Auto Approve enabled, the owner can allow any command at that exact endpoint for a bounded window. The approved credential and service must limit commands to the intended guest. The switch starts off, and the agent can still request individual commands for review. Job IDs stay private. The installed skill shows how to use `keeper-agent guest run` and `guest status` with a write receipt.

`guest wait --receipt UUID --until exited --equals-json true --timeout 30 --json` waits for an approved result field. In the pinned synthetic guest test, submitting a job and checking twice uses one private login. A short cache stays in the vault worker for that exact authorized job. Every status request still verifies TLS and the live grant.

## Use a credential with a local command

The agent calls `keeper-agent --profile PROFILE run --vault VAULT_UUID --entry ENTRY_UUID --json -- /usr/bin/example --read-stdin`. No saved command or action ID is needed. Keeper checks the installed system executable and pins its digest for that use, creates a disposable sandbox, and delivers the password as UTF-8 bytes on private stdin followed by EOF. Local jobs have no network or writable host files; `/usr` is mounted read-only.

Dynamic commands return `{"outcome":"dispatched"}` after authorized handoff. This confirms dispatch, not command success. Subprocess output and exit status remain private so agent-supplied programs cannot return the credential through those channels. The owner's Activity records execution separately. Verify external effects independently before retrying a mutation. An arbitrary program receiving a credential can disclose it to an approved recipient; this is why the owner approves capabilities and destinations explicitly.

## Use a credential with a networked command

The same `run` command accepts `--origin https://service.example.test/ --prompt-variable GIT_ASKPASS` (or a `tcp://host:port` origin) before `--` and the executable/arguments. The prompt variable must end in `_ASKPASS`. When `prompt_variable` is `SSH_ASKPASS`, Keeper automatically sets `SSH_ASKPASS_REQUIRE=force` and `DISPLAY=keeper`. Keeper answers the first prompt privately, regardless of its wording. Set any nonsecret username and other answers beforehand so that this first prompt expects the selected secret. Keeper does not embed the credential in the host command or agent-visible environment.

The sandbox mounts synthetic `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`, and `/etc/services`, and provides a SOCKS5 Unix-socket relay restricted to the approved TCP peer and port. Non-HTTP tools such as `ssh` can pass `-o ProxyCommand="/keeper/prompt --proxy-stdio %h %p"` to bridge stdio through the relay. The command controls its protocol, TLS validation, and paths or repositories; a shared address can host multiple services or tenants. This is a TCP recipient restriction, not an HTTPS-aware command firewall. Use a program supporting the supplied proxy and credential prompt. The system CA bundle is mounted at `/keeper/trust.pem`. Use Keeper's direct HTTPS or browser transport for broker-verified TLS.

A networked command can receive one nonsecret artifact with `--input < artifact`, mounted read-only at `/input`, up to 8 MiB. Keeper checks its size and digest. MCP callers provide the same command descriptor under `usage` and the artifact under `input_base64` (or `input_path` via `keeper-connect`). No command output or authenticated session returns to the agent. Existing preconfigured actions and their exact-command grants remain available for compatibility, but reusable delivery does not require creating them.

## Use a credential with brokered SSH and SFTP

For remote shell commands (`ssh_exec` / `ssh exec`) and bounded SFTP transfers (`ssh_upload` / `ssh upload`, `ssh_download` / `ssh download`), grant `ssh_exec` and/or `ssh_sftp` on an exact `ssh://host[:port]` origin (plus `ssh_sudo` when `sudo` is needed, either on the same entry or on a separate `sudo_entry`). Keeper authenticates inside the broker using KeePass SSH private key attachments (`--attachment` or auto-detected PEM attachment), `ssh_private_key`, a PEM private key stored as the entry password (with optional `ssh_passphrase`), or password authentication.

Keeper pins the server's SSH host key per token, entry, credential revision, and `ssh://` origin (TOFU). First-use and changed host keys require owner approval unless **SSH Host Keys - First Use** or **SSH Host Keys - Accept Changed Key** is enabled. Agents can request a bounded reuse window (1–60 minutes) with `--reuse-for` / `reuse_minutes`, governed by **SSH Connections - Reuse Window**.

## Review agent edit requests

An active runner token can submit one edit request with a new UUID and exact vault, entry or group references. In **Access**, open the pending edit to see its target, destination, and changed fields. Choose **Approve and Apply** or **Deny**. If agent access is paused, you can explicitly resume it from the review first. Keeper requires a fresh request if the reviewed vault state changes.

Agent-created entries must go in a named group. Agents can request a top-level group and can move an existing root entry into a group. To save a login in one review, include the password source in the create-entry request. With the owner source, enter the account's current password directly in Keeper and save it with the rest of the entry. **Save Password in Keeper** updates a vault entry for an existing login. The service's password remains the same.

Right-click a folder and choose **Copy Group Reference**, or right-click an entry and choose **Copy Entry Reference**, to give the agent the exact target.

The CLI submits proposals with `keepassxc-agent edits request --json` and checks their status with `keepassxc-agent edits status --request REQUEST_UUID --json`. The stdio runner offers `request_edit` and `edit_status`. See the KeePass skill for the request format. Reuse the same UUID for transport retries. Each approval applies to a single change. Completed edit records lose identity and project details after the Activity retention period. Keeper keeps request IDs, digests, and outcomes to prevent replay and return consistent results for retries.

Supported requests create entries or groups, edit entry metadata (including optional `notes`) or rename groups, move or recycle an item within its vault, and replace an entry password. A password request selects **Keeper-generated** or **owner-entered** in the request. Keeper handles the actual password inside the owner account. Changes through Keeper to an entry's username or password invalidate its credential action approvals. Reopening a vault saved by another KeePass client invalidates all credential action approvals for that vault. Keeper refuses vaults with duplicate entry or group IDs. Edit outcomes and changed field names are recorded in **Activity**. The Vault, Group, and Key columns identify the affected resource. Related events show their latest outcome in a summary row. Expand it to see the full history, and double-click an event for details.

## Test with synthetic data

```sh
PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v
tests/run-linux-integration
TRAY_TEST_ISOLATION=1 tests/run-linux-integration
```

The integration runner uses a private GNOME Wayland compositor, D-Bus session, and disposable OS keyring. The isolation option requires Linux subordinate UID/GID mappings and `setfacl` from the `acl` package. It verifies legacy setup and recovery, the GNOME launcher, and the scoped workspace with two disposable vaults that share KeePass IDs. The workspace scenario checks CLI enrollment, metadata-only and use-only grants, destination binding, per-token revocation, desktop lock, and Activity without using personal vaults. The runner scenario exercises the stdio tools with a disposable vault and local HTTPS service. From the desktop session, run `PYTHONPATH=src /usr/bin/python3 tests/browser_scenarios.py` to check a synthetic sign-in, exact form and redirect scope, credential and cookie privacy, and Activity.
