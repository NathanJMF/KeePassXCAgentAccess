# Design

## Context

The tray owns an unlocked KeePass worker. The current broker verifies a separate OS UID over a pathname socket and exposes one bounded operation for listing entry metadata. The broker handles connections serially and uses a short deadline. The current desktop entry point is `run-tray`, with broker configuration supplied through launch environment variables.

## Goals / Non-Goals

**Goals**

- Keep policy decisions, credentials, and administrative controls on the owner side of the existing boundary.
- Let the owner authorize a specific operation and review an accurate local record of the result.
- Keep the agent workflow declarative and let the owner operate the app from GNOME.

**Non-Goals**

Vault CRUD, arbitrary shell execution, clipboard or plaintext secret export, and additional credential adapters are follow-up work.

## Decisions

### Dispatch one configured type of credential action

Use `keepassxc-agent use --entry <id> --action <id> --json`. The owner configures each action's display name, entry binding, and exact HTTPS host, port, and path in the app. Resolve the action from owner-side settings. Accept no URL, command, headers, request body, proxy, or argument overrides from the CLI. Reject URLs with embedded credentials, query strings, fragments, or ambiguous authorities. The skill describes the command and takes the action ID from the task or the owner.

Extend the private worker protocol with a typed action request alongside listing. The worker retrieves the entry username and password after authorization and constructs the Basic-auth header in memory. Use a direct, certificate-verified HTTPS connection with a bounded timeout and no redirects or retries. The configured service receives the header. The worker returns a structured success or failure and the HTTP status when available, with a fixed diagnostic for unsupported credential encoding or TLS failure. The broker and UI consume only that result. Future adapters can use the same authorization and result contracts. [HTTP Basic authentication and TLS](https://www.rfc-editor.org/rfc/rfc7617)

### Apply policy to the exact live request

Keep the existing local peer check and explicit owner enablement for each unlocked session. Store the selected mode and per-entry review flags in owner-only settings. Scope flags and action bindings to the configured vault identity and entry UUID. Arm them for the active vault snapshot only. An entry with no stored flag requires review. Selecting a different vault keeps that vault's settings separate.

Apply eligibility before access mode. For listing, use the active metadata set. In Review all, ask once for that bounded listing and show what it covers. In Smart access, return the unflagged rows for the existing list command. Add `--include-reviewed` for an explicit request that also covers flagged rows. Keep the successful listing envelope and row fields compatible. The CLI uses a separate, bounded deadline for approval waits and cancels the request on disconnect.

Give approved and automatically allowed requests the same dispatch checks. Bind the record to the authenticated peer, operation, entry or listing snapshot, action configuration revision, policy revision, and vault session. Use a one-shot request ID and expiry. Serialize authorization consumption with revocation and recheck the same bindings immediately before protected work. On lock or stop access, cancel pending requests and terminate work that can still be cancelled. A request already sent to its configured endpoint remains visible in history.

### Put review and settings in the owner desktop session

Extend the GTK window with **Access**, **Actions**, and **Activity**, alongside vault setup and controls. Provide the mode selector, entry review toggles, validated broker account and socket settings, and the actions editor. The tray exposes **Enable agent access**, **Stop agent access**, pending approvals, and Activity. The owner is always able to stop access or lock from the tray.

Dispatch pending requests onto the GTK main loop. Use native prompts with a bounded waiting queue so an agent connection waiting on approval cannot block other clients or the desktop. Display the operation, verified OS identity, action and exact destination for a use request, and the affected scope for listing. Show model and chat labels with their provenance when available. Route approval responses through the owner-side UI. Dismissal, expiry, or an inactive desktop session prevents delivery.

### Store structured local activity

Use an owner-only SQLite store. Create or recover the lightweight audit session on first eligible request using the verified peer identity and optional conversation ID. Record model and chat labels per request, with bounded fields. Mark values supplied by the client as agent-reported. Use a trusted-host label only when the transport independently authenticates its provenance. Leave missing fields unavailable. These labels support auditing and never grant permission.

Record the accepted request and its decision before releasing results or dispatching a credential. Update the row with the observed outcome and timestamps. Distinguish declined, timed out, revoked, execution failed, and successful requests. If the app restarts with a dispatch recorded and no final result, mark it interrupted with the outcome unknown. Avoid importing raw client messages, endpoint output, or credential material. Show the agreed columns in the desktop app and provide a configurable retention period.

### Install a desktop application entry

Provide an owner-run installer for a per-user GNOME `.desktop` entry. Generate the launcher from the trusted install path and open the existing application window using its single-instance GTK application ID. First launch from the menu should present the window even when tray integration is available. Store the validated broker account and socket path in owner settings so the app can start from GNOME without a terminal environment. Keep the existing environment-based configuration as a fallback for installations that use it. [Freedesktop Desktop Entry Specification](https://specifications.freedesktop.org/desktop-entry/latest/)

## Risks / Trade-offs

- **A reviewed action changes during approval.** Tie the approval to exact revisions, invalidate stale requests, and require a new decision.
- **Endpoint attempts to reflect credentials or redirect traffic.** Return only structured status and keep the request on the configured HTTPS endpoint.
- **Activity storage fails or the app exits mid-operation.** Gate protected work on durable recording and preserve an interrupted outcome if completion is unknown.
- **Chat and model attribution is incomplete.** Preserve the OS identity and label unsupported or agent-reported context explicitly.

## Migration Plan

Load existing vault and keyring settings and start with Review all and agent access disabled. Read existing broker environment settings where no owner configuration exists. Install the application-menu entry as an explicit user step. Verify the upgrade on a synthetic vault and a local TLS test service before using configured real actions.
