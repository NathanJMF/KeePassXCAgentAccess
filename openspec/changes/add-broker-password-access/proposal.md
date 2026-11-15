# Proposal

## Why

Agents can already list entry metadata from an unlocked vault. The owner needs a way to let an agent use a password for a known operation, decide when to review it, and inspect the result afterward.

## What Changes

- Add a broker command that uses a vault credential for an owner-configured action. Start with a fixed HTTPS Basic-auth GET and return only the operation result.
- Add **Allow all**, **Review all**, and **Smart access** for agent listing and password use. Smart access reads an owner-managed **Require approval** flag for each entry.
- Show native **Approve once** and **Decline** prompts for requests that need review. Keep the current desktop lock and stop-access controls as revocation points.
- Register agent sessions automatically on first eligible request and record outcomes in a local Activity view with **Time**, **Model**, **Chat**, **Action**, and **Outcome**.
- Extend the desktop app with access settings, entry review flags, action configuration, pending requests, and Activity. Provide an installable GNOME application-menu launcher.

## Capabilities

### New Capabilities

- **`agent-credential-use`** covers credential use through owner-configured actions.
- **`agent-access-policy`** governs access modes, per-entry review, and one-time desktop approvals.
- **`agent-activity`** covers attribution, event storage, and the Activity view.
- **`desktop-launcher`** covers installing and opening the owner app from the GNOME application menu.

### Modified Capabilities

## Impact

Extends the tray app, local broker, read-only KeePass worker, CLI, and agent skill. Applies policy to the listing contract introduced by `add-agent-entry-listing` while keeping its entry fields and JSON shape. The first password adapter is HTTPS Basic auth. Registered stdin-based actions and vault mutations are follow-up work.
