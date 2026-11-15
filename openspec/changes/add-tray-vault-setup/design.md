# Design

## Context

This is a greenfield project with OpenSpec as its only existing project structure. The first milestone establishes the desktop owner interface and a read-only KeePass vault session. It gives later broker features a defined place to request use of an unlocked vault.

## Goals / Non-Goals

**Goals**

- Keep persistent unlock credentials in the owner's OS keyring and make successful retrieval visible in the tray.
- Give a single owner-side component control over the lifecycle of the unlocked database and any retained credentials.
- Define a deployment boundary and rehearse the migration using a synthetic vault.

**Non-Goals**

Agent registration, approval modes, activity history, credential delivery, and entry mutations belong to subsequent changes. This milestone focuses on a single existing database and password-based unlock with an optional key file.

## Decisions

### Use an owner-side desktop process

Run the tray, setup dialogs, keyring access, and read-only KeePass adapter in the owner's Ubuntu GNOME Wayland session. Keep the vault session behind the adapter, with one place to close it on lock or shutdown. Run the supported agent runtime under a separate, unprivileged OS account with access to approved workspaces. Keep the owner-side vault, optional key file, session endpoints, and administrative controls inaccessible to that account. A future broker endpoint can grant the account narrowly scoped access to approved operations.

An unlocked desktop keyring is accessible according to the platform's session permissions. Test from the separate account while the owner session and vault are unlocked. Check access to the database and key file, the owner's session bus and keyring, the Wayland socket and desktop controls, and owner process memory. The guarantee applies to this deployment and assumes the agent account cannot elevate to the owner or root. [Secret Service access control](https://specifications.freedesktop.org/secret-service/latest/ch10.html)

### Use the system keyring for remembered passwords

On Linux, use the desktop's Secret Service provider. Store a random item identifier with local vault settings and use it to address the keyring item. Keep file locations and keyring references in owner-only local settings. Store the password in the keyring only after the proposed configuration opens the database. Report save success after settings and the keyring item are both usable. Preserve the previous configuration on failure and clean up any unreferenced item created during the failed attempt. A failed keyring write leaves the owner with the retry and session-only paths.

When replacing a saved password or switching to session-only use, save the new configuration together with the IDs of obsolete app-owned items that still need deletion. Start deletion after that save succeeds. Persist pending deletions across restarts and let the owner retry them from Settings. Unlock only uses the active item. **Forget saved password** first locks the vault and marks the active item for removal, then deletes that item and retries any pending removals before reporting that the password was forgotten.

Treat password entry and saved-password retrieval as transient. Discard plaintext input once the backend has opened the vault, using the backend's session state for the rest of the unlock. Closing that session drops its keys and decrypted state. Manual desktop entry is the recovery path if the keyring is unavailable or the password has changed. An optional key file remains a separate owner-side file.

### Use a tray state that reflects actual vault availability

Use Ubuntu GNOME on Wayland with AppIndicator support enabled as the first tray and session-lock test environment. Keep the setup window available where a tray is unavailable. Derive the visible state from the vault controller. Route tray actions, desktop lock notifications, and shutdown through that controller. An unlock finishing after a lock or quit event must have its result discarded and any opened session closed. [AppIndicator support](https://github.com/ubuntu/gnome-shell-extension-appindicator)

## Risks / Trade-offs

- **Locked keyring or changed vault password.** Show why the vault stayed locked and offer a verified manual unlock. The owner can save a replacement only after the new password works.
- **Interrupted keyring or settings update.** Track partial saves and surface pending deletion on the next launch. A failed deletion leaves the item disabled for unlock and available for a cleanup retry in Settings.
- **Unavailable desktop session signals.** Document the supported desktop baseline and verify lock and logout behavior on it before release.
- **Earlier copies of the database.** Rotate the old password in KeePassXC and review backups separately. Older copies can still open with the credential in use when they were created.

## Migration Plan

1. Rehearse setup, restart, and recovery using a disposable vault and a test keyring with synthetic credentials.
2. For an existing installation, have the owner verify their recovery path and rotate the database password in KeePassXC. Enter the new password in the desktop wizard and enable **Remember on this device**.
3. Restart the app and unlock from the tray with the plaintext file unavailable. Show when the successful unlock used the keyring. If verification fails, use manual desktop entry and repair or replace the saved item.
4. After successful verification, have the owner retire the old plaintext file. Existing database contents and password changes remain under the owner's control in KeePassXC.
