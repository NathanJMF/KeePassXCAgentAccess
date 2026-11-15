# Tasks

## 1. Owner-side vault and lifecycle

- [x] 1.1 Add a read-only KeePass backend for password and optional key-file unlock. Verify supported synthetic fixtures open, invalid factors fail, and opening and closing leave the database bytes unchanged.
- [x] 1.2 Add a vault controller for setup, locked, and unlocked states. Verify that failed unlocks keep the vault locked, closing an unlocked session releases backend state, and a lock or shutdown invalidates an in-flight unlock.

## 2. Setup and keyring

- [ ] 2.1 Build the first-run wizard with file selection, masked password input, optional key-file selection, and verification before saving. Exercise setup success, wrong password, missing file, and cancelled setup with an existing configuration.
- [ ] 2.2 Integrate the OS keyring with **Remember on this device**, keyring retrieval on explicit unlock, and manual recovery. Verify opt-in, session-only setup, successful retrieval after restart, cancelled or unavailable keyring access, and a saved password rejected after rotation.
- [ ] 2.3 Add cleanup for password replacement, switching to session-only use, and **Forget saved password**. Verify that obsolete items are removed after a successful save, a failed save preserves the prior configuration, and deletion failure remains pending across restart. Verify retry succeeds and pending items cannot be used for unlock.
- [ ] 2.4 Check the secret-handling paths with a synthetic password. Verify its absence from persisted configuration, logs, process arguments, and captured output on both success and failure.

## 3. Linux desktop tray

- [ ] 3.1 Implement the tray states and **Setup**, **Settings**, **Unlock**, **Lock now**, and **Quit** actions. Exercise first launch, closing and reopening the window, normal unlock and lock, and the main-window fallback on Ubuntu GNOME on Wayland with AppIndicator support enabled for the tray cases.
- [ ] 3.2 Connect desktop lock, logout, and shutdown to the vault controller on the same Ubuntu GNOME Wayland baseline. Verify session lock while unlocked and during unlock, and verify relaunch starts locked.

## 4. Deployment and cutover

- [ ] 4.1 Document running agents under a separate, unprivileged OS account alongside the owner's Ubuntu GNOME Wayland session. With the owner desktop and vault unlocked, verify from the agent account that direct reads of vault and key files, keyring and session-bus access, owner process inspection, and desktop control are denied.
- [ ] 4.2 Document legacy password rotation, recovery, and plaintext file retirement. Rehearse the documented flow using a synthetic vault and separate test keyring. Verify a fresh tray unlock with the legacy input unavailable, and check that a failed rehearsal leaves retirement pending and offers manual recovery.
