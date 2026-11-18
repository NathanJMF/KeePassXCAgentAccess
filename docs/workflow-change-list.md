# Keeper workflow changes

The Forgejo rebuild and IP move logged 50 approval decisions, including 25 one-time HTTPS writes and six console opens. Keep that run as the interruption baseline. Measure rebuild and IP move separately so that guest installation time, owner wait, request retries, and console interaction can each be compared.

## Ordered changes

- [x] **Guest Consoles.** Add a default-off Auto Approve switch. Let the owner approve the exact pinned connection for a bounded window, and reopen it without a repeat review while the grant is valid. Retain one-session review for existing clients. Test descriptor changes, token and credential changes, expiry, revocation, and owner settings.
- [x] **Write receipts and recovery.** Record whether Keeper dispatched a write, whether it received an HTTP status, and whether the requested result fields were available. Let agents check an interrupted operation without submitting the write again. Test ambiguous transport failures, interrupted delivery, and duplicate requests.
- [x] **Guest Commands.** Add a default-off Auto Approve switch for a reviewed guest command workflow. Bind submission, polling, and result fields to the approved guest endpoint and credential. A command and its result have one approval. Keep the templates generic and test them against a synthetic guest service.
- [x] **Pending reviews.** Give owners a queue they can return to after dismissing a popup or unlocking a vault. Surface the agent, affected resources, what it wants to do, and when the request expires. Keep paused and locked states enforced.
- [x] **Task review with an existing token.** Present the pinned destination, credential and related HTTPS writes, console opens and guest commands in one itemized review. Bind later steps to validated IDs returned by approved steps. A changed plan needs its own review. Group related events in Activity and retain individual step receipts.
- [x] **Task enrollment.** Register fresh profiles with a workflow-only token under the same decision as the exact manifest. The credential is bound to the workflow UUID and digest. Denying a request while paused keeps access paused.
- [x] **Readiness and reconnects.** Use bounded waits and structured status for guest jobs and console changes. Make screenshots opt-in and keep result access bound to the original grant. The pinned guest fixture uses one private sign-in for submission and two status reads. Reuse is scoped to that job inside the vault worker.
- [x] **Account provisioning.** Generate a password in a scoped Keeper entry and apply it through a reviewed write using a separate scoped administrative credential in the same vault. Verify the remote account with the administrative status read. Preserve the receipt for recovery, filter reflected credential values, and let the agent release the account entry.
- [x] **Agent entry points and synthetic verification.** Exercise the CLI, stdio tools, broker, and private TLS transport with disposable profiles and vaults. Validate the skill and verify the full regression suite.
- [ ] **Installed isolated runner and production timing.** Check enrollment through the installed Linux namespace runner, then measure a comparable Forgejo setup and IP move. The current test host rejects UID mapping in `newuidmap`, before the isolated profile can enroll.

For each change, test the regular entry point and the relevant denial cases, then resolve Astra’s review feedback and ask for another pass before starting the next item.

## Verification

- A fresh CLI profile registered and completed two dependent writes with one owner decision. The synthetic broker fixture models its peer UID. Direct use and ordinary permission changes were rejected.
- A mixed workflow used one decision to create a guest, open and reconnect its console, and run and check a guest command. Resuming after a broker restart restored the approved dependency without resending its completed write.
- The synthetic pinned guest service needed one private login for submission and two status checks. Console status requested zero screenshots. These fixtures establish action counts. Forgejo deployment time still needs a comparable production run.
- A disposable KeePass vault generated an account password, which the synthetic HTTPS service received once after approval. The broker returned safe projected fields and a receipt. Release revoked an in-flight review and prevented further provisioning from that token.
