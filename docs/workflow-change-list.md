# Keeper workflow changes

The Forgejo rebuild and IP move logged 50 approval decisions, including 25 one-time HTTPS writes and six console opens. Keep that run as the interruption baseline. Measure rebuild and IP move separately so that guest installation time, owner wait, request retries, and console interaction can each be compared.

## Ordered changes

- [x] **Guest Consoles.** Add a default-off Auto Approve switch. Let the owner approve the exact pinned connection for a bounded window, and reopen it without a repeat review while the grant is valid. Retain one-session review for existing clients. Test descriptor changes, token and credential changes, expiry, revocation, and owner settings.
- [x] **Write receipts and recovery.** Record whether Keeper dispatched a write, whether it received an HTTP status, and whether the requested result fields were available. Let agents check an interrupted operation without submitting the write again. Test ambiguous transport failures, interrupted delivery, and duplicate requests.
- [ ] **Guest Commands.** Add a default-off Auto Approve switch for a reviewed guest command workflow. Bind submission, polling, and result fields to the approved guest and credential. A command and its result have one approval. Keep the templates generic and test them against a synthetic guest service.
- [ ] **Pending reviews.** Give owners a queue they can return to after dismissing a popup or unlocking a vault. Surface the agent, affected resources, what it wants to do, and when the request expires. Keep paused and locked states enforced.
- [ ] **Task review.** Present the known grants, certificate trust, and related operations in one itemized review. Bind later steps to validated IDs returned by approved steps. Ask again when a step needs wider authority. Group related events in Activity and keep individual decisions and outcomes available.
- [ ] **Readiness and reconnects.** Use bounded waits and structured status for guest jobs and console changes. Make screenshots opt-in and keep result access bound to the original grant. Check private sign-in overhead and keep any session reuse inside the vault worker.
- [ ] **Account provisioning.** Generate a password in a scoped Keeper entry, apply it through a reviewed private workflow, verify the remote account, and let the agent release its grant. Support workflows that need a separate approved administrative credential. Make partial progress recoverable without recreating accounts or accidentally rotating credentials.
- [ ] **Agent entry points and verification.** Keep the installed CLI and skill in sync with each change. Run the workflow from a fresh agent with a synthetic vault and service, exercise the full regression suite, and compare owner decisions, runtime, screenshots, and retries with the baseline.

For each change, test the regular entry point and the relevant denial cases, then resolve Astra’s review feedback and ask for another pass before starting the next item.

The target is one approval for a setup with a known scope and zero repeat prompts for covered console reconnects, commands, or result checks. Pause, vault lock, revocation, and changed credentials or destinations must still take effect. Keep credentials, session tickets, and passwords out of agent output and Activity.
