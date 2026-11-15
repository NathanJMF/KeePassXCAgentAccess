# Tasks

## 1. Owner settings and activity storage

- [x] 1.1 Add and validate owner-side settings for the broker endpoint, access mode, per-entry review flags, and HTTPS action bindings. Test defaults, restart persistence, entry rename and move, vault selection changes, invalid destinations, and existing environment configuration.
- [x] 1.2 Add local activity storage and automatic session registration. Test OS identity attribution, per-request model and chat changes and provenance, retention, safe timestamps and outcomes, and cleanup of interrupted requests after restart.

## 2. Broker policy and desktop approvals

- [ ] 2.1 Evaluate operation eligibility and the three modes for agent listing and credential-use requests. Verify a matrix of modes, eligible and ineligible clients, unknown actions, and flagged and unflagged entries, including Smart access listing and its explicit review option.
- [ ] 2.2 Add the exact-request approval queue and desktop **Approve once** and **Decline** dialogs. Exercise successful approval, decline, dismissal, expiration, duplicate approval, disconnect, vault lock, policy edits, and action changes before dispatch. Verify other requests and the desktop remain responsive.
- [ ] 2.3 Gate protected responses and dispatch on durable activity decisions. Test failed storage, revocation races, and that a failed audit write results in no listing or credential delivery.

## 3. Credential adapter and agent workflow

- [ ] 3.1 Add a typed credential-use request to the private vault worker and implement the configured HTTPS Basic-auth GET action. With a disposable TLS server, verify one authorized request, TLS failure, redirect confinement, route override rejection, timeout, and safe output when the server echoes authorization material.
- [ ] 3.2 Add the agent CLI options and update the skill. Verify the documented listing and use commands, the unchanged listing JSON shape, and bounded success and failure responses through the isolated client. Exercise missing model and chat metadata and a well-formed agent-reported attribution.

## 4. Owner desktop and launcher

- [ ] 4.1 Add desktop controls for the allowed runtime, mode, entry review toggles, and actions editor. Verify settings persist and the owner can enable or stop agent access and open pending requests from the tray.
- [ ] 4.2 Add the Activity window with columns **Time**, **Model**, **Chat**, **Action**, and **Outcome**. Verify ordering, filtering, row details, and visible distinctions between automatic allowance, manual approval, decline, revocation, and execution errors.
- [ ] 4.3 Add and document the per-user GNOME launcher and installation step. In a private GNOME session, launch with and without saved settings, verify reopening uses one instance, and verify persisted broker settings work without launch-time environment variables.

## 5. Integration verification

- [ ] 5.1 Rehearse the complete upgraded workflow with a synthetic vault, isolated agent, and local TLS fixture. Verify all three modes, real popup decisions, lock and stop-access revocation, and matching Activity rows. Check captured command output and activity records for synthetic secret sentinels.
