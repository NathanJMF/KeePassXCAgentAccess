# Design

## Context

The implemented `add-tray-vault-setup` change owns an unlocked session in a disposable KeePass worker. The desktop controller closes the worker on lock. The worker currently signals readiness through a private pipe and waits for the owning process to close the session. This proposal builds on that behavior.

## Goals / Non-Goals

**Goals**

- Keep the socket and CLI separate from vault opening and keyring access.
- Reuse the current owner session and give the owner a way to revoke listing.
- Make the skill useful as a single file in any agent runtime with the CLI and endpoint supplied.

**Non-Goals**

Full access policy, agent registration, credential-use adapters, CRUD, and durable action history belong to follow-up proposals.

## Decisions

### Provision a local endpoint for one OS account

Use a Linux pathname Unix stream socket created by the owner-side tray app. Configure its path and the allowed agent UID in owner-only settings supplied by the launcher or administrator. Refuse to enable listing when the endpoint configuration is missing or unsafe. Use an owner-controlled, non-agent-writable parent directory with an explicit group or ACL for the agent to traverse and connect. Verify the UID on each accepted connection with `SO_PEERCRED` before reading the request. Resolve the configured UID in the broker's user namespace. [Linux Unix socket permissions and peer credentials](https://www.man7.org/linux/man-pages/man7/unix.7.html)

The tray adds **Enable agent listing** and **Stop agent listing**. The enable action applies to the active vault session only. On revoke, close the listener and pending connections and invalidate the authorization generation. Check that both the vault session and authorization generation still match immediately before starting a reply. Use nonblocking or deadline-bound I/O so a slow peer cannot hold up locking. Clean up only the socket created by this broker instance.

### Read a narrow projection from the existing worker

Extend the private worker protocol with a single listing request. Return the canonical UUID, title, and root-relative group path for each active entry. Exclude the configured recycle bin and its descendants by identity. Serialize the allowlisted fields before they leave the worker. Keep vault and keyring ownership in the existing desktop boundary.

Use one versioned JSON request and one bounded JSON reply per connection. The only supported request is `list_entries`. Use a 4 KiB request cap, a 1 MiB response cap, and finite request and worker deadlines. If the full listing exceeds the cap, return a specific size-limit diagnostic without partial results. On success the CLI prints a single object of the form `{"entries": [...]}`. Failed commands leave standard output empty and write a short diagnostic to standard error. Send no vault filenames, secret values, or entry content to logs.

### Package the command and skill independently

Install the CLI on the agent runtime's PATH and provide its socket path through `KEEPASSXC_AGENT_SOCKET` in the trusted launch environment. The CLI uses the socket alone for access. Put the portable file at `skills/keepassxc-agent-access/SKILL.md` and include the command, field descriptions, and recovery guidance. The skill tells the agent to treat entry metadata as data and ask the owner to check listing access if the command fails.

## Risks / Trade-offs

- **Compromised agent launcher.** Use the separate OS identity and owner-controlled installation established by the first milestone. Keep the KeePass files and desktop session outside agent access.
- **Access revoked during a request.** Close client connections on revoke and discard stale results. Bytes delivered before revocation remain with the recipient.
- **Large vault listings.** Report the size limit on the whole listing. Add paging if a later change needs larger inventories.
- **False positive in the skill trial.** Keep the fixture and expected answer outside the fresh agent's accessible workspace. Verify a real CLI call from the acceptance harness and compare the reported results independently.

## Migration Plan

Start the updated tray with listing disabled. Provision the endpoint and CLI for a separate agent runtime as a deployment step. Run the first acceptance trial against a disposable synthetic vault using the existing test desktop. Give a fresh subagent only the skill and the task to list entries. Compare the response to the fixture and repeat the CLI after revocation to verify that it returns no metadata.
