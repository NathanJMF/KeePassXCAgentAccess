# Tasks

## Isolated local stdin

- [x] Add an owner-configured command policy and pin its executable digest and literal args in the grant.
- [x] Extend the CLI and stdio interface to accept the credential reference and exact command.
- [x] Supervise the sandbox with resource and lifetime limits. Recheck authorization immediately before stdin delivery and return a status-only result.
- [x] Verify exact-scope rejection, binding revision changes, revocation, and sandbox behaviour with a synthetic vault.
- [x] Complete the staged implementation review with Astra.

## Additional profiles

- [ ] Define and review a reusable credential-delivery policy for networked CLI. Verify it with a scoped Git push.
- [ ] Define and review reusable API and protected browser delivery profiles and test their session and output boundaries.
