# Tasks

## Isolated local stdin

- [x] Add an owner-configured command policy and pin its executable digest and literal args in the grant.
- [x] Extend the CLI and stdio interface to accept the credential reference and exact command.
- [x] Supervise the sandbox with resource and lifetime limits. Recheck authorization immediately before stdin delivery and return a status-only result.
- [x] Verify exact-scope rejection, binding revision changes, revocation, and sandbox behaviour with a synthetic vault.
- [x] Complete the staged implementation review with Astra.

## Networked command prompts

- [x] Add a private prompt, bounded input file transfer, and an exact-origin network relay.
- [x] Review the isolation and authorization path with Astra.
- [x] Verify a synthetic HTTPS Git push end to end and check wrong-origin refusal, hidden credentials, and Activity.

## Additional profiles
- [ ] Define and review reusable API and protected browser delivery profiles and test their session and output boundaries.
