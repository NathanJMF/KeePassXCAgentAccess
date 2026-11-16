# Tasks

## Git HTTPS

- [ ] Add a destination- and branch-bound Git action to desktop configuration and scoped grants.
- [ ] Add a bounded upload and commit validation protocol with durable request identities.
- [ ] Implement credential-free bundle preflight and a supervised, isolated push with a job-specific credential exchange.
- [ ] Use a synthetic vault and local HTTPS Git server. Verify replay handling, scope changes, revocation, TLS validation, redirects, resource bounds, and process cleanup. Check that synthetic secrets never appear in results, errors, Activity, process arguments, environments, traces, or temporary files.
- [ ] Have Astra review implementation and test results before enabling the adapter in the installed copy.

## Deferred transports

API and browser operations need separate operation-specific proposals and reviews. Their requirements in this change define the common security boundary. This change implements only the Git HTTPS action.
