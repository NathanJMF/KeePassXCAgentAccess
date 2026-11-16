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

## HTTPS API requests

- [x] Add separate credential review settings and migrate the previous password-use policy.
- [x] Extend HTTPS profiles with a fixed method, endpoint, authentication scheme, and optional fixed JSON body.
- [x] Include the method and body in review and the binding revision. Record the request outcome without credentials or raw API content.

## Browser sign-ins

- [x] Pin the login page, form fields, exact submit URL, and success check in the token scope.
- [x] Inspect HTML in a private offline browser and submit through the trusted TLS worker.
- [x] Record the authorization and outcome in Activity without session data.
- [x] Verify the isolated runner against a synthetic login and complete implementation review.
