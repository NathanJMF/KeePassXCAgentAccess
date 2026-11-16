# Design

## Reference and grant model

An agent identifies a vault, entry, and approved action. For a command, it also supplies the argument vector to run. The owner defines which program and inputs are allowed and how it receives the secret. The broker rejects commands outside the approved scope. The reusable interface applies to delivery channels and isolation policies. Applications use those policies through configuration.

A grant pins the action revision. Changing the consumer, arguments, transport policy, destination, or the pinned executable requires approval for a new grant. Standard lock, pause, and one-use review settings apply. Repeated uses within an active grant can run without further owner input when per-use review is off. Activity records the action and its outcome every time.

## First profile

The consumer is an owner-approved system executable with an exact argument vector and a pinned binary digest. Keeper launches it in a private Linux sandbox with a read-only system runtime, no host working directories or session sockets, bounded temporary storage, an empty environment apart from its private home, and a separate network namespace with socket creation disabled. The operating system's trusted libraries and runtime are part of this profile. The process scope limits memory, tasks, and CPU. Keeper rejects the request if the sandbox cannot start.

Keeper waits for sandbox readiness and rechecks authorization before delivering the entry's password as UTF-8 bytes on stdin followed by EOF. The secret never appears in argv or the command environment. The broker generates a success or failure result. It discards stdout and stderr and confines process lifetime to the sandbox and its supervisor.

## Networked command profile

The owner binds the exact command, HTTPS origin, prompt variable, and input file policy. The sandbox remains disconnected from direct IP sockets and exposes a per-job Unix-socket SOCKS relay. The relay resolves only the approved host, connects to the resolved numeric address and approved port, and bounds traffic, connections, and lifetime. The trusted command verifies TLS and enforces its HTTPS path, repository, and branch. Scope is updated when any of those policy inputs change.

The private prompt helper answers one bounded password prompt with a newline-terminated credential. Git and other programs configure the username independently. The broker accepts an optional bounded input file from the approved agent, verifies its length and hash, and mounts it read-only at a fixed path. It never opens a host path supplied by the agent. Git uses a bare repository populated from the artifact and an owner-fixed HTTPS URL and refspec; Keeper has no Git-specific runtime handler.

Prompt delivery begins after the final authorization check. A dispatched operation can complete after token revocation. If a networked process fails after bytes were relayed, Keeper records an uncertain outcome without retrying.

## HTTPS API requests

The HTTPS action adds an owner-selected method and optional fixed JSON object to the existing Basic and Bearer profiles. Agents reference the existing action ID. The method, canonical JSON, destination, and authentication scheme participate in the binding revision. The desktop shows the method, destination, and configured body during approval. The worker sends the credential in the Authorization header over verified TLS and returns status only. A write without a confirmed response is uncertain. Activity records the method, destination, body digest when present, and decision and outcome.

Legacy HTTPS profiles retain their bodyless GET behavior. The former password-use review switch migrates to the same value for HTTPS requests, local commands, and networked commands.


## Browser sign-ins

An owner configures a fixed HTML form and an exact same-origin HTTPS submission endpoint. An offline WebKit process in a private X display and bounded Linux namespace inspects the form. The process receives the HTML response and the form identifiers, disables website scripts, and returns bounded metadata. Keeper verifies the action and field schema, prepares the request inside the trusted vault worker, and checks authorization immediately before submitting it. Cookies remain in a temporary worker-only session.

A successful result requires the owner-configured HTML marker. Keeper can follow a 302 or 303 once as a GET to the exact configured confirmation URL. It never forwards the original credential in a redirect. An unconfirmed post returns an uncertain outcome. Agent output and Activity contain only structured results and the configured scope. The worker discards the session after each attempt.
