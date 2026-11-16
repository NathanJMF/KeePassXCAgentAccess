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

## Additional profiles

Future API delivery needs owner-approved methods, destinations, and input and result schemas. Future browser delivery needs private session state protected from all agent-controlled tools and connectors. It needs bound origins and verified navigation and form destinations. Raw remote output can contain credentials supplied by the request or new credentials created in the response.
