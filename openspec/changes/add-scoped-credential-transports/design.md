# Design

## Reference and grant model

An agent identifies a vault, entry, and approved action. For a command, it also supplies the argument vector to run. The owner defines which program and inputs are allowed and how it receives the secret. The broker rejects commands outside the approved scope. The reusable interface applies to delivery channels and isolation policies. Applications use those policies through configuration.

A grant pins the action revision. Changing the consumer, arguments, transport policy, destination, or the pinned executable requires approval for a new grant. Standard lock, pause, and one-use review settings apply. Repeated uses within an active grant can run without further owner input when per-use review is off. Activity records the action and its outcome every time.

## First profile

The consumer is an owner-approved system executable with an exact argument vector and a pinned binary digest. Keeper launches it in a private Linux sandbox with a read-only system runtime, no host working directories or session sockets, bounded temporary storage, an empty environment apart from its private home, and a separate network namespace with socket creation disabled. The operating system's trusted libraries and runtime are part of this profile. The process scope limits memory, tasks, and CPU. Keeper rejects the request if the sandbox cannot start.

Keeper waits for sandbox readiness and rechecks authorization before delivering the entry's password as UTF-8 bytes on stdin followed by EOF. The secret never appears in argv or the command environment. The broker generates a success or failure result. It discards stdout and stderr and confines process lifetime to the sandbox and its supervisor.

## Additional profiles

Future networked CLI delivery requires a trusted process with reusable input framing, destination enforcement, and bounded results. Git should exercise that profile with a repository-scoped credential, the usual command interface, and an auditable result. A command that can read a secret can try to forward it, so each delivery profile needs explicit boundaries for network, configuration, workspace access, and output.

Future API delivery needs owner-approved methods, destinations, and input and result schemas. Future browser delivery needs private session state protected from all agent-controlled tools and connectors. It needs bound origins and verified navigation and form destinations. Raw remote output can contain credentials supplied by the request or new credentials created in the response.
