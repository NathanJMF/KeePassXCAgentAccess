# Design

## Grant and audit model

A transport binding contains the entry, operation type, exact destination, and transport parameters. Keeper records a revision for these fields. A change to any of them requires a fresh grant. An approved agent can use the same revision repeatedly from any checkout. Keeper applies the owner's existing per-use review settings, lock, pause, and token revocation controls.

The broker checks scope before accepting an upload or preparing an operation. It rechecks the token, binding revision, vault session, and live request immediately before credential delivery. An Activity record identifies the agent, entry, operation, destination, safe operation parameters, approval path, and outcome. The record omits credentials, raw request data, remote output, and browser session data. Keeper persists admission and dispatch state before releasing the credential. The replay key binds the request ID to the requesting token, binding revision, and immutable input digest. A repeated ID can return the same recorded outcome. A repeated ID with different input is rejected. An uncertain push is shown as such and requires a fresh intent to retry.

## Git HTTPS push

The owner sets an exact HTTPS repository and branch on an entry. The agent runner uploads a bounded Git bundle and supplies the commit ID it wants to push. The broker never opens a host path supplied by the agent. A separate preflight process receives the upload without a secret, enforces upload and expanded-object limits, and validates the complete object set and selected commit in a fresh per-job bare repository without alternates or a shared object cache. Preflight does not install refs supplied by the bundle or enable replacement refs. Keeper binds the approved request to the bundle digest and commit ID. Git only sees the private repository and its trusted configuration, and never checks out a worktree.

A supervised Git client uses the exact approved HTTPS destination and a single explicit commit-to-branch refspec. Force, tag, deletion, mirror, submodule, redirect, hook, proxy, and caller configuration paths are disabled. A private credential exchange serves the token for the exact destination and job. The exchange ends with the job and never persists a token. Repository object preparation cannot access that exchange. The agent receives a bounded outcome, branch and commit ID. Keeper discards Git stdout and stderr.

CPU, memory, disk, and wall-clock bounds apply to preflight and push. Keeper also limits concurrent jobs per token and across the broker, caps total staged bytes, and expires abandoned uploads. The supervisor ends Git and its helper processes if their trusted owner exits or the job times out. A completed remote mutation may survive a local cancellation. Keeper records an uncertain result when it cannot determine what the remote accepted.

## API and browser operations

An API binding pins the HTTPS origin, path, method, and allowed input schema. Each allowed write operation has a named purpose and a narrowed payload schema. A typed adapter returns a bounded result. It can return approved response fields only after review of whether those fields can contain the original credential or a new reusable credential. Existing GET actions keep their status-only results.

A browser adapter operates in a Keeper-controlled browser context. An approved binding pins the site, frame origins, identified form or operation, and submission destination. Keeper checks scope and document identity before entering or submitting the credential. The agent receives a typed result through the adapter. The trusted context's cookies, storage, debugger, network traffic, full DOM, screenshots, and clipboard are inaccessible to every agent-controlled tool and connector, including any existing browser or debugging integration. Site scripts that handle a submitted password form part of the approved destination's trust boundary. Additional interactions require separately defined browser operations.
