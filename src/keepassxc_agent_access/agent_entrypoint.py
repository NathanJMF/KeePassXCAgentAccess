"""Use the installed isolated Keeper CLI with a separate profile for each task."""

import argparse
import json
import os
import pwd
from pathlib import Path
import re
import stat
import subprocess
from uuid import uuid4

from .isolated_runner import launch, owned, subordinate_ids


def text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 160 or not value.isprintable():
        raise ValueError("Use a readable identity and project, each at most 160 characters.")
    return value.strip()


def installed_home():
    # Caller environment is not a trusted selector for existing token storage.
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def session_base(state=None):
    state = installed_home() / ".local/state" if state is None else Path(state)
    base = state / "keeper-agent-sessions"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned(base, private=True)
    return base


def create_session(identity, project, model=None, chat=None, *, state=None):
    metadata = {"identity": text(identity), "project": text(project)}
    for key, value in (("model", model), ("chat", chat)):
        if value is not None:
            metadata[key] = text(value)
    base = session_base(state)
    name = "agent-" + uuid4().hex
    anchor = base / name
    anchor.mkdir(mode=0o700)
    # Keep registration metadata outside the anchor briefly used to provision
    # its subordinate-owned profile. The parent stays owner-only.
    descriptor = os.open(base / f"{name}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(metadata, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    return {"profile": name, **metadata}


def session(name, *, state=None):
    if not re.fullmatch(r"agent-[a-f0-9]{32}", name):
        raise ValueError("Use the profile returned by keeper-agent begin for this task.")
    base = session_base(state)
    descriptor = os.open(base / f"{name}.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > 4096):
            raise ValueError("The task registration is unavailable or unsafe.")
        metadata = json.load(stream)
    if (not isinstance(metadata, dict) or not {"identity", "project"} <= metadata.keys()
            or metadata.keys() - {"identity", "project", "model", "chat"}):
        raise ValueError("The task registration is invalid.")
    metadata = {key: text(value) for key, value in metadata.items()}
    anchor = base / name
    owned(anchor, private=False)
    return anchor, metadata


def main(argv=None, *, _state=None, _runtime=None, _checkout=None):
    # These injected paths are for trusted in-process integration fixtures only.
    # There is deliberately no CLI or environment override for the live broker.
    runtime = Path(f"/run/user/{os.getuid()}") if _runtime is None else Path(_runtime)
    checkout = Path(__file__).resolve().parents[2] if _checkout is None else Path(_checkout)
    parser = argparse.ArgumentParser(description=__doc__, prog="keeper-agent")
    parser.add_argument("--profile", help="The task profile returned by begin")
    parser.add_argument("--note", help="Short audit note without credentials")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    if not options.command:
        parser.error("Run begin --identity NAME --project PROJECT, or use --profile PROFILE followed by a Keeper command.")
    try:
        if options.command[0] == "begin":
            begin = argparse.ArgumentParser(prog="keeper-agent begin")
            begin.add_argument("--identity", required=True)
            begin.add_argument("--project", required=True)
            begin.add_argument("--model")
            begin.add_argument("--chat")
            args = begin.parse_args(options.command[1:])
            print(json.dumps(create_session(args.identity, args.project, args.model, args.chat, state=_state)))
            return 0
        if not options.profile:
            raise ValueError("Start this task with keeper-agent begin and use its returned profile.")
        anchor, metadata = session(options.profile, state=_state)
        attribution = {f"KEEPASSXC_AGENT_{key.upper()}": value for key, value in metadata.items()}
        if options.note is not None:
            attribution["KEEPASSXC_AGENT_NOTE"] = text(options.note)
        uid, gid = subordinate_ids()
        owned(runtime, private=True)
        return launch(runtime / "keeper-scoped-runner", checkout, options.profile, uid, gid,
                      cli=options.command, anchor=anchor, attribution=attribution)
    except ValueError as error:
        parser.exit(1, f"Keeper: {error}\n")
    except (KeyError, OSError, subprocess.CalledProcessError):
        parser.exit(1, "Keeper could not connect this task. Open Keeper with agent support installed, or run begin for a fresh task profile.\n")


if __name__ == "__main__":
    raise SystemExit(main())
