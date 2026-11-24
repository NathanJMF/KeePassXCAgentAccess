"""Install the per-user GNOME launcher and Keeper skill from the trusted checkout."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from shlex import quote
import sys
import stat
import tempfile

from gi.repository import GLib

from . import APP_TITLE


DESKTOP_ID = "io.github.keepassxcagentaccess.Tray.desktop"
SKILL_PATH = Path("keepassxc-agent-access") / "SKILL.md"
_ICON_LINE = re.compile(r"^Icon=(.+)$", re.MULTILINE)


def _exec_argument(value):
    if not value.isprintable():
        raise ValueError("The installation path contains unsupported characters.")
    escaped = "".join("\\" + char if char in '\\"$`' else char for char in value)
    return '"' + escaped.replace("\\", "\\\\").replace("%", "%%") + '"'


def skill_destination():
    documents = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOCUMENTS)
    documents = Path(documents) if documents else Path.home() / "Documents"
    return documents / "Skills" / "Keeper" / SKILL_PATH.name


@dataclass(frozen=True)
class AgentClient:
    key: str
    label: str
    skill_path: Path
    mcp_path: Path | None
    mcp_format: str


def _non_symlink_dir(path):
    return not path.is_symlink() and path.is_dir()


def antigravity_skill_destination():
    config = Path.home() / ".gemini" / "config"
    if not _non_symlink_dir(config):
        return None
    return config / "skills" / "keeper" / "SKILL.md"


def antigravity_mcp_config_destination():
    config = Path.home() / ".gemini" / "config"
    if not _non_symlink_dir(config):
        return None
    return config / "mcp_config.json"


def antigravity_mcp_entry(command):
    return {"command": str(command), "args": []}


def antigravity_mcp_snippet(command):
    return json.dumps({"mcpServers": {"keeper": antigravity_mcp_entry(command)}}, indent=2)


def codex_skill_destination():
    codex = Path.home() / ".codex"
    if not _non_symlink_dir(codex):
        return None
    return codex / "skills" / "keeper" / "SKILL.md"


def codex_mcp_config_destination():
    codex = Path.home() / ".codex"
    if not _non_symlink_dir(codex):
        return None
    return codex / "config.toml"


def codex_mcp_snippet(command):
    return f"[mcp_servers.keeper]\ncommand = {json.dumps(str(command))}\nargs = []"


def codex_mcp_entry(command):
    return f"# BEGIN KEEPER MCP\n{codex_mcp_snippet(command)}\n# END KEEPER MCP\n"


def claude_skill_destination():
    claude = Path.home() / ".claude"
    if not _non_symlink_dir(claude):
        return None
    return claude / "skills" / "keeper" / "SKILL.md"


def claude_mcp_config_destination():
    claude = Path.home() / ".claude"
    if not _non_symlink_dir(claude):
        return None
    return Path.home() / ".claude.json"


def detected_agent_clients():
    clients = []
    if (ag_skill := antigravity_skill_destination()) is not None:
        clients.append(AgentClient("antigravity", "Antigravity", ag_skill, antigravity_mcp_config_destination(), "json"))
    if (cx_skill := codex_skill_destination()) is not None:
        clients.append(AgentClient("codex", "Codex", cx_skill, codex_mcp_config_destination(), "toml"))
    if (cc_skill := claude_skill_destination()) is not None:
        clients.append(AgentClient("claude", "Claude Code", cc_skill, claude_mcp_config_destination(), "json"))
    return clients


def desktop_icon(contents):
    if isinstance(contents, str) and "[Desktop Entry]" in contents:
        match = _ICON_LINE.search(contents)
        if match:
            value = match.group(1).strip()
            if value and value.isprintable() and "\n" not in value and "\r" not in value:
                return value
    return "dialog-password"


def normalize_desktop_icon(contents):
    icon = desktop_icon(contents)
    if icon == "dialog-password":
        return contents
    return _ICON_LINE.sub("Icon=dialog-password", contents, count=1)


def skill_launcher_contents(executable):
    """Bind the skill helper to its trusted installation, without shell expansion."""
    executable = str(Path(executable).absolute())
    if not executable.isprintable():
        raise ValueError("The installation path contains unsupported characters.")
    return f'#!/bin/sh\nset -eu\nexec {quote(executable)} "$@"\n'.encode()


def _install_skill_file(destination, contents, mode):
    if destination.exists() or destination.is_symlink():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(contents)
            file.flush()
            os.fchmod(file.fileno(), mode)
            # Publish the complete file without replacing an existing skill/helper.
            os.link(temporary, destination)
        except FileExistsError:
            pass
        finally:
            temporary.unlink(missing_ok=True)


def _install_skill():
    destination = skill_destination()
    checkout = Path(__file__).resolve().parents[2]
    source = checkout / "skills" / SKILL_PATH
    helper = destination.with_name("keeper-agent")
    helper_contents = skill_launcher_contents(checkout / "keeper-agent")
    if helper.exists() or helper.is_symlink():
        info = helper.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or not info.st_mode & 0o100
                or helper.read_bytes() != helper_contents):
            raise ValueError("Keeper found a customized skill helper. Move keeper-agent beside the skill aside before installing.")
    _install_skill_file(destination, source.read_bytes(), 0o644)
    _install_skill_file(helper, helper_contents, 0o755)


def desktop_contents(executable, *, icon="dialog-password"):
    if not isinstance(icon, str) or not icon.strip() or not icon.isprintable() or "\n" in icon or "\r" in icon:
        icon = "dialog-password"
    return "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        f"Name={APP_TITLE}",
        "Comment=Manage agent access to your KeePass vault",
        f"Icon={icon}",
        f"Exec={_exec_argument(str(executable))} --show-window",
        "Terminal=false",
        "Categories=Utility;Security;",
        "",
    ])


def install(executable, data_directory):
    executable = Path(executable).resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("The tray executable is unavailable.")
    directory = Path(data_directory) / "applications"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / DESKTOP_ID
    icon = "dialog-password"
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    if info is not None and stat.S_ISREG(info.st_mode):
        icon = desktop_icon(path.read_text(encoding="utf-8", errors="ignore"))
    contents = desktop_contents(executable, icon=icon)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(contents)
            file.flush()
            os.fchmod(file.fileno(), 0o644)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    _install_skill()
    return path


if __name__ == "__main__":
    data = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share"
    print(install(sys.argv[1], data))
