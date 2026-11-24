"""Install the per-user GNOME launcher and Keeper skill from the trusted checkout."""

import os
from pathlib import Path
from shlex import quote
import sys
import stat
import tempfile

from gi.repository import GLib

from . import APP_TITLE


DESKTOP_ID = "io.github.keepassxcagentaccess.Tray.desktop"
SKILL_PATH = Path("keepassxc-agent-access") / "SKILL.md"


def _exec_argument(value):
    if not value.isprintable():
        raise ValueError("The installation path contains unsupported characters.")
    escaped = "".join("\\" + char if char in '\\"$`' else char for char in value)
    return '"' + escaped.replace("\\", "\\\\").replace("%", "%%") + '"'


def skill_destination():
    documents = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOCUMENTS)
    documents = Path(documents) if documents else Path.home() / "Documents"
    return documents / "Skills" / "Keeper" / SKILL_PATH.name


def antigravity_skill_destination():
    config = Path.home() / ".gemini" / "config"
    if config.is_symlink() or not config.is_dir():
        return None
    return config / "skills" / "keeper" / "SKILL.md"


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


def desktop_contents(executable):
    return "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        f"Name={APP_TITLE}",
        "Comment=Manage agent access to your KeePass vault",
        "Icon=dialog-password",
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
    contents = desktop_contents(executable)
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
