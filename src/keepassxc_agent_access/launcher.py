"""Install the per-user GNOME launcher and Keeper skill from the trusted checkout."""

import os
from pathlib import Path
import sys
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


def _install_skill():
    destination = skill_destination()
    if destination.exists() or destination.is_symlink():
        return
    source = Path(__file__).resolve().parents[2] / "skills" / SKILL_PATH
    contents = source.read_bytes()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(contents)
            file.flush()
            os.fchmod(file.fileno(), 0o644)
            # Publish the complete file without replacing an existing skill.
            os.link(temporary, destination)
        except FileExistsError:
            pass
        finally:
            temporary.unlink(missing_ok=True)


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
