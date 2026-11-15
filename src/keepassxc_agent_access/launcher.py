"""Install the per-user GNOME launcher from the current trusted checkout."""

import os
from pathlib import Path
import sys
import tempfile


DESKTOP_ID = "io.github.keepassxcagentaccess.Tray.desktop"


def _exec_argument(value):
    if not value.isprintable():
        raise ValueError("The installation path contains unsupported characters.")
    escaped = "".join("\\" + char if char in '\\"$`' else char for char in value)
    return '"' + escaped.replace("\\", "\\\\").replace("%", "%%") + '"'


def install(executable, data_directory):
    executable = Path(executable).resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("The tray executable is unavailable.")
    directory = Path(data_directory) / "applications"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / DESKTOP_ID
    contents = "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        "Name=KeePassXC Agent Access",
        "Comment=Manage agent access to your KeePass vault",
        "Icon=dialog-password",
        f"Exec={_exec_argument(str(executable))} --show-window",
        "Terminal=false",
        "Categories=Utility;Security;",
        "",
    ])
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(contents)
            file.flush()
            os.fchmod(file.fileno(), 0o644)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    return path


if __name__ == "__main__":
    data = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share"
    print(install(sys.argv[1], data))
