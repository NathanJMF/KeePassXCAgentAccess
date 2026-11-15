"""Read or initialize a credential in a trusted runner's private profile."""

import os
from pathlib import Path
import re
from secrets import token_hex
import stat

from .protocol import ListingError


def credential(path, *, create=False):
    if not path or not Path(path).is_absolute():
        raise ListingError("token_storage")
    target = Path(path)
    if target.name in ("", ".", ".."):
        raise ListingError("token_storage")
    directory = None
    try:
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            temporary = ".token-" + token_hex(16)
            handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            try:
                with os.fdopen(handle, "wb") as stream:
                    stream.write(token_hex(32).encode("ascii") + b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, target.name, src_dir_fd=directory, dst_dir_fd=directory)
                except FileExistsError:
                    pass
            finally:
                os.unlink(temporary, dir_fd=directory)
        with os.fdopen(os.open(target.name, flags, dir_fd=directory), "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != 65):
                raise ValueError
            value = stream.read(66)
        if not re.fullmatch(rb"[0-9a-f]{64}\n", value):
            raise ValueError
        return value[:-1].decode("ascii")
    except (ValueError, OSError):
        raise ListingError("token_storage") from None
    finally:
        if directory is not None:
            os.close(directory)
