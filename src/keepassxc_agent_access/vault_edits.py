"""Stage owner edits to an unlocked KDBX 4 database."""

from contextlib import contextmanager
import errno
from fcntl import flock, LOCK_EX, LOCK_NB
from hashlib import file_digest
import os
from pathlib import Path
from secrets import token_bytes, token_hex, token_urlsafe
import stat

from .entry_projection import active_entry, active_group, owner_snapshot
from .protocol import RESPONSE_LIMIT, decode, encode


EDIT_LIMIT = RESPONSE_LIMIT
EDIT_TIMEOUT = 30


class EditError(Exception):
    """An owner edit failed before publishing a new vault revision."""


def file_stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def database_file(path):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as database:
        if not stat.S_ISREG(os.fstat(database.fileno()).st_mode):
            raise EditError("changed")
        yield database


def edit_text(value, *, required=False, limit=4096):
    if not isinstance(value, str) or len(value) > limit or required and not value.strip():
        raise EditError("invalid")
    # Match the XML character range that the KeePass format can preserve.
    if not all(char in "\t\n\r" or 0x20 <= ord(char) <= 0xD7FF
               or 0xE000 <= ord(char) <= 0xFFFD or 0x10000 <= ord(char) <= 0x10FFFF for char in value):
        raise EditError("invalid")
    return value


def _group(vault, identifier, *, allow_root=True):
    if identifier in (None, "") and allow_root:
        return vault.root_group
    group = active_group(vault, identifier)
    if group is None or (group.is_root_group and not allow_root):
        raise EditError("invalid")
    return group


def _entry(vault, identifier):
    entry, _ = active_entry(vault, identifier)
    if entry is None:
        raise EditError("invalid")
    return entry


def _put_entry(vault, request):
    destination = _group(vault, request["parent"])
    title = edit_text(request["title"], required=True)
    username = edit_text(request["username"])
    url = edit_text(request["url"])
    notes = request.get("notes")
    if notes is not None:
        notes = edit_text(notes, limit=EDIT_LIMIT)
    password = request["password"]
    if request.get("generate_password"):
        if request["entry"] is None or password is not None:
            raise EditError("invalid")
        password = token_urlsafe(32)
    if password is not None:
        password = edit_text(password)
    if request["entry"] is None:
        return vault.add_entry(
            destination, title, username, password or "", url=url, notes=notes, force_creation=True,
        ).uuid

    entry = _entry(vault, request["entry"])
    metadata_changed = (entry.title or "", entry.username or "", entry.url or "") != (title, username, url)
    password_changed = password is not None and password != (entry.password or "")
    notes_changed = notes is not None and notes != (entry.notes or "")
    if metadata_changed or password_changed or notes_changed:
        entry.save_history()
        entry.title, entry.username, entry.url = title, username, url
        if password is not None:
            entry.password = password
        if notes_changed:
            entry.notes = notes
        entry.touch(modify=True)
    if entry.group.uuid != destination.uuid:
        vault.move_entry(entry, destination)
        entry.touch(modify=True)
    return entry.uuid


def _put_group(vault, request):
    destination = _group(vault, request["parent"])
    name = edit_text(request["name"], required=True)
    if request["group"] is None:
        return vault.add_group(destination, name).uuid

    group = _group(vault, request["group"], allow_root=False)
    ancestor = destination
    while ancestor is not None:
        if ancestor.uuid == group.uuid:
            raise EditError("cycle")
        ancestor = ancestor.parentgroup
    if group.parentgroup.uuid != destination.uuid:
        vault.move_group(group, destination)
    group.name = name
    group.touch(modify=True)
    return group.uuid


def _delete(vault, item, delete):
    attachments = {attachment.id for attachment in vault.find_attachments(element=item, history=True)}
    identifier = item.uuid
    delete(item)
    if attachments:
        retained = {attachment.id for attachment in vault.find_attachments(history=True)}
        for binary in sorted(attachments - retained, reverse=True):
            vault.delete_binary(binary)
    return identifier


def _apply(vault, request):
    change = request["change"]
    if change == "put_entry":
        return _put_entry(vault, request)
    if change == "put_group":
        return _put_group(vault, request)
    if change == "delete_entry":
        return _delete(vault, _entry(vault, request["entry"]), vault.delete_entry)
    if change == "delete_group":
        return _delete(vault, _group(vault, request["group"], allow_root=False), vault.delete_group)
    if change in ("remove_entry", "remove_group"):
        if vault.tree.findtext("Meta/RecycleBinEnabled") != "True":
            raise EditError("recycle_disabled")
        if change == "remove_entry":
            item = _entry(vault, request["entry"])
            vault.trash_entry(item)
        else:
            item = _group(vault, request["group"], allow_root=False)
            vault.trash_group(item)
        return item.uuid
    raise EditError("invalid")


def _renew_encryption(vault):
    header = vault.kdbx.header.value.dynamic_header
    inner = vault.kdbx.body.payload.inner_header
    for field in (header.master_seed, header.encryption_iv, inner.protected_stream_key):
        field.data = token_bytes(len(field.data))
    # PyKeePass otherwise writes its original cached header bytes.
    vault.kdbx.header.pop("data")


def stage_edit(vault, path, stamp, request, ready, may_commit):
    if vault.version not in ((4, 0), (4, 1)):
        raise EditError("version")
    try:
        with database_file(path) as source:
            info = os.fstat(source.fileno())
            if file_stamp(info) != stamp:
                raise EditError("changed")
            if info.st_uid != os.geteuid() or info.st_nlink != 1 or not info.st_mode & stat.S_IWUSR:
                raise EditError("read_only")
            try:
                flock(source.fileno(), LOCK_EX | LOCK_NB)
            except BlockingIOError:
                raise EditError("busy") from None
            key = vault.transformed_key
            try:
                candidate = type(vault)(source, transformed_key=key)
            except Exception:
                raise EditError("changed") from None
            if file_stamp(os.fstat(source.fileno())) != stamp:
                raise EditError("changed")
            try:
                identifier = str(_apply(candidate, request))
            except (KeyError, TypeError, ValueError, AttributeError):
                raise EditError("invalid") from None
            snapshot = decode(owner_snapshot(candidate))
            if "error" in snapshot:
                raise EditError("too_large")
            _renew_encryption(candidate)
            return _publish(candidate, key, source, info, path, snapshot, identifier, ready, may_commit)
    except FileNotFoundError:
        raise EditError("changed") from None


def _staging_file(directory, name):
    try:
        return os.open(".", os.O_RDWR | os.O_TMPFILE, 0o600, dir_fd=directory), True
    except OSError as error:
        if error.errno not in (errno.EOPNOTSUPP, errno.EINVAL, errno.EISDIR, errno.ENOENT):
            raise
    return os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory), False


def _publish(candidate, key, source, info, path, snapshot, identifier, ready, may_commit):
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = None
    try:
        directory_info = os.fstat(directory)
        os.fsync(directory)
        staging_name = ".keeper-" + token_hex(16)
        handle, anonymous = _staging_file(directory, staging_name)
        if not anonymous:
            temporary = staging_name
        with os.fdopen(handle, "w+b") as staged:
            candidate.save(staged, transformed_key=key)
            staged.flush()
            # Reopen the encrypted candidate before publishing it. Keep its freshly
            # parsed state when the original path is replaced.
            staged.seek(0)
            candidate = type(candidate)(staged, transformed_key=key)
            staged.seek(0)
            digest = file_digest(staged, "sha256").hexdigest()
            response = {"id": identifier, "fingerprint": digest, "snapshot": snapshot, "durable": True}
            if len(encode(response)) > RESPONSE_LIMIT:
                raise EditError("too_large")

            if os.fstat(staged.fileno()).st_gid != info.st_gid:
                os.fchown(staged.fileno(), -1, info.st_gid)
            os.fchmod(staged.fileno(), stat.S_IMODE(info.st_mode))
            source_attrs = set(os.listxattr(source.fileno()))
            for attribute in set(os.listxattr(staged.fileno())) - source_attrs:
                os.removexattr(staged.fileno(), attribute)
            for attribute in source_attrs:
                os.setxattr(staged.fileno(), attribute, os.getxattr(source.fileno(), attribute))
            os.fsync(staged.fileno())

            ready()
            if not may_commit():
                raise EditError("cancelled")

            if not os.path.samestat(directory_info, path.parent.stat(follow_symlinks=False)):
                raise EditError("changed")
            if anonymous:
                os.link(f"/proc/self/fd/{staged.fileno()}", staging_name,
                        dst_dir_fd=directory, follow_symlinks=True)
                temporary = staging_name
            expected = file_stamp(info)
            if (file_stamp(os.stat(path.name, dir_fd=directory, follow_symlinks=False)) != expected
                    or file_stamp(os.fstat(source.fileno())) != expected):
                raise EditError("changed")
            os.replace(staging_name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            temporary = None
            stamp = file_stamp(os.fstat(staged.fileno()))
            try:
                os.fsync(directory)
            except OSError:
                # The rename happened. Report an uncertain disk flush without inviting a duplicate save.
                response["durable"] = False
            return candidate, stamp, encode(response)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except OSError:
                pass
        os.close(directory)
