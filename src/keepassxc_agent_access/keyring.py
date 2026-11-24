"""Store credentials in the owner's Linux Secret Service."""

import gi

gi.require_version("Secret", "1")
from gi.repository import GLib, Secret


class KeyringError(Exception):
    """A safe, user-facing keyring error."""


class SystemKeyring:
    def __init__(self):
        self.schema = Secret.Schema.new(
            "io.github.keepassxcagentaccess.Vault",
            Secret.SchemaFlags.NONE,
            {"item-id": Secret.SchemaAttributeType.STRING},
        )

    def remember(self, item_id, password, cancellable=None):
        try:
            saved = Secret.password_store_sync(
                self.schema, {"item-id": item_id}, Secret.COLLECTION_DEFAULT,
                "KeePassXC Agent Access vault password", password, cancellable,
            )
        except GLib.Error:
            saved = False
        if not saved:
            raise KeyringError("The password was not saved. Retry or finish without remembering it.")

    def retrieve(self, item_id, cancellable=None):
        try:
            password = Secret.password_lookup_sync(self.schema, {"item-id": item_id}, cancellable)
        except GLib.Error:
            password = None
        if password is None:
            raise KeyringError("The saved password is unavailable. Retry or enter it manually.")
        return password

    def remove(self, item_id):
        try:
            service = Secret.Service.get_sync(Secret.ServiceFlags.NONE, None)
            items = service.search_sync(self.schema, {"item-id": item_id}, Secret.SearchFlags.ALL, None)
            for item in items:
                if not item.delete_sync(None):
                    raise KeyringError("Keyring cleanup is pending.")
        except GLib.Error:
            raise KeyringError("Keyring cleanup is pending.") from None

    def remove_all(self):
        try:
            service = Secret.Service.get_sync(Secret.ServiceFlags.NONE, None)
            items = service.search_sync(self.schema, {}, Secret.SearchFlags.ALL, None)
            removed = 0
            for item in items:
                if not item.delete_sync(None):
                    raise KeyringError("Keyring cleanup is pending.")
                removed += 1
            return removed
        except GLib.Error:
            raise KeyringError("Keyring cleanup is pending.") from None
