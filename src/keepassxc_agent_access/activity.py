"""Local structured authorization history."""

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import stat
from time import time

from .access_settings import label


class ActivityError(Exception):
    """History could not be stored safely."""


@dataclass(frozen=True)
class Attribution:
    model: str | None = None
    chat: str | None = None
    chat_id: str | None = None
    note: str | None = None

    @classmethod
    def parse(cls, payload):
        if not isinstance(payload, dict) or set(payload) - {"model", "chat", "chat_id", "note"}:
            raise ValueError
        return cls(**{key: label(value, limit=180 if key == "note" else 160) for key, value in payload.items()})


def folder_label(parts):
    return " / ".join(part or "(Untitled folder)" for part in parts) or "Root"


def entry_label(title):
    return title or "(Untitled entry)"


def entry_target_labels(entries, identifier):
    matches = [row for row in entries if row["id"] == identifier]
    if len(matches) != 1:
        return None, None
    entry = matches[0]
    path, title = entry.get("group_path"), entry.get("title")
    if not isinstance(path, (list, tuple)) or not all(isinstance(part, str) for part in path):
        return None, None
    return folder_label(path), entry_label(title) if isinstance(title, str) else None


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    uid INTEGER NOT NULL,
    chat_id TEXT NOT NULL,
    UNIQUE(uid, chat_id)
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY,
    session INTEGER NOT NULL REFERENCES sessions(id),
    requested REAL NOT NULL,
    decided REAL,
    completed REAL,
    model TEXT,
    chat TEXT,
    action TEXT NOT NULL,
    entry TEXT,
    group_id TEXT,
    edit_request_id TEXT,
    workflow_id TEXT,
    workflow_step TEXT,
    folder TEXT,
    entry_title TEXT,
    destination TEXT,
    note TEXT,
    decision TEXT,
    outcome TEXT NOT NULL,
    status INTEGER
);
CREATE INDEX IF NOT EXISTS activity_requested ON activity(requested DESC, id DESC);
CREATE TABLE IF NOT EXISTS write_receipts (
    token TEXT NOT NULL,
    id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    vault TEXT NOT NULL,
    entry TEXT NOT NULL,
    revision TEXT NOT NULL,
    digest TEXT NOT NULL,
    stage TEXT NOT NULL,
    http_status INTEGER,
    captured_id INTEGER,
    captured_value TEXT,
    secondary_entry TEXT,
    PRIMARY KEY (token, id)
);
CREATE TABLE IF NOT EXISTS reviewed_workflows (
    token TEXT NOT NULL,
    id TEXT NOT NULL,
    digest TEXT NOT NULL,
    PRIMARY KEY (token, id)
);
"""

WRITE_RECEIPTS_PER_TOKEN = 512


class ActivityStore:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def connection(self):
        connection = None
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            with os.fdopen(os.open(self.path, flags, 0o600), "wb") as file:
                info = os.fstat(file.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise ActivityError()
            connection = sqlite3.connect(self.path, timeout=.25)
            connection.row_factory = sqlite3.Row
            with connection:
                yield connection
        except (OSError, sqlite3.Error):
            raise ActivityError() from None
        finally:
            if connection is not None:
                connection.close()

    def recover(self, days):
        with self.connection() as db:
            db.executescript(SCHEMA)
            columns = {column["name"] for column in db.execute("PRAGMA table_info(activity)")}
            for name in ("entry", "vault", "vault_id", "token", "agent", "project", "scope", "folder", "entry_title",
                         "group_id", "edit_request_id", "workflow_id", "workflow_step", "note"):
                if name not in columns:
                    db.execute(f"ALTER TABLE activity ADD COLUMN {name} TEXT")
            receipt_columns = {column["name"] for column in db.execute("PRAGMA table_info(write_receipts)")}
            if "captured_id" not in receipt_columns:
                db.execute("ALTER TABLE write_receipts ADD COLUMN captured_id INTEGER")
            if "captured_value" not in receipt_columns:
                db.execute("ALTER TABLE write_receipts ADD COLUMN captured_value TEXT")
            if "secondary_entry" not in receipt_columns:
                db.execute("ALTER TABLE write_receipts ADD COLUMN secondary_entry TEXT")
            db.execute(
                """UPDATE activity SET completed=?, outcome=CASE
                WHEN outcome='Dispatching' THEN 'Interrupted · outcome unknown' ELSE 'Revoked' END
                WHERE completed IS NULL""",
                (time(),),
            )
            db.execute("UPDATE write_receipts SET stage='not_sent' WHERE stage='pending'")
            db.execute("UPDATE write_receipts SET stage='uncertain' WHERE stage='dispatching'")
        self.prune(days)

    def prune(self, days):
        with self.connection() as db:
            db.execute("DELETE FROM activity WHERE requested < ? AND completed IS NOT NULL",
                       (time() - days * 86400,))
            db.execute("DELETE FROM sessions WHERE id NOT IN (SELECT session FROM activity)")

    def begin(self, uid, context, action, destination, entry=None, *, vault=None, vault_id=None,
              token=None, agent=None, project=None, scope=None, folder=None, entry_title=None,
              group_id=None, edit_request_id=None, workflow_id=None, workflow_step=None):
        with self.connection() as db:
            chat_id = context.chat_id or ""
            db.execute("INSERT OR IGNORE INTO sessions(uid, chat_id) VALUES (?, ?)", (uid, chat_id))
            session = db.execute(
                "SELECT id FROM sessions WHERE uid=? AND chat_id=?", (uid, chat_id),
            ).fetchone()[0]
            cursor = db.execute(
                """INSERT INTO activity(session, requested, model, chat, action, destination, entry,
                                         vault, vault_id, token, agent, project, scope, folder, entry_title,
                                         group_id, edit_request_id, workflow_id, workflow_step, note, outcome)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending')""",
                (session, time(), context.model, context.chat, action, destination, entry,
                 vault, vault_id, token, agent, project, scope, folder, entry_title, group_id, edit_request_id,
                 workflow_id, workflow_step, context.note),
            )
            return cursor.lastrowid

    def authorize(self, event, source):
        with self.connection() as db:
            changed = db.execute(
                "UPDATE activity SET decided=?, decision=?, outcome='Authorized' WHERE id=? AND outcome='Pending'",
                (time(), source, event),
            ).rowcount
            if changed != 1:
                raise ActivityError()

    def dispatched(self, event):
        with self.connection() as db:
            changed = db.execute(
                "UPDATE activity SET outcome='Dispatching' WHERE id=? AND outcome='Authorized'", (event,),
            ).rowcount
            if changed != 1:
                raise ActivityError()

    def finish(self, event, outcome, status=None, *, entry=None, group_id=None, folder=None, entry_title=None):
        now = time()
        with self.connection() as db:
            db.execute(
                """UPDATE activity SET decided=coalesce(decided, ?), completed=?, outcome=?, status=?,
                    entry=coalesce(entry, ?), group_id=coalesce(?, group_id), folder=coalesce(?, folder),
                    entry_title=coalesce(?, entry_title) WHERE id=?""",
                (now, now, outcome, status, entry, group_id, folder, entry_title, event),
            )

    def claim_write(self, token, identifier, generation, vault, entry, revision, digest, *, secondary_entry=None):
        with self.connection() as db:
            previous = db.execute("SELECT digest, stage FROM write_receipts WHERE token=? AND id=?",
                                  (token, identifier)).fetchone()
            if previous is not None:
                if previous["digest"] != digest:
                    return "receipt_conflict"
                if previous["stage"] not in ("failed", "not_sent"):
                    return "receipt_exists"
                db.execute("""UPDATE write_receipts
                              SET generation=?, vault=?, entry=?, revision=?, secondary_entry=?,
                                  stage='pending', http_status=NULL, captured_id=NULL, captured_value=NULL
                              WHERE token=? AND id=?""",
                           (generation, vault, entry, revision, secondary_entry, token, identifier))
                return None
            count = db.execute("SELECT count(*) FROM write_receipts WHERE token=?", (token,)).fetchone()[0]
            if count >= WRITE_RECEIPTS_PER_TOKEN:
                return "receipt_limit"
            db.execute("""INSERT INTO write_receipts(token, id, generation, vault, entry, revision, digest,
                                                     secondary_entry, stage)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
                       (token, identifier, generation, vault, entry, revision, digest, secondary_entry))
            return None

    def write_receipt(self, token, identifier):
        with self.connection() as db:
            return db.execute("SELECT * FROM write_receipts WHERE token=? AND id=?", (token, identifier)).fetchone()

    def has_provision(self, token, vault, entry):
        with self.connection() as db:
            return db.execute("""SELECT 1 FROM write_receipts
                                 WHERE token=? AND vault=? AND secondary_entry=? LIMIT 1""",
                              (token, vault, entry)).fetchone() is not None

    def claim_workflow(self, token, identifier, digest):
        with self.connection() as db:
            row = db.execute("SELECT digest FROM reviewed_workflows WHERE token=? AND id=?", (token, identifier)).fetchone()
            if row is not None:
                return None if row["digest"] == digest else "receipt_conflict"
            count = db.execute("SELECT count(*) FROM reviewed_workflows WHERE token=?", (token,)).fetchone()[0]
            if count >= WRITE_RECEIPTS_PER_TOKEN:
                return "receipt_limit"
            db.execute("INSERT INTO reviewed_workflows(token, id, digest) VALUES(?, ?, ?)",
                       (token, identifier, digest))
            return None

    def advance_write(self, token, identifier, expected, stage, status=None, *, captured_id=None):
        legacy_id = captured_id if type(captured_id) is int else None
        serialized = json.dumps(captured_id, ensure_ascii=True, allow_nan=False) if captured_id is not None else None
        with self.connection() as db:
            changed = db.execute("""UPDATE write_receipts SET stage=?, http_status=?, captured_id=?, captured_value=?
                                    WHERE token=? AND id=? AND stage=?""",
                                 (stage, status, legacy_id, serialized, token, identifier, expected)).rowcount
            if changed != 1:
                raise ActivityError()

    def rows(self, *, model="", chat="", action="", outcome="", vault="", agent="", limit=1000):
        with self.connection() as db:
            return [dict(row) for row in db.execute(
                """SELECT activity.*, sessions.uid, sessions.chat_id FROM activity
                JOIN sessions ON activity.session=sessions.id
                WHERE instr(lower(coalesce(model,'')), lower(?)) > 0
                  AND instr(lower(coalesce(chat,'')), lower(?)) > 0
                  AND instr(lower(action), lower(?)) > 0 AND instr(lower(outcome), lower(?)) > 0
                  AND instr(lower(coalesce(vault,'') || ' ' || coalesce(vault_id,'')), lower(?)) > 0
                  AND instr(lower(coalesce(agent,'')), lower(?)) > 0
                ORDER BY requested DESC, activity.id DESC LIMIT ?""",
                (model, chat, action, outcome, vault, agent, -1 if limit is None else limit),
            )]
