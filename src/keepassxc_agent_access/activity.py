"""Local structured authorization history."""

from contextlib import contextmanager
from dataclasses import dataclass
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

    @classmethod
    def parse(cls, payload):
        if not isinstance(payload, dict) or set(payload) - {"model", "chat", "chat_id"}:
            raise ValueError
        return cls(**{key: label(value) for key, value in payload.items()})


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
    destination TEXT,
    decision TEXT,
    outcome TEXT NOT NULL,
    status INTEGER
);
"""


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
            if "entry" not in {column["name"] for column in db.execute("PRAGMA table_info(activity)")}:
                db.execute("ALTER TABLE activity ADD COLUMN entry TEXT")
            db.execute(
                """UPDATE activity SET completed=?, outcome=CASE
                WHEN outcome='Dispatching' THEN 'Interrupted · outcome unknown' ELSE 'Revoked' END
                WHERE completed IS NULL""",
                (time(),),
            )
        self.prune(days)

    def prune(self, days):
        with self.connection() as db:
            db.execute("DELETE FROM activity WHERE requested < ? AND completed IS NOT NULL",
                       (time() - days * 86400,))
            db.execute("DELETE FROM sessions WHERE id NOT IN (SELECT session FROM activity)")

    def begin(self, uid, context, action, destination, entry=None):
        with self.connection() as db:
            chat_id = context.chat_id or ""
            db.execute("INSERT OR IGNORE INTO sessions(uid, chat_id) VALUES (?, ?)", (uid, chat_id))
            session = db.execute(
                "SELECT id FROM sessions WHERE uid=? AND chat_id=?", (uid, chat_id),
            ).fetchone()[0]
            cursor = db.execute(
                """INSERT INTO activity(session, requested, model, chat, action, destination, entry, outcome)
                VALUES(?, ?, ?, ?, ?, ?, ?, 'Pending')""",
                (session, time(), context.model, context.chat, action, destination, entry),
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

    def finish(self, event, outcome, status=None):
        now = time()
        with self.connection() as db:
            db.execute(
                """UPDATE activity SET decided=coalesce(decided, ?), completed=?, outcome=?, status=?
                WHERE id=?""", (now, now, outcome, status, event),
            )

    def rows(self, *, model="", chat="", action="", outcome=""):
        with self.connection() as db:
            return [dict(row) for row in db.execute(
                """SELECT activity.*, sessions.uid, sessions.chat_id FROM activity
                JOIN sessions ON activity.session=sessions.id
                WHERE instr(lower(coalesce(model,'')), lower(?)) > 0
                  AND instr(lower(coalesce(chat,'')), lower(?)) > 0
                  AND instr(lower(action), lower(?)) > 0 AND instr(lower(outcome), lower(?)) > 0
                ORDER BY requested DESC, activity.id DESC LIMIT 1000""",
                (model, chat, action, outcome),
            )]
