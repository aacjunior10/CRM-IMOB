import os
import re
import sqlite3
from pathlib import Path


DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
SQLITE_DATABASE = Path(os.environ.get("CRM_DATABASE", Path(__file__).resolve().parent / "casa_norte.sqlite3"))

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None


class HybridRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


class Cursor:
    def __init__(self, cursor, lastrowid=None):
        self._cursor = cursor
        self.lastrowid = lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @staticmethod
    def _row(row):
        return HybridRow(row) if isinstance(row, dict) else row

    def fetchone(self):
        return self._row(self._cursor.fetchone())

    def fetchall(self):
        return [self._row(row) for row in self._cursor.fetchall()]


class Connection:
    def __init__(self, connection, postgres=False):
        self._connection = connection
        self.postgres = postgres

    def __enter__(self):
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return self._connection.__exit__(exc_type, exc_value, traceback)
        finally:
            self._connection.close()

    def execute(self, query, parameters=()):
        if not self.postgres:
            return self._connection.execute(query, parameters)

        statement = query.strip()
        if statement.upper() == "BEGIN IMMEDIATE":
            return Cursor(self._connection.execute("SELECT pg_advisory_xact_lock(90310323)"))

        returning_id = bool(
            re.match(r"INSERT\s+INTO\s+(users|lead_documents)\b", statement, re.IGNORECASE)
            and not re.search(r"\bRETURNING\b", statement, re.IGNORECASE)
        )
        if returning_id:
            statement = statement.rstrip(";") + " RETURNING id"

        cursor = self._connection.execute(statement.replace("?", "%s"), parameters)
        lastrowid = None
        if returning_id:
            row = cursor.fetchone()
            lastrowid = row["id"] if row else None
        return Cursor(cursor, lastrowid)

    def executescript(self, script):
        if self.postgres:
            raise RuntimeError("Scripts SQL multilinha não são suportados pelo PostgreSQL.")
        return self._connection.executescript(script)


def connect_db():
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("Instale as dependências do projeto para conectar ao PostgreSQL.")
        return Connection(
            psycopg.connect(DATABASE_URL, connect_timeout=10, row_factory=dict_row),
            postgres=True,
        )

    if os.environ.get("VERCEL") == "1":
        raise RuntimeError("Configure DATABASE_URL ou POSTGRES_URL no projeto Vercel.")

    SQLITE_DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(SQLITE_DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return Connection(connection)


def integrity_errors():
    errors = [sqlite3.IntegrityError]
    if psycopg is not None:
        errors.append(psycopg.IntegrityError)
    return tuple(errors)
