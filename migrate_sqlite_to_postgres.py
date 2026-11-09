import argparse
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

import server
from database import DATABASE_URL


TABLES = {
    "users": (
        "id", "name", "username", "email", "photo", "password_hash", "role",
        "active", "approved", "auth_version", "created_at",
    ),
    "sessions": ("token_hash", "user_id", "auth_version", "expires_at", "last_seen"),
    "login_attempts": ("id", "address", "username", "attempted_at"),
    "leads": ("id", "data", "updated_at"),
    "lead_documents": (
        "id", "lead_id", "name", "mime_type", "content", "size", "created_at",
    ),
}


def migrate(source_path):
    source_path = Path(source_path)
    if not source_path.is_file():
        raise FileNotFoundError(f"Arquivo SQLite não encontrado: {source_path}")
    if not DATABASE_URL:
        raise RuntimeError("Defina DATABASE_URL ou POSTGRES_URL para o PostgreSQL de destino.")

    server.initialize_db()
    with server.connect_db() as target:
        if not target.postgres:
            raise RuntimeError("Defina DATABASE_URL ou POSTGRES_URL para o PostgreSQL de destino.")
        populated_tables = []
        for table in TABLES:
            if target.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:
                populated_tables.append(table)
        if populated_tables:
            names = ", ".join(populated_tables)
            raise RuntimeError(
                f"O PostgreSQL já contém dados nas tabelas {names}; use um banco vazio para evitar mesclar contas incorretamente."
            )

        with closing(sqlite3.connect(source_path)) as source:
            source.row_factory = sqlite3.Row
            for table, columns in TABLES.items():
                names = ", ".join(columns)
                placeholders = ", ".join("?" for _ in columns)
                statement = (
                    f"INSERT INTO {table} ({names}) VALUES ({placeholders}) "
                    "ON CONFLICT DO NOTHING"
                )
                migrated = 0
                rows = source.execute(f"SELECT {names} FROM {table}").fetchall()
                for row in rows:
                    result = target.execute(statement, tuple(row[column] for column in columns))
                    migrated += result.rowcount
                print(f"{table}: {migrated} de {len(rows)} registros copiados.")

        for table in ("users", "login_attempts", "lead_documents"):
            target.execute(
                f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                f"COALESCE(MAX(id), 1), MAX(id) IS NOT NULL) FROM {table}"
            )


def main():
    parser = argparse.ArgumentParser(description="Copie o CRM SQLite para o PostgreSQL configurado.")
    parser.add_argument("--source", default=str(server.DATABASE), help="arquivo SQLite de origem")
    args = parser.parse_args()
    try:
        migrate(args.source)
    except (OSError, sqlite3.Error, RuntimeError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
