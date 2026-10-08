import argparse
import getpass
import sqlite3
import sys

import server


def normalize_username(value):
    username = value.strip().lower()
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    if not 3 <= len(username) <= 80 or any(character not in allowed for character in username):
        raise ValueError("Usuário inválido. Use de 3 a 80 letras, números, ponto, hífen ou sublinhado.")
    return username


def prompt_password():
    password = getpass.getpass("Senha (mínimo de 12 caracteres): ")
    confirmation = getpass.getpass("Confirme a senha: ")
    if password != confirmation:
        raise ValueError("As senhas não coincidem.")
    if not 12 <= len(password) <= 256:
        raise ValueError("A senha deve ter entre 12 e 256 caracteres.")
    return password


def create_user(args):
    name = args.name.strip()[:100]
    username = normalize_username(args.username)
    if not name:
        raise ValueError("O nome é obrigatório.")
    password = prompt_password()
    with server.connect_db() as db:
        db.execute(
            "INSERT INTO users(name, username, password_hash, role) VALUES (?, ?, ?, ?)",
            (name, username, server.hash_password(password), args.role),
        )
    print(f"Acesso {args.role} criado para {name} ({username}).")


def list_users(_args):
    with server.connect_db() as db:
        users = db.execute(
            "SELECT name, username, role, active, created_at FROM users ORDER BY name COLLATE NOCASE"
        ).fetchall()
    if not users:
        print("Nenhum acesso cadastrado.")
        return
    for user in users:
        status = "Ativo" if user["active"] else "Desativado"
        role = "Administrador" if user["role"] == "admin" else "Equipe"
        print(f"{user['name']} | {user['username']} | {role} | {status} | {user['created_at']}")


def set_user_active(args):
    active = args.active
    username = normalize_username(args.username)
    with server.connect_db() as db:
        user = db.execute("SELECT id, role, active FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            raise ValueError("Usuário não encontrado.")
        if not active and user["role"] == "admin" and user["active"]:
            active_admins = db.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1"
            ).fetchone()[0]
            if active_admins <= 1:
                raise ValueError("Mantenha pelo menos um administrador ativo.")
        db.execute(
            "UPDATE users SET active = ?, auth_version = auth_version + 1 WHERE id = ?",
            (int(active), user["id"]),
        )
        if not active:
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    print(f"Acesso de {username}: {'ativo' if active else 'desativado'}.")


def reset_password(args):
    username = normalize_username(args.username)
    password = prompt_password()
    with server.connect_db() as db:
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            raise ValueError("Usuário não encontrado.")
        db.execute(
            "UPDATE users SET password_hash = ?, auth_version = auth_version + 1 WHERE id = ?",
            (server.hash_password(password), user["id"]),
        )
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    print(f"Senha redefinida para {username}; sessões anteriores encerradas.")


def set_user_role(args):
    username = normalize_username(args.username)
    role = args.role
    with server.connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT id, role, active FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            raise ValueError("Usuário não encontrado.")
        if role == user["role"]:
            print(f"{username} já possui o perfil {role}.")
            return
        if role != "admin" and user["role"] == "admin" and user["active"]:
            active_admins = db.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1"
            ).fetchone()[0]
            if active_admins <= 1:
                raise ValueError("Mantenha pelo menos um administrador ativo.")
        db.execute(
            "UPDATE users SET role = ?, auth_version = auth_version + 1 WHERE id = ?",
            (role, user["id"]),
        )
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    print(f"Perfil de {username} atualizado para {role}; sessões anteriores encerradas.")


def main():
    parser = argparse.ArgumentParser(description="Gerencie os acessos do Casa Norte CRM.")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="criar uma conta")
    create.add_argument("--name", required=True, help="nome da pessoa")
    create.add_argument("--username", required=True, help="usuário de acesso")
    create.add_argument("--role", choices=("admin", "member"), default="member")
    create.set_defaults(action=create_user)

    listing = commands.add_parser("list", help="listar contas")
    listing.set_defaults(action=list_users)

    for command_name, active in (("disable", False), ("enable", True)):
        command = commands.add_parser(command_name, help=f"{'ativar' if active else 'desativar'} uma conta")
        command.add_argument("--username", required=True)
        command.set_defaults(action=set_user_active, active=active)

    reset = commands.add_parser("reset-password", help="redefinir uma senha")
    reset.add_argument("--username", required=True)
    reset.set_defaults(action=reset_password)

    role = commands.add_parser("set-role", help="alterar o perfil de uma conta")
    role.add_argument("--username", required=True)
    role.add_argument("--role", choices=("admin", "member"), required=True)
    role.set_defaults(action=set_user_role)

    args = parser.parse_args()
    try:
        server.initialize_db()
        args.action(args)
    except (ValueError, sqlite3.IntegrityError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())