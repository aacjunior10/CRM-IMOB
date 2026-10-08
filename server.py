import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote


ROOT = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("CRM_DATABASE", ROOT / "casa_norte.sqlite3"))
HOST = os.environ.get("CRM_HOST", "0.0.0.0")
PORT = int(os.environ.get("CRM_PORT", "8000"))
SESSION_SECONDS = 8 * 60 * 60
ONLINE_WINDOW_SECONDS = 120
COOKIE_NAME = "casa_norte_session"
HTTPS_ONLY = os.environ.get("CRM_HTTPS", "0") == "1"
PASSWORD_ITERATIONS = 600_000
MAX_PROFILE_PHOTO_BYTES = 512 * 1024
MAX_LEAD_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_DOCUMENTS_PER_LEAD = 10


def connect_db():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_db():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT NOT NULL DEFAULT '',
                photo TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
                active INTEGER NOT NULL DEFAULT 1,
                approved INTEGER NOT NULL DEFAULT 1,
                auth_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                auth_version INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                username TEXT NOT NULL,
                attempted_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS login_attempts_lookup ON login_attempts(address, username, attempted_at);
            CREATE TABLE IF NOT EXISTS leads (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS leads_updated ON leads(updated_at DESC);
            CREATE TABLE IF NOT EXISTS lead_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lead_id TEXT NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                mime_type TEXT NOT NULL CHECK (mime_type IN ('image/jpeg', 'application/pdf')),
                content BLOB NOT NULL,
                size INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS lead_documents_lookup ON lead_documents(lead_id, created_at DESC);
        """)
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "email" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
        if "photo" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN photo TEXT NOT NULL DEFAULT ''")
        if "approved" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 1")
        session_columns = {row["name"] for row in db.execute("PRAGMA table_info(sessions)")}
        if "last_seen" not in session_columns:
            db.execute("ALTER TABLE sessions ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0")
        db.execute("CREATE INDEX IF NOT EXISTS sessions_last_seen ON sessions(last_seen)")


def validate_profile_photo(value):
    if not value:
        return ""
    if not isinstance(value, str) or len(value) > 700_000:
        return None
    try:
        header, encoded = value.split(",", 1)
        mime_type = header.removeprefix("data:").removesuffix(";base64")
        if header != f"data:{mime_type};base64" or mime_type not in ("image/png", "image/jpeg", "image/webp"):
            return None
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(content) > MAX_PROFILE_PHOTO_BYTES:
        return None
    signatures = {
        "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg": content.startswith(b"\xff\xd8\xff"),
        "image/webp": len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP",
    }
    if not signatures[mime_type]:
        return None
    return value


def valid_action_datetime(value):
    if value == "":
        return True
    if not isinstance(value, str) or len(value) != 16:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M")
        return True
    except ValueError:
        return False


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class CRMServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class CRMHandler(BaseHTTPRequestHandler):
    server_version = "CasaNorteCRM"
    sys_version = ""

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}")

    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_html_file(self, filename, status=200):
        body = (ROOT / filename).read_bytes()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://cdn.jsdelivr.net https://unpkg.com; script-src 'self' https://cdn.jsdelivr.net https://unpkg.com 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, max_length=16_384):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 1 or length > max_length:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def request_is_same_origin(self):
        origin = self.headers.get("Origin")
        if origin:
            expected_scheme = "https" if HTTPS_ONLY else "http"
            expected_host = self.headers.get("Host", "").lower()
            if os.environ.get("CRM_TRUST_PROXY") == "1":
                expected_host = self.headers.get("X-Forwarded-Host", expected_host).lower()
                expected_scheme = self.headers.get("X-Forwarded-Proto", expected_scheme).lower()
            return origin.rstrip("/").lower() == f"{expected_scheme}://{expected_host}"
        return self.headers.get("Sec-Fetch-Site", "same-origin") in ("same-origin", "none")

    def get_session(self):
        cookie_header = self.headers.get("Cookie", "")
        parsed = cookies.SimpleCookie()
        try:
            parsed.load(cookie_header)
            token = parsed[COOKIE_NAME].value
        except (KeyError, cookies.CookieError):
            return None
        now = int(time.time())
        with connect_db() as db:
            row = db.execute("""
                SELECT users.id, users.name, users.username, users.email, users.role, users.active,
                       users.auth_version, sessions.token_hash
                FROM sessions JOIN users ON users.id = sessions.user_id
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """, (token_digest(token), now)).fetchone()
            if not row or not row["active"]:
                return None
            session_version = db.execute("SELECT auth_version FROM sessions WHERE token_hash = ?", (token_digest(token),)).fetchone()
            if not session_version or session_version["auth_version"] != row["auth_version"]:
                return None
            return dict(row)

    def require_user(self, admin=False):
        user = self.get_session()
        if not user:
            self.send_json(401, {"error": "Faça login para continuar."})
            return None
        if admin and user["role"] != "admin":
            self.send_json(403, {"error": "Acesso restrito à administração."})
            return None
        return user

    def do_GET(self):
        if self.path == "/api/me":
            user = self.require_user()
            if user:
                with connect_db() as db:
                    db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (int(time.time()), user["token_hash"]))
                    photo = db.execute("SELECT photo FROM users WHERE id = ?", (user["id"],)).fetchone()["photo"]
                self.send_json(200, {"user": {"id": user["id"], "name": user["name"], "username": user["username"], "email": user["email"], "photo": photo, "role": user["role"]}})
            return
        if self.path == "/api/users":
            user = self.require_user(admin=True)
            if not user:
                return
            with connect_db() as db:
                users = db.execute("SELECT id, name, username, email, role, active, approved, created_at FROM users ORDER BY name COLLATE NOCASE").fetchall()
                online = db.execute("SELECT COUNT(DISTINCT sessions.user_id) FROM sessions JOIN users ON users.id = sessions.user_id WHERE users.active = 1 AND sessions.expires_at > ? AND sessions.last_seen > ?", (int(time.time()), int(time.time()) - ONLINE_WINDOW_SECONDS)).fetchone()[0]
            self.send_json(200, {"users": [dict(item) for item in users], "capacity": "unlimited", "online": online, "currentUserId": user["id"]})
            return
        if self.path == "/api/leads":
            if not self.require_user():
                return
            with connect_db() as db:
                rows = db.execute("SELECT data, updated_at FROM leads ORDER BY updated_at DESC, id DESC").fetchall()
            self.send_json(200, {"leads": [{**json.loads(row["data"]), "updatedAt": row["updated_at"]} for row in rows]})
            return
        lead_documents_prefix = "/api/leads/"
        if self.path.startswith(lead_documents_prefix) and self.path.endswith("/documents"):
            lead_id = unquote(self.path[len(lead_documents_prefix):-len("/documents")])
            self.list_lead_documents(lead_id)
            return
        document_prefix = "/api/lead-documents/"
        if self.path.startswith(document_prefix):
            self.send_lead_document(unquote(self.path[len(document_prefix):]))
            return
        if self.path in ("/", "/login"):
            if self.get_session():
                self.send_html_file("index.html")
            else:
                self.send_html_file("login.html")
            return
        if self.path == "/cadastro":
            if self.get_session():
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self.send_html_file("cadastro.html")
            return
        if self.path == "/admin":
            user = self.get_session()
            if not user:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
            elif user["role"] != "admin":
                self.send_response(403)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_html_file("admin.html")
            return
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_json(404, {"error": "Página não encontrada."})

    def do_POST(self):
        if not self.request_is_same_origin():
            self.send_json(403, {"error": "Origem da solicitação inválida."})
            return
        if self.path == "/api/logout":
            self.logout()
            return
        if self.path == "/api/heartbeat":
            self.heartbeat()
            return
        lead_documents_prefix = "/api/leads/"
        if self.path.startswith(lead_documents_prefix) and self.path.endswith("/documents"):
            lead_id = unquote(self.path[len(lead_documents_prefix):-len("/documents")])
            self.upload_lead_document(lead_id)
            return
        data = self.read_json(1_000_000 if self.path == "/api/register" else 16_384)
        if not isinstance(data, dict):
            self.send_json(400, {"error": "Dados inválidos."})
            return
        if self.path == "/api/login":
            self.login(data)
        elif self.path == "/api/register":
            self.register_user(data)
        elif self.path == "/api/users":
            self.create_user(data)
        elif self.path == "/api/account/delete":
            self.delete_own_account(data)
        elif self.path == "/api/leads":
            self.create_lead(data)
        elif self.path == "/api/leads/seed":
            self.seed_leads(data)
        else:
            self.send_json(404, {"error": "Rota não encontrada."})

    def do_PATCH(self):
        if not self.request_is_same_origin():
            self.send_json(403, {"error": "Origem da solicitação inválida."})
            return
        data = self.read_json(32_768 if self.path.startswith("/api/leads/") else 16_384)
        if not isinstance(data, dict):
            self.send_json(400, {"error": "Dados inválidos."})
            return
        if self.path.startswith("/api/users/"):
            self.update_user(unquote(self.path[len("/api/users/"):]), data)
        elif self.path.startswith("/api/leads/"):
            self.update_lead(unquote(self.path[len("/api/leads/"):]), data)
        else:
            self.send_json(404, {"error": "Rota não encontrada."})

    def do_DELETE(self):
        if not self.request_is_same_origin():
            self.send_json(403, {"error": "Origem da solicitação inválida."})
            return
        document_prefix = "/api/lead-documents/"
        if self.path.startswith(document_prefix):
            self.delete_lead_document(unquote(self.path[len(document_prefix):]))
            return
        prefix = "/api/users/"
        if not self.path.startswith(prefix):
            self.send_json(404, {"error": "Rota não encontrada."})
            return
        actor = self.require_user(admin=True)
        if not actor:
            return
        user_id = unquote(self.path[len(prefix):])
        if not user_id.isdigit():
            self.send_json(400, {"error": "Usuário inválido."})
            return
        target_id = int(user_id)
        if target_id == actor["id"]:
            self.send_json(400, {"error": "Não é possível excluir a própria conta de administrador."})
            return
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            target = db.execute("SELECT id, role, active, approved FROM users WHERE id = ?", (target_id,)).fetchone()
            if not target:
                self.send_json(404, {"error": "Usuário não encontrado."})
                return
            if target["role"] == "admin" and target["active"] and target["approved"]:
                remaining_admins = db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1 AND approved = 1 AND id != ?", (target_id,)).fetchone()[0]
                if remaining_admins == 0:
                    self.send_json(400, {"error": "Mantenha pelo menos um administrador ativo."})
                    return
            db.execute("DELETE FROM users WHERE id = ?", (target_id,))
        self.send_json(200, {"ok": True})

    def list_lead_documents(self, lead_id):
        if not self.require_user():
            return
        with connect_db() as db:
            if not db.execute("SELECT 1 FROM leads WHERE id = ?", (lead_id,)).fetchone():
                self.send_json(404, {"error": "Lead não encontrada."})
                return
            rows = db.execute("SELECT id, name, mime_type, size, created_at FROM lead_documents WHERE lead_id = ? ORDER BY created_at DESC, id DESC", (lead_id,)).fetchall()
        self.send_json(200, {"documents": [dict(row) for row in rows]})

    def upload_lead_document(self, lead_id):
        if not self.require_user():
            return
        encoded_name = self.headers.get("X-File-Name", "")
        name = unquote(encoded_name).replace("\\", "/").rsplit("/", 1)[-1].strip()
        if not name or len(name) > 180:
            self.send_json(400, {"error": "Nome de arquivo inválido."})
            return
        extension = Path(name).suffix.lower()
        if extension not in (".jpg", ".jpeg", ".pdf"):
            self.send_json(400, {"error": "Envie somente arquivos JPG ou PDF."})
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "Tamanho do arquivo inválido."})
            return
        if content_length < 1:
            self.send_json(400, {"error": "O arquivo está vazio."})
            return
        if content_length > MAX_LEAD_DOCUMENT_BYTES:
            self.send_json(413, {"error": "Cada arquivo pode ter no máximo 10 MB."})
            return
        content = self.rfile.read(content_length)
        if len(content) != content_length:
            self.send_json(400, {"error": "Não foi possível receber o arquivo completo."})
            return
        if content.startswith(b"\xff\xd8\xff"):
            mime_type = "image/jpeg"
            valid_extension = extension in (".jpg", ".jpeg")
        elif content.startswith(b"%PDF-"):
            mime_type = "application/pdf"
            valid_extension = extension == ".pdf"
        else:
            self.send_json(400, {"error": "O conteúdo não corresponde a um JPG ou PDF válido."})
            return
        request_mime = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if not valid_extension or request_mime not in (mime_type, "application/octet-stream"):
            self.send_json(400, {"error": "A extensão e o conteúdo do arquivo não correspondem."})
            return
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM leads WHERE id = ?", (lead_id,)).fetchone():
                self.send_json(404, {"error": "Lead não encontrada."})
                return
            document_count = db.execute("SELECT COUNT(*) FROM lead_documents WHERE lead_id = ?", (lead_id,)).fetchone()[0]
            if document_count >= MAX_DOCUMENTS_PER_LEAD:
                self.send_json(400, {"error": "Cada lead pode ter no máximo 10 documentos."})
                return
            cursor = db.execute("INSERT INTO lead_documents(lead_id, name, mime_type, content, size, created_at) VALUES (?, ?, ?, ?, ?, ?)", (lead_id, name, mime_type, content, len(content), int(time.time())))
        self.send_json(201, {"document": {"id": cursor.lastrowid, "name": name, "mime_type": mime_type, "size": len(content)}})

    def send_lead_document(self, document_id):
        if not self.require_user():
            return
        if not document_id.isdigit():
            self.send_json(400, {"error": "Documento inválido."})
            return
        with connect_db() as db:
            row = db.execute("SELECT name, mime_type, content FROM lead_documents WHERE id = ?", (int(document_id),)).fetchone()
        if not row:
            self.send_json(404, {"error": "Documento não encontrado."})
            return
        self.send_response(200)
        self.send_header("Content-Type", row["mime_type"])
        self.send_header("Content-Length", str(len(row["content"])))
        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(row['name'])}")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(row["content"])

    def delete_lead_document(self, document_id):
        if not self.require_user():
            return
        if not document_id.isdigit():
            self.send_json(400, {"error": "Documento inválido."})
            return
        with connect_db() as db:
            deleted = db.execute("DELETE FROM lead_documents WHERE id = ?", (int(document_id),)).rowcount
        if not deleted:
            self.send_json(404, {"error": "Documento não encontrado."})
            return
        self.send_json(200, {"ok": True})

    def create_lead(self, data):
        if not self.require_user():
            return
        lead = self.validate_lead(data)
        if not lead:
            return
        lead["id"] = secrets.token_urlsafe(12)
        lead["updated"] = "Agora"
        with connect_db() as db:
            db.execute("INSERT INTO leads(id, data, updated_at) VALUES (?, ?, ?)", (lead["id"], json.dumps(lead, ensure_ascii=False), int(time.time())))
        self.send_json(201, {"lead": lead})

    def seed_leads(self, data):
        if not self.require_user(admin=True):
            return
        seeds = data.get("leads") if isinstance(data, dict) else None
        if not isinstance(seeds, list) or len(seeds) > 100:
            self.send_json(400, {"error": "Dados iniciais inválidos."})
            return
        seeded = False
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("SELECT COUNT(*) FROM leads").fetchone()[0]
            if count == 0:
                now = int(time.time())
                for lead_data in seeds:
                    if not isinstance(lead_data, dict):
                        continue
                    lead = self.validate_lead(lead_data, respond=False)
                    if not lead:
                        continue
                    lead["id"] = secrets.token_urlsafe(12)
                    lead["updated"] = str(lead_data.get("updated", "Recente"))[:60]
                    db.execute("INSERT INTO leads(id, data, updated_at) VALUES (?, ?, ?)", (lead["id"], json.dumps(lead, ensure_ascii=False), now))
                seeded = True
        with connect_db() as db:
            rows = db.execute("SELECT data, updated_at FROM leads ORDER BY updated_at DESC, id DESC").fetchall()
        self.send_json(200, {"leads": [{**json.loads(row["data"]), "updatedAt": row["updated_at"]} for row in rows], "seeded": seeded})

    def validate_lead(self, data, respond=True):
        stages = ("Lead", "Atendimento", "Agendamento", "Visita", "Proposta", "Venda concretizada", "Venda perdida")
        if not isinstance(data, dict):
            if respond:
                self.send_json(400, {"error": "Dados da lead inválidos."})
            return None
        name = str(data.get("name", "")).strip()[:100]
        phone = str(data.get("phone", "")).strip()[:40]
        next_action_at = data.get("nextActionAt", "") or ""
        stage = data.get("stage", "Lead")
        value = data.get("value", 0)
        if len(name.split()) < 2:
            if respond:
                self.send_json(400, {"error": "Informe o nome completo, com nome e sobrenome."})
            return None
        phone_digits = re.sub(r"\D", "", phone)
        if not 8 <= len(phone_digits) <= 15:
            if respond:
                self.send_json(400, {"error": "Informe um telefone válido com 8 a 15 dígitos."})
            return None
        if stage not in stages:
            if respond:
                self.send_json(400, {"error": "Informe uma etapa válida."})
            return None
        if not valid_action_datetime(next_action_at):
            if respond:
                self.send_json(400, {"error": "Informe uma data e hora válidas para a próxima ação."})
            return None
        try:
            value = max(0, min(float(value or 0), 1_000_000_000_000))
        except (TypeError, ValueError):
            if respond:
                self.send_json(400, {"error": "Valor estimado inválido."})
            return None
        return {
            "name": name,
            "phone": phone,
            "email": str(data.get("email", ""))[:254],
            "property": str(data.get("property", ""))[:200],
            "value": value,
            "stage": stage,
            "agent": str(data.get("agent", ""))[:100],
            "priority": str(data.get("priority", "Normal"))[:30],
            "nextAction": str(data.get("nextAction", ""))[:200],
            "nextActionAt": next_action_at,
            "notes": str(data.get("notes", ""))[:5000],
            "source": str(data.get("source", "Contato direto"))[:100],
        }

    def update_lead(self, lead_id, data):
        if not self.require_user():
            return
        stages = ("Lead", "Atendimento", "Agendamento", "Visita", "Proposta", "Venda concretizada", "Venda perdida")
        if "stage" in data and data["stage"] not in stages:
            self.send_json(400, {"error": "Etapa inválida."})
            return
        if "notes" in data and (not isinstance(data["notes"], str) or len(data["notes"]) > 5000):
            self.send_json(400, {"error": "As anotações devem ter até 5.000 caracteres."})
            return
        if "nextAction" in data and (not isinstance(data["nextAction"], str) or len(data["nextAction"]) > 200):
            self.send_json(400, {"error": "A próxima ação deve ter até 200 caracteres."})
            return
        if "nextActionAt" in data and not valid_action_datetime(data["nextActionAt"]):
            self.send_json(400, {"error": "Informe uma data e hora válidas para a próxima ação."})
            return
        if not any(field in data for field in ("stage", "notes", "nextAction", "nextActionAt")):
            self.send_json(400, {"error": "Nenhuma alteração informada."})
            return
        with connect_db() as db:
            row = db.execute("SELECT data FROM leads WHERE id = ?", (lead_id,)).fetchone()
            if not row:
                self.send_json(404, {"error": "Lead não encontrada."})
                return
            lead = json.loads(row["data"])
            if "stage" in data:
                lead["stage"] = data["stage"]
            if "notes" in data:
                lead["notes"] = data["notes"].strip()
            if "nextAction" in data:
                lead["nextAction"] = data["nextAction"].strip()
            if "nextActionAt" in data:
                lead["nextActionAt"] = data["nextActionAt"]
            lead["updated"] = "Agora"
            db.execute("UPDATE leads SET data = ?, updated_at = ? WHERE id = ?", (json.dumps(lead, ensure_ascii=False), int(time.time()), lead_id))
        self.send_json(200, {"lead": lead})

    def login(self, data):
        username = str(data.get("username", "")).strip().lower()[:80]
        password = str(data.get("password", ""))[:256]
        address = self.client_address[0]
        now = int(time.time())
        with connect_db() as db:
            db.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (now - 900,))
            attempts = db.execute("SELECT COUNT(*) FROM login_attempts WHERE address = ? AND username = ?", (address, username)).fetchone()[0]
            if attempts >= 5:
                self.send_json(429, {"error": "Muitas tentativas. Aguarde 15 minutos e tente novamente."})
                return
            row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not row or not verify_password(password, row["password_hash"]):
                db.execute("INSERT INTO login_attempts(address, username, attempted_at) VALUES (?, ?, ?)", (address, username, now))
                self.send_json(401, {"error": "Usuário ou senha incorretos."})
                return
            if not row["approved"]:
                self.send_json(403, {"error": "Cadastro aguardando aprovação do administrador."})
                return
            if not row["active"]:
                self.send_json(403, {"error": "Esta conta está desativada. Fale com o administrador."})
                return
            db.execute("DELETE FROM login_attempts WHERE address = ? AND username = ?", (address, username))
            token = secrets.token_urlsafe(32)
            db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            db.execute("INSERT INTO sessions(token_hash, user_id, auth_version, expires_at, last_seen) VALUES (?, ?, ?, ?, ?)", (token_digest(token), row["id"], row["auth_version"], now + SESSION_SECONDS, now))
        cookie = f"{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}"
        if HTTPS_ONLY:
            cookie += "; Secure"
        self.send_json(200, {"user": {"name": row["name"], "role": row["role"]}}, {"Set-Cookie": cookie})

    def logout(self):
        user = self.get_session()
        if user:
            try:
                parsed = cookies.SimpleCookie(self.headers.get("Cookie", ""))
                token = parsed[COOKIE_NAME].value
                with connect_db() as db:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
            except (KeyError, cookies.CookieError):
                pass
        cookie = f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" + ("; Secure" if HTTPS_ONLY else "")
        self.send_json(200, {"ok": True}, {"Set-Cookie": cookie})

    def heartbeat(self):
        user = self.require_user()
        if not user:
            return
        with connect_db() as db:
            db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (int(time.time()), user["token_hash"]))
        self.send_json(200, {"ok": True})

    def delete_own_account(self, data):
        user = self.require_user()
        if not user:
            return
        password = str(data.get("password", ""))[:256]
        cookie = f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" + ("; Secure" if HTTPS_ONLY else "")
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            account = db.execute("SELECT password_hash, role, active FROM users WHERE id = ?", (user["id"],)).fetchone()
            if not account or not verify_password(password, account["password_hash"]):
                self.send_json(401, {"error": "Senha incorreta."})
                return
            if account["role"] == "admin" and account["active"]:
                active_admins = db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]
                if active_admins <= 1:
                    self.send_json(409, {"error": "Não é possível excluir o último administrador ativo."})
                    return
            db.execute("UPDATE users SET active = 0, auth_version = auth_version + 1 WHERE id = ?", (user["id"],))
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        self.send_json(200, {"ok": True}, {"Set-Cookie": cookie})

    def create_user(self, data):
        actor = self.require_user(admin=True)
        if not actor:
            return
        name = str(data.get("name", "")).strip()[:100]
        username = str(data.get("username", "")).strip().lower()
        password = str(data.get("password", ""))
        role = data.get("role", "member")
        if not name or not 3 <= len(username) <= 80 or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in username):
            self.send_json(400, {"error": "Informe nome e usuário válido (letras, números, ponto, hífen ou sublinhado)."})
            return
        if not 12 <= len(password) <= 256:
            self.send_json(400, {"error": "A senha deve ter entre 12 e 256 caracteres."})
            return
        if role not in ("admin", "member"):
            self.send_json(400, {"error": "Perfil inválido."})
            return
        try:
            with connect_db() as db:
                cursor = db.execute("INSERT INTO users(name, username, password_hash, role) VALUES (?, ?, ?, ?)", (name, username, hash_password(password), role))
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "Este usuário já existe."})
            return
        self.send_json(201, {"user": {"id": user_id, "name": name, "username": username, "role": role, "active": 1}})

    def register_user(self, data):
        name = str(data.get("name", "")).strip()[:100]
        username = str(data.get("username", "")).strip().lower()
        email = str(data.get("email", "")).strip().lower()[:254]
        password = str(data.get("password", ""))
        photo = validate_profile_photo(data.get("photo", ""))
        if not name or not 3 <= len(username) <= 80 or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in username):
            self.send_json(400, {"error": "Informe nome e usuário válido (letras, números, ponto, hífen ou sublinhado)."})
            return
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            self.send_json(400, {"error": "Informe um e-mail válido."})
            return
        if photo is None:
            self.send_json(400, {"error": "Envie uma foto PNG, JPEG ou WebP de até 512 KB."})
            return
        if not 12 <= len(password) <= 256:
            self.send_json(400, {"error": "A senha deve ter entre 12 e 256 caracteres."})
            return
        try:
            with connect_db() as db:
                cursor = db.execute("INSERT INTO users(name, username, email, photo, password_hash, role, active, approved) VALUES (?, ?, ?, ?, ?, 'member', 0, 0)", (name, username, email, photo, hash_password(password)))
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            self.send_json(409, {"error": "Este usuário já existe."})
            return
        self.send_json(201, {"user": {"id": user_id, "name": name, "username": username, "email": email, "role": "member", "active": 0, "approved": 0}})

    def update_user(self, user_id, data):
        actor = self.require_user(admin=True)
        if not actor:
            return
        if not user_id.isdigit():
            self.send_json(400, {"error": "Usuário inválido."})
            return
        target_id = int(user_id)
        if target_id == actor["id"]:
            self.send_json(400, {"error": "Não é possível alterar o próprio acesso por esta tela."})
            return
        with connect_db() as db:
            target = db.execute("SELECT id, role, active, approved FROM users WHERE id = ?", (target_id,)).fetchone()
            if not target:
                self.send_json(404, {"error": "Usuário não encontrado."})
                return
            if data.get("approved") is True:
                if target["approved"]:
                    self.send_json(400, {"error": "Este cadastro já foi aprovado."})
                    return
                db.execute("UPDATE users SET approved = 1, active = 1, auth_version = auth_version + 1 WHERE id = ?", (target_id,))
                db.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
            elif "active" in data:
                active = 1 if data["active"] else 0
                if not active and target["role"] == "admin" and target["active"]:
                    count = db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]
                    if count <= 1:
                        self.send_json(400, {"error": "Mantenha pelo menos um administrador ativo."})
                        return
                db.execute("UPDATE users SET active = ?, auth_version = auth_version + 1 WHERE id = ?", (active, target_id))
                if not active:
                    db.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
            elif "password" in data:
                password = str(data["password"])
                if not 12 <= len(password) <= 256:
                    self.send_json(400, {"error": "A senha deve ter entre 12 e 256 caracteres."})
                    return
                db.execute("UPDATE users SET password_hash = ?, auth_version = auth_version + 1 WHERE id = ?", (hash_password(password), target_id))
                db.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
            else:
                self.send_json(400, {"error": "Nenhuma alteração informada."})
                return
        self.send_json(200, {"ok": True})


def main():
    initialize_db()
    server = CRMServer((HOST, PORT), CRMHandler)
    print(f"Casa Norte CRM disponível em http://{HOST}:{PORT}")
    if HOST == "127.0.0.1":
        print("Acesso local ativo. Para equipe na rede, configure HTTPS antes de expor o servidor.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor encerrado.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()