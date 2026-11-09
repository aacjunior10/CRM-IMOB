import io
from email.message import Message
from threading import Lock

from fastapi import FastAPI, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

import server


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_database_initialized = False
_database_lock = Lock()
_ALLOWED_METHODS = ("GET", "POST", "PATCH", "DELETE")
_MAX_REQUEST_BYTES = server.MAX_LEAD_DOCUMENT_BYTES + 64 * 1024


class ServerlessHandler(server.CRMHandler):
    def __init__(self, path, method, headers, body, client_address):
        self.path = path
        self.command = method
        self.headers = headers
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.client_address = client_address
        self.response_status = 200
        self.response_headers = []

    def send_response(self, code, message=None):
        self.response_status = code

    def send_header(self, keyword, value):
        self.response_headers.append((keyword, str(value)))

    def end_headers(self):
        pass

    def log_message(self, format_string, *args):
        pass


def _initialize_database():
    global _database_initialized
    if _database_initialized:
        return
    with _database_lock:
        if not _database_initialized:
            server.initialize_db()
            _database_initialized = True


def _handle_request(path, method, request_headers, body, client_address):
    _initialize_database()
    handler = ServerlessHandler(path, method, request_headers, body, client_address)
    dispatch = getattr(handler, f"do_{method}", None)
    if dispatch is None:
        handler.send_response(405)
        handler.send_header("Allow", ", ".join(_ALLOWED_METHODS))
        handler.end_headers()
    else:
        dispatch()

    response = Response(content=handler.wfile.getvalue(), status_code=handler.response_status)
    response.raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in handler.response_headers
    ]
    return response


async def _dispatch(request: Request):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _MAX_REQUEST_BYTES:
                return Response(status_code=413, content="Request body too large")
        except ValueError:
            return Response(status_code=400, content="Invalid Content-Length")

    chunks = bytearray()
    async for chunk in request.stream():
        chunks.extend(chunk)
        if len(chunks) > _MAX_REQUEST_BYTES:
            return Response(status_code=413, content="Request body too large")

    request_path = request.scope.get("raw_path", request.url.path.encode("utf-8")).decode("latin-1")
    if request.scope.get("query_string"):
        request_path += "?" + request.scope["query_string"].decode("latin-1")

    headers = Message()
    for name, value in request.headers.items():
        headers[name] = value
    client_address = (request.client.host if request.client else "", 0)
    return await run_in_threadpool(
        _handle_request,
        request_path,
        request.method,
        headers,
        bytes(chunks),
        client_address,
    )


app.add_api_route("/", _dispatch, methods=list(_ALLOWED_METHODS), include_in_schema=False)
app.add_api_route("/{path:path}", _dispatch, methods=list(_ALLOWED_METHODS), include_in_schema=False)
