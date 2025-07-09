import os
import http.server
import socketserver
import socket
from pathlib import Path
import urllib.parse
import html
import time
from datetime import datetime
import argparse
import shutil
from functools import partial
from io import BytesIO
import json
import qrcode
import base64
import bcrypt
import secrets
import logging
import threading
import re
import uuid

# Настройка логирования
logging.basicConfig(
    filename='server.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Парсинг аргументов командной строки
parser = argparse.ArgumentParser(description='HTTP File Server for Termux')
parser.add_argument('-p', '--port', type=int, default=8080, help='Server port')
parser.add_argument('-r', '--root', type=str, default=os.path.expanduser("~/storage/shared"),
                    help='Root directory')
parser.add_argument('--auth', action='store_true', help='Enable password authentication')
parser.add_argument('--user', type=str, default='admin', help='Username for authentication')
parser.add_argument('--pass', type=str, dest='password', default=None, help='Password for authentication')
parser.add_argument('--tokens', action='store_true', help='Enable token-based sharing')
parser.add_argument('--token-duration', type=int, default=86400,
                    help='Token validity duration in seconds (default: 24 hours)')
args = parser.parse_args()

PORT = args.port
DIRECTORY = os.path.expanduser(args.root)
SERVER_START_TIME = datetime.now()
AUTH_ENABLED = args.auth
USERNAME = args.user
PASSWORD = args.password
TOKENS_ENABLED = args.tokens
TOKEN_DURATION = args.token_duration
TOKENS = {}
CSRF_TOKENS = {}
CSRF_TOKEN_DURATION = 3600

if not os.path.exists(DIRECTORY):
    DIRECTORY = os.path.expanduser("~")
    logging.warning(f"Root directory changed to {DIRECTORY}")

if AUTH_ENABLED and not PASSWORD:
    PASSWORD = secrets.token_urlsafe(8)
    logging.info(f"Generated password for user {USERNAME}")
if AUTH_ENABLED:
    PASSWORD_HASH = bcrypt.hashpw(PASSWORD.encode('utf-8'), bcrypt.gensalt())
else:
    PASSWORD_HASH = None

def clean_expired_tokens():
    while True:
        now = time.time()
        expired = [t for t, data in TOKENS.items() if data['expiry'] <= now]
        for t in expired:
            del TOKENS[t]
            logging.info(f"Removed expired token: {t}")
        time.sleep(3600)

def clean_expired_csrf_tokens():
    while True:
        now = time.time()
        expired = [sid for sid, data in CSRF_TOKENS.items() if data['created'] + CSRF_TOKEN_DURATION < now]
        for sid in expired:
            del CSRF_TOKENS[sid]
            logging.info(f"Removed expired CSRF token for session: {sid}")
        time.sleep(3600)

if TOKENS_ENABLED:
    threading.Thread(target=clean_expired_tokens, daemon=True).start()
threading.Thread(target=clean_expired_csrf_tokens, daemon=True).start()

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Termux File Server"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def check_auth(self):
        logging.debug(f"Checking auth for path: {self.path}")
        if not AUTH_ENABLED and not TOKENS_ENABLED:
            return True

        if TOKENS_ENABLED:
            parsed_url = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_url.query)
            if 'token' in query:
                token = query['token'][0]
                logging.debug(f"Token in query: {token}")
                if token in TOKENS and TOKENS[token]['expiry'] > time.time():
                    return True

            token = self.headers.get('X-Access-Token') or self.headers.get('Authorization', '').replace('Bearer ', '')
            if token in TOKENS and TOKENS[token]['expiry'] > time.time():
                requested_path = os.path.abspath(self.translate_path(self.path))
                token_path = os.path.abspath(TOKENS[token]['path'])
                logging.debug(f"Token auth: requested_path={requested_path}, token_path={token_path}")
                if requested_path.startswith(token_path):
                    return True

        if AUTH_ENABLED:
            auth_header = self.headers.get('Authorization')
            logging.debug(f"Auth header: {auth_header}")
            if auth_header is None or not auth_header.startswith('Basic '):
                logging.debug("No or invalid auth header")
                return False
            try:
                auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                username, password = auth_decoded.split(':', 1)
                logging.debug(f"Auth attempt: username={username}")
                if username == USERNAME and bcrypt.checkpw(password.encode('utf-8'), PASSWORD_HASH):
                    return True
            except Exception as e:
                logging.error(f"Auth error: {str(e)}")
                return False
        return False

    def check_csrf(self):
        if self.command in ['POST', 'DELETE']:
            csrf_token = self.headers.get('X-CSRF-Token')
            session_id = self.headers.get('X-Session-ID')
            logging.debug(f"CSRF check: session_id={session_id}, csrf_token={csrf_token}")
            if session_id in CSRF_TOKENS and CSRF_TOKENS[session_id]['token'] == csrf_token:
                return True
            logging.warning(f"Invalid CSRF token for session {session_id}")
            return False
        return True

    def validate_path(self, path):
        abs_path = os.path.abspath(path)
        if not abs_path.startswith(os.path.abspath(DIRECTORY)):
            logging.warning(f"Path validation failed: {abs_path} not in {DIRECTORY}")
            return False
        if os.path.islink(path) or '..' in path or re.search(r'[<>|*?"]', path):
            logging.warning(f"Path validation failed: invalid characters or symlink in {path}")
            return False
        return True

    def send_head(self):
        if TOKENS_ENABLED:
            parsed_url = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_url.query)
            if 'token' in query:
                token = query['token'][0]
                if token in TOKENS and TOKENS[token]['expiry'] > time.time():
                    self.path = parsed_url.path
                    return super().send_head()

        if (AUTH_ENABLED or TOKENS_ENABLED) and not self.check_auth():
            self.do_AUTHHEAD()
            self.wfile.write(b'Authentication required')
            return None

        path = self.translate_path(self.path)
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                self.send_response(301)
                self.send_header('Location', self.path + '/')
                self.end_headers()
                return None
            return self.list_directory(path)
        return super().send_head()

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, PUT, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Access-Token, X-CSRF-Token, X-Session-ID')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')  # Prevent caching
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        logging.debug(f"GET request for path: {self.path}")
        if self.path == '/_get_token':
            if not TOKENS_ENABLED:
                self.send_error(403, "Token sharing is not enabled")
                return
            if AUTH_ENABLED and not self.check_auth():
                self.do_AUTHHEAD()
                self.wfile.write(b'Authentication required')
                return
            path = self.translate_path("/")
            token = generate_token(path)
            response = {
                'token': token,
                'expires_in': TOKEN_DURATION,
                'path': path,
                'expires_at': time.time() + TOKEN_DURATION
            }
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            return

        if self.path == '/_get_csrf':
            session_id = str(uuid.uuid4())
            csrf_token = secrets.token_urlsafe(16)
            CSRF_TOKENS[session_id] = {'token': csrf_token, 'created': time.time()}
            logging.debug(f"Generated CSRF token: session_id={session_id}, token={csrf_token}")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'session_id': session_id, 'csrf_token': csrf_token}).encode('utf-8'))
            return

        super().do_GET()

    def do_POST(self):
        if not self.check_csrf():
            self.send_error(403, "Invalid CSRF token")
            return

        content_type = self.headers.get('Content-Type', '')
        request_type = self.headers.get('X-Request-Type', '')
        logging.debug(f"POST request: path={self.path}, content_type={content_type}, request_type={request_type}")

        if self.path == '/_rename':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            logging.debug(f"Rename request data: {post_data}")
            try:
                data = json.loads(post_data)
                old_path = self.translate_path(data['old_path'])
                new_name = data['new_name']
                if not new_name or re.search(r'[<>|*?"/\\]', new_name):
                    self.send_error(400, "Invalid new name")
                    return
                new_path = os.path.join(os.path.dirname(old_path), new_name)
                if os.path.exists(new_path):
                    self.send_error(409, "Target name already exists")
                    return
                if self.validate_path(new_path):
                    try:
                        os.rename(old_path, new_path)
                        logging.info(f"Renamed {old_path} to {new_path}")
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'success'}).encode('utf-8'))
                    except Exception as e:
                        logging.error(f"Rename failed: {str(e)}")
                        self.send_error(500, str(e))
                else:
                    self.send_error(403, "Invalid path")
            except Exception as e:
                logging.error(f"Invalid rename request: {str(e)}")
                self.send_error(400, "Invalid request data")
            return

        if request_type == 'create-folder':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = urllib.parse.parse_qs(post_data)
            folder_name = params.get('folder_name', [''])[0]
            logging.debug(f"Create folder: {folder_name}")
            if not folder_name or re.search(r'[<>|*?"/\\]', folder_name):
                self.send_error(400, "Invalid folder name")
                return
            folder_path = os.path.join(self.translate_path(self.path), folder_name)
            if self.validate_path(folder_path):
                try:
                    os.makedirs(folder_path, exist_ok=True)
                    logging.info(f"Created folder: {folder_path}")
                    self.send_response(302)
                    self.send_header('Location', self.path)
                    self.end_headers()
                except Exception as e:
                    logging.error(f"Create folder failed: {str(e)}")
                    self.send_error(500, str(e))
            else:
                self.send_error(403, "Invalid path")
            return

        if content_type.startswith('multipart/form-data'):
            boundary = content_type.split('boundary=')[1].encode()
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length)
            parts = data.split(b'--' + boundary)
            for part in parts:
                if b'filename="' in part:
                    filename_match = re.search(b'filename="(.+?)"', part)
                    if not filename_match:
                        continue
                    filename = filename_match.group(1).decode('utf-8')
                    if re.search(r'[<>|*?"/\\]', filename):
                        self.send_error(400, "Invalid filename")
                        return
                    file_data = part.split(b'\r\n\r\n')[1].rsplit(b'\r\n', 1)[0]
                    if len(file_data) > 10 * 1024 * 1024:
                        self.send_error(413, "File too large")
                        return
                    allowed_extensions = {'.txt', '.jpg', '.png', '.pdf'}
                    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
                        self.send_error(415, "Unsupported file type")
                        return
                    temp_dir = os.path.join(DIRECTORY, '.temp')
                    os.makedirs(temp_dir, exist_ok=True)
                    temp_path = os.path.join(temp_dir, secrets.token_hex(16))
                    final_path = os.path.join(self.translate_path(self.path), filename)
                    if os.path.exists(final_path):
                        self.send_error(409, "File already exists")
                        return
                    if self.validate_path(final_path):
                        with open(temp_path, 'wb') as f:
                            f.write(file_data)
                        shutil.move(temp_path, final_path)
                        logging.info(f"Uploaded file: {final_path}")
                    else:
                        os.remove(temp_path)
                        self.send_error(403, "Invalid path")
                        return
            self.send_response(302)
            self.send_header('Location', self.path)
            self.end_headers()
            return

        self.send_error(400, "Invalid request")

    def do_DELETE(self):
        logging.debug(f"DELETE request for path: {self.path}")
        if not self.check_csrf():
            self.send_error(403, "Invalid CSRF token")
            return
        path = self.translate_path(self.path)
        logging.debug(f"Translated path: {path}")
        if not os.path.exists(path):
            self.send_error(404, "Path does not exist")
            return
        if self.validate_path(path):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                logging.info(f"Deleted: {path}")
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success'}).encode('utf-8'))
            except Exception as e:
                logging.error(f"Delete failed: {path}, error: {str(e)}")
                self.send_error(500, str(e))
        else:
            self.send_error(403, "Invalid path")

    def list_directory(self, path):
        try:
            items = os.listdir(path)
            items.sort(key=lambda a: a.lower())
            html_content = self.generate_html_index(path, items)
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_content)))
            self.end_headers()
            return self.wfile.write(html_content.encode('utf-8'))
        except PermissionError:
            self.send_error_page(403, "No permission to list directory")
        except Exception as e:
            self.send_error_page(500, str(e))

    def generate_html_index(self, path, items):
        rel_path = os.path.relpath(path, DIRECTORY)
        if rel_path == ".":
            rel_path = ""
        current_dir = self.path.rstrip('/') or '/'
        uptime = datetime.now() - SERVER_START_TIME
        days, seconds = uptime.days, uptime.seconds
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        uptime_str = f"{days}d {hours}h {minutes}m"

        qr = qrcode.QRCode(version=1, box_size=4, border=4)
        qr.add_data(f"http://{self.headers.get('Host')}{current_dir}")
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="#6ea8fe", back_color="transparent")
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()

        session_id = str(uuid.uuid4())
        csrf_token = secrets.token_urlsafe(16)
        CSRF_TOKENS[session_id] = {'token': csrf_token, 'created': time.time()}

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Termux File Server - {html.escape(rel_path)}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {{
            --bs-body-bg: #212529;
            --bs-body-color: #f8f9fa;
            --bs-dark-bg: #1a1e21;
            --bs-dark-border: #2c3034;
            --bs-light-text: #f8f9fa;
            --bs-primary-text: #6ea8fe;
            --bs-danger: #dc3545;
            --bs-warning: #ffc107;
        }}
        body {{
            background-color: var(--bs-body-bg);
            color: var(--bs-body-color);
            padding: 20px;
        }}
        .table {{
            --bs-table-bg: transparent;
            --bs-table-color: var(--bs-body-color);
            --bs-table-border-color: var(--bs-dark-border);
        }}
        .table-hover tbody tr:hover {{
            background-color: rgba(255, 255, 255, 0.075);
        }}
        .breadcrumb {{
            background-color: var(--bs-dark-bg);
            padding: 8px 15px;
            border-radius: 4px;
        }}
        .file-icon {{
            margin-right: 8px;
        }}
        .actions-column {{
            width: 150px;
        }}
        .folder-link {{
            color: var(--bs-primary-text);
            text-decoration: none;
        }}
        .file-link {{
            color: var(--bs-body-color);
            text-decoration: none;
        }}
        .folder-link:hover, .file-link:hover {{
            text-decoration: underline;
        }}
        .card {{
            background-color: var(--bs-dark-bg);
            border-color: var(--bs-dark-border);
        }}
        .form-control, .form-control:focus {{
            background-color: var(--bs-dark-bg);
            color: var(--bs-body-color);
            border-color: var(--bs-dark-border);
        }}
        .modal-content {{
            background-color: var(--bs-dark-bg);
            color: var(--bs-body-color);
        }}
        .btn-close {{
            filter: invert(1);
        }}
        #createFolderModal .modal-body {{
            padding: 20px;
        }}
        .text-muted {{
            color: #adb5bd !important;
        }}
        .input-group-text {{
            background-color: var(--bs-dark-bg);
            border-color: var(--bs-dark-border);
            color: var(--bs-body-color);
        }}
        .dropdown-menu {{
            background-color: var(--bs-dark-bg);
            border-color: var(--bs-dark-border);
        }}
        .dropdown-item {{
            color: var(--bs-body-color);
        }}
        .dropdown-item:hover {{
            background-color: rgba(255, 255, 255, 0.1);
            color: var(--bs-body-color);
        }}
        .breadcrumb-item.dropdown:hover .dropdown-menu {{
            display: block;
        }}
        #qrCodeContainer img {{
            background-color: white;
            padding: 10px;
            border-radius: 5px;
        }}
        .img-preview {{
            position: absolute;
            max-height: 200px;
            z-index: 1000;
            border: 2px solid #555;
            background: white;
            display: none;
        }}
        .sortable {{
            cursor: pointer;
            text-decoration: underline;
        }}
    </style>
</head>
<body data-bs-theme="dark">
    <div class="container">
        <h2 class="mt-4 mb-4">Termux File Server</h2>
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb" id="breadcrumb">
                <li class="breadcrumb-item"><a href="/">Home</a></li>
        """
        breadcrumbs = []
        current_path = ""
        for part in rel_path.split(os.sep):
            if part:
                current_path = os.path.join(current_path, part)
                breadcrumbs.append((part, current_path))
        for name, crumb_path in breadcrumbs:
            is_last = crumb_path == current_path and current_path == rel_path
            html_content += f"""
                <li class="breadcrumb-item {'dropdown' if not is_last else 'active'}">
                    {'' if is_last else f'<a href="/{crumb_path}">{html.escape(name)}</a>'}
                    {'' if is_last else f'''
                    <div class="dropdown-menu">
                        <a class="dropdown-item" href="/{crumb_path}">Open</a>
                        <a class="dropdown-item" href="#" onclick="deleteItem('/{crumb_path}')">Delete</a>
                        <a class="dropdown-item" href="#" onclick="renameItem('/{crumb_path}', '{html.escape(name)}')">Rename</a>
                    </div>
                    '''}
                    {html.escape(name) if is_last else ''}
                </li>
            """
        html_content += f"""
            </ol>
        </nav>
        <div class="card mb-4">
            <div class="card-body">
                <h5 class="card-title">Current directory: <code>/{html.escape(rel_path)}</code></h5>
                <p class="card-text">Server running on port {PORT}</p>
                <p class="card-text">Root directory: <code>{html.escape(DIRECTORY)}</code></p>
                <div class="d-flex gap-2 mb-3">
                    <form id="uploadForm" method="post" enctype="multipart/form-data" class="flex-grow-1">
                        <div class="input-group">
                            <input type="file" class="form-control" name="file" multiple>
                            <button class="btn btn-primary" type="submit">
                                <i class="bi bi-upload"></i> Upload
                            </button>
                        </div>
                        <small class="text-muted">You can select multiple files</small>
                    </form>
                    <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#createFolderModal">
                        <i class="bi bi-folder-plus"></i> New Folder
                    </button>
                </div>
                <div class="mb-3">
                    <input type="text" id="searchInput" class="form-control" placeholder="Search files...">
                </div>
            </div>
        </div>
        <div class="modal fade" id="createFolderModal" tabindex="-1" aria-labelledby="createFolderModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="createFolderModalLabel">Create New Folder</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <form id="createFolderForm" method="post">
                        <div class="modal-body">
                            <div class="mb-3">
                                <label for="folderName" class="form-label">Folder Name</label>
                                <input type="text" class="form-control" id="folderName" name="folder_name" required>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-primary">Create</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        <div class="modal fade" id="qrCodeModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-sm">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Scan QR Code</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body text-center">
                        <img src="data:image/png;base64,{qr_base64}" alt="QR Code">
                        <p class="mt-2">Scan to access this directory</p>
                    </div>
                </div>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-hover">
                <thead class="table-dark">
                    <tr>
                        <th class="sortable" onclick="sortTable(0)">Name ▲▼</th>
                        <th class="sortable" onclick="sortTable(1)">Size ▲▼</th>
                        <th class="sortable" onclick="sortTable(2)">Modified ▲▼</th>
                        <th class="actions-column">Actions</th>
                    </tr>
                </thead>
                <tbody>
        """
        if rel_path:
            parent_path = os.path.dirname(rel_path)
            if parent_path == ".":
                parent_path = ""
            html_content += f"""
                    <tr>
                        <td colspan="4"><a href="/{parent_path}" class="folder-link">
                            <i class="bi bi-arrow-left-circle file-icon"></i>
                            Go up
                            </a>
                        </td>
                    </tr>
            """
        for name in items:
            full_path = os.path.join(path, name)
            try:
                display_name = html.escape(name)
                is_dir = os.path.isdir(full_path)
                if is_dir:
                    size = "-"
                else:
                    try:
                        size = os.path.getsize(full_path)
                    except OSError:
                        size = 0
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime('%Y-%m-%d %H:%M:%S')
                except OSError:
                    mtime = "Unknown"
                if is_dir:
                    icon = '<i class="bi bi-folder-fill text-warning file-icon"></i>'
                    display_name = f'<a href="{urllib.parse.quote(name)}/" class="folder-link">{display_name}/</a>'
                else:
                    icon = '<i class="bi bi-file-earmark file-icon"></i>'
                    display_name = f'<a href="{urllib.parse.quote(name)}" class="file-link">{display_name}</a>'
                item_path = f"{current_dir}{urllib.parse.quote(name)}".replace('//', '/')
                if is_dir:
                    item_path += '/'
                actions = f"""
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-danger" onclick="deleteItem('{item_path}')" title="Delete">
                        <i class="bi bi-trash"></i>
                    </button>
                    <button class="btn btn-outline-primary" onclick="renameItem('{item_path}', '{html.escape(name)}')" title="Rename">
                        <i class="bi bi-pencil"></i>
                    </button>
                </div>
                """
                html_content += f"""
                        <tr>
                            <td>{icon}{display_name}</td>
                            <td>{self.format_size(size)}</td>
                            <td>{mtime}</td>
                            <td>{actions}</td>
                        </tr>
                """
            except Exception as e:
                logging.error(f"Error processing {name}: {e}")
                continue
        html_content += """
                </tbody>
            </table>
        </div>
        <footer class="mt-5 text-center text-muted">
            <div class="mb-2">
                <button class="btn btn-sm btn-outline-info" data-bs-toggle="modal" data-bs-target="#qrCodeModal">
                    <i class="bi bi-qr-code"></i> Show QR Code
                </button>
            </div>
            <p>Termux HTTP File Server</p>
            <p class="small">
                {time.strftime('%Y-%m-%d %H:%M:%S')} |
                Uptime: <span id="uptime">{uptime_str}</span> |
                Files: {len(items)}
            </p>
        </footer>
    </div>
    <div id="imgPreview" class="img-preview"></div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        console.log('JavaScript loaded');
        function testButtons() {
            console.log('Testing button functions: deleteItem and renameItem are defined');
        }
        testButtons();
        let sessionId = '';
        let csrfToken = '';
        fetch('/_get_csrf', {
            headers: {
                'Authorization': 'Basic ' + btoa('test:test')
            }
        }).then(res => {
            console.log('CSRF fetch status:', res.status);
            if (!res.ok) {
                throw new Error('Failed to fetch CSRF token: ' + res.statusText);
            }
            return res.json();
        }).then(data => {
            sessionId = data.session_id;
            csrfToken = data.csrf_token;
            console.log('CSRF Token fetched:', sessionId, csrfToken);
        }).catch(err => {
            console.error('CSRF token error:', err);
            alert('Failed to initialize session. Please refresh the page.');
        });
        function updateUptime() {
            const start = new Date("{SERVER_START_TIME.strftime('%Y-%m-%d %H:%M:%S')}");
            const now = new Date();
            const diff = now - start;
            const days = Math.floor(diff / (1000 * 60 * 60 * 24));
            const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
            const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
            document.getElementById('uptime').textContent = `${days}d ${hours}h ${mins}m`;
        }
        setInterval(updateUptime, 60000);
        document.getElementById('searchInput').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            document.querySelectorAll('tbody tr').forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });
        function sortTable(columnIndex) {
            const table = document.querySelector('table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            if (rows[0].querySelector('a[href*=".."]')) {
                rows.shift();
            }
            rows.sort((a, b) => {
                const aVal = a.cells[columnIndex].textContent;
                const bVal = b.cells[columnIndex].textContent;
                if (columnIndex === 1) {
                    if (aVal === '-' || bVal === '-') return aVal === '-' ? 1 : -1;
                    const aSize = parseFloat(aVal.split(' ')[0]);
                    const bSize = parseFloat(bVal.split(' ')[0]);
                    return aSize - bSize;
                }
                if (columnIndex === 2) {
                    return new Date(aVal) - new Date(bVal);
                }
                return aVal.localeCompare(bVal);
            });
            const firstRow = table.querySelector('tbody tr:first-child');
            if (firstRow && firstRow.querySelector('a[href*=".."]')) {
                rows.unshift(firstRow);
            }
            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
        }
        function deleteItem(path) {
            console.log('Deleting item:', path);
            if (!sessionId || !csrfToken) {
                alert('Session not initialized. Please refresh the page.');
                return;
            }
            if (confirm('Are you sure you want to delete "' + decodeURIComponent(path.split('/').pop()) + '"?')) {
                fetch(path, {
                    method: 'DELETE',
                    headers: {
                        'X-Session-ID': sessionId,
                        'X-CSRF-Token': csrfToken,
                        'Authorization': 'Basic ' + btoa('test:test')
                    }
                })
                .then(response => {
                    console.log('Delete response status:', response.status);
                    if (response.ok) {
                        location.reload();
                    } else {
                        return response.text().then(text => {
                            throw new Error(text || 'Failed to delete item');
                        });
                    }
                })
                .catch(error => {
                    console.error('Delete error:', error);
                    alert('Error: ' + error.message);
                });
            }
        }
        function renameItem(path, currentName) {
            console.log('Renaming item:', path, 'to new name');
            if (!sessionId || !csrfToken) {
                alert('Session not initialized. Please refresh the page.');
                return;
            }
            const newName = prompt("Enter new name:", currentName);
            if (newName && newName !== currentName) {
                fetch('/_rename', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Session-ID': sessionId,
                        'X-CSRF-Token': csrfToken,
                        'Authorization': 'Basic ' + btoa('test:test')
                    },
                    body: JSON.stringify({
                        old_path: path,
                        new_name: newName
                    })
                })
                .then(response => {
                    console.log('Rename response status:', response.status);
                    if (response.ok) {
                        location.reload();
                    } else {
                        return response.text().then(text => {
                            throw new Error(text || 'Failed to rename item');
                        });
                    }
                })
                .catch(error => {
                    console.error('Rename error:', error);
                    alert('Error: ' + error.message);
                });
            }
        }
        document.getElementById('createFolderForm').addEventListener('submit', function(e) {
            e.preventDefault();
            if (!sessionId || !csrfToken) {
                alert('Session not initialized. Please refresh the page.');
                return;
            }
            const folderName = document.getElementById('folderName').value.trim();
            if (!folderName) return;
            fetch(window.location.pathname, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Request-Type': 'create-folder',
                    'X-Session-ID': sessionId,
                    'X-CSRF-Token': csrfToken,
                    'Authorization': 'Basic ' + btoa('test:test')
                },
                body: `folder_name=${encodeURIComponent(folderName)}`
            })
            .then(response => {
                console.log('Create folder response status:', response.status);
                if (response.redirected) {
                    window.location.href = response.url;
                } else {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to create folder');
                    });
                }
            })
            .catch(error => {
                console.error('Create folder error:', error);
                alert('Error: ' + error.message);
            });
            const modal = bootstrap.Modal.getInstance(document.getElementById('createFolderModal'));
            modal.hide();
        });
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            if (!sessionId || !csrfToken) {
                alert('Session not initialized. Please refresh the page.');
                return;
            }
            const formData = new FormData(this);
            fetch(window.location.pathname, {
                method: 'POST',
                headers: {
                    'X-Session-ID': sessionId,
                    'X-CSRF-Token': csrfToken,
                    'Authorization': 'Basic ' + btoa('test:test')
                },
                body: formData
            })
            .then(response => {
                console.log('Upload response status:', response.status);
                if (response.redirected) {
                    location.reload();
                } else {
                    return response.text().then(text => {
                        throw new Error(text || 'Failed to upload file');
                    });
                }
            })
            .catch(error => {
                console.error('Upload error:', error);
                alert('Error: ' + error.message);
            });
        });
        document.querySelectorAll('a.file-link[href$=".jpg"], a.file-link[href$=".png"], a.file-link[href$=".gif"], a.file-link[href$=".jpeg"], a.file-link[href$=".webp"]').forEach(link => {
            link.addEventListener('mouseenter', function() {
                const imgPreview = document.getElementById('imgPreview');
                imgPreview.src = this.href;
                imgPreview.style.display = 'block';
                const rect = this.getBoundingClientRect();
                imgPreview.style.left = `${rect.right + 10}px`;
                imgPreview.style.top = `${rect.top}px`;
                this.addEventListener('mouseleave', () => {
                    imgPreview.style.display = 'none';
                });
            });
        });
    </script>
</body>
</html>
        """
        return html_content

    def format_size(self, size):
        if size == "-":
            return size
        try:
            size = float(size)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        except (ValueError, TypeError):
            return "N/A"

    def send_error_page(self, status_code, message=None, details=None):
        error_pages = {
            403: {
                "title": "Forbidden",
                "icon": "bi-lock-fill",
                "icon_class": "text-danger",
                "default_msg": "You don't have permission to access this resource."
            },
            404: {
                "title": "Not Found",
                "icon": "bi-exclamation-triangle-fill",
                "icon_class": "text-warning",
                "default_msg": "The requested resource was not found."
            },
            500: {
                "title": "Server Error",
                "icon": "bi-bug-fill",
                "icon_class": "text-danger",
                "default_msg": "Something went wrong on our server."
            }
        }
        error_info = error_pages.get(status_code, {
            "title": f"{status_code} Error",
            "icon": "bi-question-circle-fill",
            "icon_class": "text-info",
            "default_msg": "An error occurred."
        })
        error_details = f'<div class="error-details">{html.escape(str(details))}</div>' if details else ''
        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{status_code} - Termux File Server</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {{
            --bs-body-bg: #212529;
            --bs-body-color: #f8f9fa;
            --bs-dark-bg: #1a1e21;
            --bs-dark-border: #2c3034;
            --bs-light-text: #f8f9fa;
            --bs-primary-text: #6ea8fe;
            --bs-danger: #dc3545;
            --bs-warning: #ffc107;
        }}
        body {{
            background-color: var(--bs-body-bg);
            color: var(--bs-body-color);
            padding: 20px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}
        .container {{
            max-width: 800px;
            margin: 50px auto;
            padding: 30px;
            background-color: var(--bs-dark-bg);
            border-radius: 8px;
            border: 1px solid var(--bs-dark-border);
        }}
        .error-icon {{
            font-size: 5rem;
            margin-bottom: 20px;
        }}
        .error-title {{
            font-size: 2.5rem;
            margin-bottom: 15px;
        }}
        .error-details {{
            background-color: rgba(0, 0, 0, 0.2);
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            font-family: monospace;
            white-space: pre-wrap;
        }}
        .btn-home {{
            margin-top: 20px;
        }}
        .text-danger {{
            color: var(--bs-danger);
        }}
        .text-warning {{
            color: var(--bs-warning);
        }}
        .text-info {{
            color: var(--bs-primary-text);
        }}
    </style>
</head>
<body data-bs-theme="dark">
    <div class="container text-center">
        <div class="error-icon {error_info['icon_class']}">
            <i class="bi {error_info['icon']}"></i>
        </div>
        <h1 class="error-title">{status_code} - {error_info['title']}</h1>
        <p class="lead">{message or error_info['default_msg']}</p>
        {error_details}
        <a href="/" class="btn btn-primary btn-home">
            <i class="bi bi-house-door"></i> Return to Home
        </a>
        <footer class="mt-5 text-center text-muted">
            <p></p>
            <p class="small">{time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>
        """.encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

def generate_token(path):
    if not TOKENS_ENABLED:
        return None
    token = secrets.token_urlsafe(32)
    expiry = time.time() + TOKEN_DURATION
    TOKENS[token] = {
        'path': os.path.abspath(path),
        'expiry': expiry
    }
    logging.info(f"Generated token for path: {path}")
    return token

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) != 0

def run_server():
    os.chdir(DIRECTORY)
    for port in range(PORT, PORT + 10):
        if check_port(port):
            handler = partial(CustomHTTPRequestHandler)
            with socketserver.TCPServer(("", port), handler) as httpd:
                logging.info(f"Server started on port {port}")
                print(f"Server running on port {port}")
                print(f"Access at: http://localhost:{port}")
                print(f"Root directory: {DIRECTORY}")
                if AUTH_ENABLED:
                    print(f"Authentication enabled - Username: {USERNAME}")
                if TOKENS_ENABLED:
                    print(f"Token sharing enabled - Token duration: {TOKEN_DURATION} seconds")
                print("Press Ctrl+C to stop the server")
                httpd.serve_forever()
                break
        else:
            print(f"Port {port} is busy, trying next...")
    else:
        raise OSError("No available ports found")

if __name__ == "__main__":
    run_server()
