from flask import Flask, request
import bcrypt, os, base64, re, logging
from logging.handlers import RotatingFileHandler
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = '/uploads'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# === Setup rotating logging ===
LOG_FILE = '/app/upload.log'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5  # Simpan 5 log lama (upload.log.1, upload.log.2, ...)

log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
log_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT
)
log_handler.setFormatter(log_formatter)

logging.getLogger().setLevel(logging.INFO)
logging.getLogger().addHandler(log_handler)

# Tampilkan juga ke console Docker logs
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logging.getLogger().addHandler(console_handler)

# === Load environment variables ===
USERNAME = os.getenv("UPLOAD_USER")
PASSWORD_ENV = os.getenv("UPLOAD_PASS")

# === Auto-detect apakah password sudah bcrypt hash ===
BCRYPT_PATTERN = re.compile(r"^\$2[aby]\$.{56}$")

if BCRYPT_PATTERN.match(PASSWORD_ENV):
    HASHED_PASSWORD = PASSWORD_ENV
    logging.info("Detected hashed password (bcrypt). Using as-is.")
else:
    HASHED_PASSWORD = bcrypt.hashpw(PASSWORD_ENV.encode(), bcrypt.gensalt()).decode()
    logging.info("Plaintext password detected. Auto-hashed for security.")

def check_auth(auth_header):
    """Validasi Basic Auth"""
    if not auth_header or not auth_header.startswith("Basic "):
        return False

    try:
        encoded = auth_header.split(" ")[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return False

    if username != USERNAME:
        return False

    return bcrypt.checkpw(password.encode(), HASHED_PASSWORD.encode())

@app.before_request
def require_auth():
    """Wajib autentikasi untuk semua endpoint kecuali root (/)"""
    if request.path == "/":
        return  # Health check
    auth_header = request.headers.get("Authorization")
    if not check_auth(auth_header):
        client_ip = request.remote_addr
        logging.warning(f"Unauthorized access attempt from {client_ip}")
        return (
            {"error": "Unauthorized"},
            401,
            {"WWW-Authenticate": 'Basic realm="Login Required"'},
        )

@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload file ke folder /uploads"""
    file = request.files.get('file')
    if not file:
        return {'error': 'No file uploaded'}, 400

    filename = secure_filename(file.filename)
    path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(path)

    # Logging informasi upload
    client_ip = request.remote_addr
    user = USERNAME
    filesize = os.path.getsize(path)
    logging.info(f"File uploaded by '{user}' from {client_ip}: {filename} ({filesize} bytes)")

    return {'message': 'File uploaded successfully', 'filename': filename}

@app.route('/')
def home():
    """Health check"""
    return {'status': 'OK', 'message': 'This Server is Manage by The Infratools Team'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
