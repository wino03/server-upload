from flask import Flask, request
import bcrypt, os, base64, re
from werkzeug.utils import secure_filename
 
app = Flask(__name__)
 
UPLOAD_FOLDER = '/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
 
# === Load environment variables ===
USERNAME = os.getenv("UPLOAD_USER")
PASSWORD_ENV = os.getenv("UPLOAD_PASS")

# Format bcrypt hash: $2b$<cost>$<22chars><31chars>
BCRYPT_PATTERN = re.compile(r"^\$2[aby]\$.{56}$")
 
if BCRYPT_PATTERN.match(PASSWORD_ENV):
    HASHED_PASSWORD = PASSWORD_ENV
    print("Detected hashed password (bcrypt). Using as-is.")
else:
    HASHED_PASSWORD = bcrypt.hashpw(PASSWORD_ENV.encode(), bcrypt.gensalt()).decode()
    print("Plaintext password detected. Auto-hashed for security.")
 
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
    if not check_auth(request.headers.get("Authorization")):
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
    return {'message': 'File uploaded successfully', 'filename': filename}
 
@app.route('/')
def home():
    """Health check"""
    return {'status': 'OK', 'message': 'Flask HTTPS server with auto-hash detection'}
 
if __name__ == '__main__':
    context = ('/app/ssl/server.crt', '/app/ssl/server.key')
    app.run(host='0.0.0.0', port=5000, ssl_context=context)