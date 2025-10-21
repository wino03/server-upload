from flask import Flask, request
import bcrypt
import os
import base64
 
app = Flask(__name__)
 
UPLOAD_FOLDER = '/app/provisioning'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
 
# --- User database (contoh hardcoded, bisa pakai DB nanti)
USER_DB = {
    "admin": bcrypt.hashpw(b"supersecret", bcrypt.gensalt()).decode()
}
 
def check_auth(auth_header):
    """Validasi Basic Auth"""
    if not auth_header or not auth_header.startswith("Basic "):
        return False
 
    encoded = auth_header.split(" ")[1]
    decoded = base64.b64decode(encoded).decode("utf-8")
    username, password = decoded.split(":", 1)
 
    hashed = USER_DB.get(username)
    if not hashed:
        return False
 
    return bcrypt.checkpw(password.encode(), hashed.encode())
 
@app.before_request
def require_auth():
    if request.path == "/app":
        return  # allow health check
    if not check_auth(request.headers.get("Authorization")):
        return {"error": "Unauthorized"}, 401, {"WWW-Authenticate": 'Basic realm="Login Required"'}
 
@app.route('/app/provisioning', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file:
        return {'error': 'No file uploaded'}, 400
 
    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)
    return {'message': 'File uploaded', 'filename': file.filename}
 
@app.route('/app')
def home():
    return {'status': 'OK', 'message': 'Flask HTTPS server with auth'}
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)