from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import bcrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

app = Flask(__name__)
app.secret_key = "supersecretkey"

# --- CONFIG ---
UPLOAD_FOLDER = "uploads"
KEY_FOLDER = "keys"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
USERS_FILE = "users.json"

app.config.update(UPLOAD_FOLDER=UPLOAD_FOLDER, MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

# --- LOAD USERS ---
if os.path.exists(USERS_FILE):
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    users = {u: v.encode() for u, v in users.items()}  # convert back to bytes
else:
    users = {}

# --- SAVE USERS ---
def save_users():
    users_str = {u: v.decode() for u, v in users.items()}
    with open(USERS_FILE, "w") as f:
        json.dump(users_str, f)

# --- AES HELPERS ---
def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data))
    with open(file_path, 'wb') as f:
        f.write(cipher.iv + ct_bytes)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ct = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(ct).rstrip(b"\0")
    return data

def generate_key():
    return get_random_bytes(32)  # AES-256

def save_user_key(username, key):
    with open(os.path.join(KEY_FOLDER, f"{username}.key"), "wb") as f:
        f.write(key)

def load_user_key(username):
    return open(os.path.join(KEY_FOLDER, f"{username}.key"), "rb").read()

# --- UTILITIES ---
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            flash("⚠️ Please log in first")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# --- ROUTES ---

@app.route("/upload_success/<filename>")
@login_required
def upload_success(filename):
    return render_template("success.html", filename=filename)


@app.route("/")
def index():
    return render_template("signup.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()

        if username in users:
            flash("⚠️ Username already exists")
            return redirect(url_for("signup"))

        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        users[username] = hashed_pw
        save_users()  # persist user

        # Generate AES key and save
        key = generate_key()
        save_user_key(username, key)

        flash("✅ Signup successful! Please log in")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()

        if username in users and bcrypt.checkpw(password, users[username]):
            session["username"] = username
            flash("✅  File uploaded & encrypted successfully")
            return redirect(url_for("upload_file"))  # go to upload after login
        else:
            flash("❌ Invalid credentials")
            return redirect(url_for("login"))

    # GET request → show login form
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.pop("username", None)  # remove the user from session
    flash("👋 Logged out successfully")
    return redirect(url_for("login"))  # send them back to login page

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    os.makedirs(user_folder, exist_ok=True)

    if request.method == "POST":
        if "file" not in request.files:
            flash("❌ No file part")
            return redirect(url_for("upload_file"))

        file = request.files["file"]
        if file.filename == "":
            flash("❌ No file selected")
            return redirect(url_for("upload_file"))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(user_folder, filename)
            file.save(file_path)

            # Encrypt the uploaded file
            key = load_user_key(session["username"])
            encrypt_file(file_path, key)

            # Flash success message and redirect to success page
            flash("✅ File uploaded & encrypted successfully")
            return redirect(url_for("upload_success", filename=filename))
        else:
            flash("❌ File type not allowed")
            return redirect(url_for("upload_file"))

    # GET request → show upload form
    return render_template("upload.html")

@app.route("/files")
@login_required
def list_files():
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    os.makedirs(user_folder, exist_ok=True)
    files = os.listdir(user_folder)
    return render_template("files.html", files=files)

@app.route("/download/<filename>")
@login_required
def download_file(filename):
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    file_path = os.path.join(user_folder, filename)
    key = load_user_key(session["username"])
    data = decrypt_file(file_path, key)
    return data, 200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': f'attachment; filename={filename}'
    }

@app.route("/delete/<filename>")
@login_required
def delete_file(filename):
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], session["username"])
    file_path = os.path.join(user_folder, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        flash("🗑️ File deleted")
    else:
        flash("❌ File not found")

    return redirect(url_for("list_files"))

if __name__ == "__main__":
    app.run(debug=True)
