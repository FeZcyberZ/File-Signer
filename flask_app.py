import os
import logging
from logging.handlers import RotatingFileHandler
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask, render_template, request, send_file, flash, redirect
from werkzeug.utils import secure_filename
import tempfile

# -------------------- Flask App Setup -------------------- #
app = Flask(__name__)
app.secret_key = os.urandom(32)  # Secure random session key (NIST SP 800-57)
PRIVATE_KEY_PASSPHRASE = os.environ["PRIVATE_KEY_PASSPHRASE"].encode()


# -------------------- Directory Setup -------------------- #
BASE_DIR = os.getcwd()
LOG_DIR = os.path.join(BASE_DIR, "logs")
KEYS_DIR = os.path.join(BASE_DIR, "keys")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# -------------------- Logging Config (STIG APP3550 compliant) -------------------- #
log_file = os.path.join(LOG_DIR, "flask_app.log")
handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(name)s [%(threadName)s]: %(message)s"
)
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# -------------------- Key Paths -------------------- #
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

# -------------------- Key Management -------------------- #
def generate_keys():
    """Generate and securely store ECDSA key pair."""
    try:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(PRIVATE_KEY_PASSPHRASE)
                )
            )
        os.chmod(PRIVATE_KEY_PATH, 0o600)

        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        os.chmod(PUBLIC_KEY_PATH, 0o644)

        app.logger.info(" Keys generated successfully .")
        return private_key, public_key
    except Exception as e:
        app.logger.error(f"Key generation failed: {e}")
        raise

def load_keys():
    """Load existing keys, or generate new ones if missing."""
    try:
        if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
            with open(PRIVATE_KEY_PATH, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=PRIVATE_KEY_PASSPHRASE,
                    backend=default_backend()
                )
            with open(PUBLIC_KEY_PATH, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            app.logger.info("Keys loaded from disk.")
        else:
            app.logger.warning("Keys not found — generating new ones.")
            private_key, public_key = generate_keys()
        return private_key, public_key
    except Exception as e:
        app.logger.error(f"Key loading failed: {e}")
        raise

# Load or create keys at startup
private_key, public_key = load_keys()

# -------------------- Routes -------------------- #
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/sign", methods=["GET", "POST"])
def sign():
    if request.method == "POST":
        file = request.files.get("file")
        if not file:
            flash("No file uploaded", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_data = file.read()

        # Use a temporary file to prevent race conditions
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as tmp_file:
            sig_filename = tmp_file.name
            try:
                signature = private_key.sign(file_data, ec.ECDSA(hashes.SHA256()))
                tmp_file.write(signature)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
                app.logger.info(f"File '{filename}' signed successfully.")
                return send_file(sig_filename, as_attachment=True, download_name=f"{filename}.sig")
            except Exception as e:
                app.logger.error(f"Signing failed: {e}")
                flash("Error during signing.", "danger")
            finally:
                if os.path.exists(sig_filename):
                    os.remove(sig_filename)
        return redirect(request.url)

    return render_template("sign.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        uploaded_file = request.files.get("file")
        signature_file = request.files.get("signature")

        if not uploaded_file or not signature_file:
            flash("File or signature missing", "danger")
            return redirect(request.url)

        file_data = uploaded_file.read()
        signature = signature_file.read()

        try:
            public_key.verify(signature, file_data, ec.ECDSA(hashes.SHA256()))
            flash("Signature is VALID", "success")
            app.logger.info("Signature verification succeeded.")
        except Exception as e:
            flash("Signature is INVALID", "danger")
            app.logger.warning(f"Signature verification failed: {e}")

        return redirect(request.url)

    return render_template("verify.html")

# -------------------- Run Flask -------------------- #
if __name__ == "__main__":
    # debug=False ensures logs are not duplicated and stack traces are not exposed
    app.run(host="0.0.0.0", port=5000, debug=False)
