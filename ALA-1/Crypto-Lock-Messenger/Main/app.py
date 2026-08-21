from flask import Flask, render_template, request
import base64
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)


# ============================================================
# RSA KEY GENERATION
# RSA is ASYMMETRIC encryption.
# It uses a PUBLIC KEY and a PRIVATE KEY.
# ============================================================

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()


# ============================================================
# AES ENCRYPTION
# AES is SYMMETRIC encryption.
# The SAME AES key is used for encryption and decryption.
# ============================================================

def encrypt_message(message):
    # Generate a random 256-bit AES key
    aes_key = AESGCM.generate_key(bit_length=256)

    # Create AES-GCM object
    aes = AESGCM(aes_key)

    # Generate a random nonce
    nonce = os.urandom(12)

    # Encrypt message using AES
    encrypted_message = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    # ========================================================
    # RSA ENCRYPTION
    # Encrypt the AES key using RECIPIENT'S PUBLIC KEY.
    # ========================================================

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return (
        base64.b64encode(encrypted_message).decode("utf-8"),
        base64.b64encode(nonce).decode("utf-8"),
        base64.b64encode(encrypted_aes_key).decode("utf-8")
    )


# ============================================================
# RSA DECRYPTION + AES DECRYPTION
# ============================================================

def decrypt_message(encrypted_message, nonce, encrypted_aes_key):

    # Decode Base64 values
    encrypted_message = base64.b64decode(encrypted_message)
    nonce = base64.b64decode(nonce)
    encrypted_aes_key = base64.b64decode(encrypted_aes_key)

    # ========================================================
    # RSA DECRYPTION
    # Decrypt the AES key using the RSA PRIVATE KEY.
    # ========================================================

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # ========================================================
    # AES DECRYPTION
    # SAME AES KEY is used to decrypt the message.
    # ========================================================

    aes = AESGCM(aes_key)

    decrypted_message = aes.decrypt(
        nonce,
        encrypted_message,
        None
    )

    return decrypted_message.decode("utf-8")


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():

    encrypted_message = None
    encrypted_aes_key = None
    nonce = None
    decrypted_message = None
    original_message = None
    error = None

    if request.method == "POST":

        action = request.form.get("action")

        # ====================================================
        # ENCRYPTION
        # ====================================================

        if action == "encrypt":

            original_message = request.form.get("message", "").strip()

            if not original_message:
                error = "Please enter a message."

            else:
                try:
                    (
                        encrypted_message,
                        nonce,
                        encrypted_aes_key
                    ) = encrypt_message(original_message)

                except Exception as e:
                    error = f"Encryption error: {str(e)}"

        # ====================================================
        # DECRYPTION
        # ====================================================

        elif action == "decrypt":

            encrypted_message = request.form.get(
                "encrypted_message", ""
            ).strip()

            nonce = request.form.get(
                "nonce", ""
            ).strip()

            encrypted_aes_key = request.form.get(
                "encrypted_aes_key", ""
            ).strip()

            if not encrypted_message or not nonce or not encrypted_aes_key:

                error = "Please provide all encrypted values."

            else:

                try:

                    decrypted_message = decrypt_message(
                        encrypted_message,
                        nonce,
                        encrypted_aes_key
                    )

                except Exception as e:

                    error = (
                        "Decryption failed. "
                        "Make sure the encrypted values are correct."
                    )

    return render_template(
        "index.html",
        encrypted_message=encrypted_message,
        encrypted_aes_key=encrypted_aes_key,
        nonce=nonce,
        decrypted_message=decrypted_message,
        original_message=original_message,
        error=error
    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)