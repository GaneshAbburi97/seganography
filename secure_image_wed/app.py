from flask import Flask, render_template, request, send_file
from PIL import Image
from cryptography.fernet import Fernet
import base64, hashlib, os, uuid

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "outputs")
ALLOWED_EXTENSIONS = {"png"}
DELIMITER = "1111111111111110"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# ---------- Utility Functions ----------

def derive_key(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

def to_binary(data):
    return ''.join(format(byte, '08b') for byte in data)

def is_allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------- Routes ----------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    image = request.files.get("image")
    message = request.form.get("message", "")
    password = request.form.get("password", "")

    if not image or image.filename == "":
        return "No image selected", 400
    if not is_allowed_file(image.filename):
        return "Only PNG images are supported", 400
    if not message or not password:
        return "Message and password are required", 400

    filename = f"{uuid.uuid4()}.png"
    image_path = os.path.join(UPLOAD_FOLDER, filename)
    image.save(image_path)

    key = derive_key(password)
    cipher = Fernet(key)
    encrypted_msg = cipher.encrypt(message.encode())

    binary_data = to_binary(encrypted_msg) + DELIMITER

    img = Image.open(image_path).convert("RGB")
    max_bits = img.width * img.height
    if len(binary_data) > max_bits:
        os.remove(image_path)
        return "Message too large for the selected image", 400
    pixels = img.load()

    data_index = 0
    for y in range(img.height):
        for x in range(img.width):
            if data_index < len(binary_data):
                r, g, b = pixels[x, y]
                r = int(format(r, '08b')[:-1] + binary_data[data_index], 2)
                pixels[x, y] = (r, g, b)
                data_index += 1

    output_path = os.path.join(OUTPUT_FOLDER, filename)
    img.save(output_path)

    return send_file(output_path, as_attachment=True)

@app.route("/decrypt")
def decrypt_page():
    return render_template("decrypt.html")

@app.route("/decrypt", methods=["POST"])
def decrypt():
    image = request.files.get("image")
    password = request.form.get("password", "")

    if not image or image.filename == "":
        return "No image selected", 400
    if not is_allowed_file(image.filename):
        return "Only PNG images are supported", 400
    if not password:
        return "Password is required", 400

    img = Image.open(image).convert("RGB")
    pixels = img.load()

    binary_data = ""
    found = False

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            binary_data += format(r, '08b')[-1]
            if DELIMITER in binary_data:
                found = True
                break
        if found:
            break

    if not found:
        return "No hidden data found"

    hidden_bits = binary_data.split(DELIMITER)[0]
    if not hidden_bits or len(hidden_bits) % 8 != 0:
        return "Hidden data is corrupted", 400
    data_bytes = int(hidden_bits, 2).to_bytes(len(hidden_bits) // 8, byteorder='big')

    try:
        key = derive_key(password)
        cipher = Fernet(key)
        message = cipher.decrypt(data_bytes).decode()
        return f"<h2>Decrypted Message:</h2><p>{message}</p>"
    except:
        return "Wrong password or corrupted image"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
