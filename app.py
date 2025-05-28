import os
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from PIL import Image
import io
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Configuration
UPLOAD_FOLDER = '/tmp/uploads' if os.environ.get('VERCEL') else 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_image(image_data, password):
    # Generate a random salt and nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Initialize AESGCM
    aesgcm = AESGCM(key)
    
    # Encrypt the image data
    ciphertext = aesgcm.encrypt(nonce, image_data, None)
    
    # Combine salt, nonce, and ciphertext
    encrypted_data = salt + nonce + ciphertext
    return encrypted_data

def decrypt_image(encrypted_data, password):
    # Extract salt, nonce, and ciphertext
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    
    # Derive key from password
    key = derive_key(password, salt)
    
    # Initialize AESGCM
    aesgcm = AESGCM(key)
    
    # Decrypt the data
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data
    except Exception as e:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form.get('password')
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if not password:
        flash('Password is required')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Read image data
        image_data = file.read()
        
        # Encrypt the image
        encrypted_data = encrypt_image(image_data, password)
        
        # Save encrypted data to a file
        encrypted_filename = secure_filename(file.filename) + '.encrypted'
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        return send_file(
            encrypted_path,
            as_attachment=True,
            download_name=encrypted_filename
        )
    
    flash('Invalid file type')
    return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    password = request.form.get('password')
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if not password:
        flash('Password is required')
        return redirect(url_for('index'))
    
    if file:
        # Read encrypted data
        encrypted_data = file.read()
        
        # Decrypt the data
        decrypted_data = decrypt_image(encrypted_data, password)
        
        if decrypted_data is None:
            flash('Invalid password or corrupted file')
            return redirect(url_for('index'))
        
        # Create a BytesIO object from the decrypted data
        image_io = io.BytesIO(decrypted_data)
        
        # Verify it's a valid image
        try:
            Image.open(image_io)
            image_io.seek(0)
        except:
            flash('Decrypted data is not a valid image')
            return redirect(url_for('index'))
        
        # Generate filename for decrypted image
        decrypted_filename = secure_filename(file.filename).replace('.encrypted', '')
        
        return send_file(
            image_io,
            mimetype='image/jpeg',
            as_attachment=True,
            download_name=decrypted_filename
        )
    
    flash('Invalid file')
    return redirect(url_for('index'))

# For local development
if __name__ == '__main__':
    app.run(debug=True) 