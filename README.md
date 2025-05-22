# Image Encryption Tool

A secure web application for encrypting and decrypting images using AES-256-GCM encryption. This tool provides a user-friendly interface to protect your images with password-based encryption.

## Features

- Secure AES-256-GCM encryption
- Password-based key derivation using PBKDF2
- Support for common image formats (JPG, PNG, GIF)
- Modern and responsive web interface
- Easy-to-use encryption and decryption process

## Requirements

- Python 3.7 or higher
- Flask
- cryptography
- Pillow
- python-dotenv

## Installation

1. Clone this repository:

```bash
git clone <repository-url>
cd <repository-name>
```

2. Create a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:

```bash
pip install -r requirements.txt
```

## Usage

1. Start the Flask application:

```bash
python app.py
```

2. Open your web browser and navigate to:

```
http://localhost:5000
```

3. To encrypt an image:

   - Click the "Encrypt" tab
   - Select an image file
   - Enter a password
   - Click "Encrypt Image"
   - The encrypted file will be downloaded automatically

4. To decrypt an image:
   - Click the "Decrypt" tab
   - Select the encrypted file
   - Enter the same password used for encryption
   - Click "Decrypt Image"
   - The decrypted image will be downloaded automatically

## Security Features

- Uses AES-256-GCM for authenticated encryption
- Implements PBKDF2 for secure key derivation
- Generates unique salt and nonce for each encryption
- Validates decrypted data integrity
- Secure password handling

## Notes

- Keep your password safe! If you lose it, you won't be able to decrypt your images.
- The encrypted files will have a `.encrypted` extension.
- Make sure to use strong passwords for better security.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
