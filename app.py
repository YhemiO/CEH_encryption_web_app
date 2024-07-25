from flask import Flask, request, render_template, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import logging

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.DEBUG)

def get_key(password, key_length):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length // 8,  # key_length is in bits, length in bytes
        salt=b'0000000000000000',
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json.get('data')
    password = request.json.get('password')
    algorithm = request.json.get('algorithm')
    key_length = request.json.get('key_length')

    logging.debug(f"Received encrypt request with data: {data}, password: {password}, algorithm: {algorithm}, key_length: {key_length}")

    # Check if all fields are provided
    if not all([data, password, algorithm, key_length]):
        return jsonify({'error': 'All fields are required'}), 400

    try:
        key_length = int(key_length)
    except ValueError:
        return jsonify({'error': 'Key length must be an integer'}), 400

    key = get_key(password, key_length)
    iv_length = 16 if algorithm in ['AES', 'RC4'] else 8
    iv = os.urandom(iv_length)

    try:
        if algorithm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        elif algorithm == 'DES':
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        elif algorithm == 'Blowfish':
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        elif algorithm == 'RC4':
            cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
        else:
            return jsonify({'error': 'Invalid algorithm selected'}), 400

        encryptor = cipher.encryptor()
        ct = encryptor.update(data.encode()) + encryptor.finalize()
        result = {
            'ciphertext': urlsafe_b64encode(ct).decode(),
            'iv': urlsafe_b64encode(iv).decode()
        }
        if algorithm == 'AES':
            result['tag'] = urlsafe_b64encode(encryptor.tag).decode()
        logging.debug(f"Encryption successful, result: {result}")
        return jsonify(result)
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json.get('data')
    password = request.json.get('password')
    iv = request.json.get('iv')
    tag = request.json.get('tag')
    algorithm = request.json.get('algorithm')
    key_length = request.json.get('key_length')

    logging.debug(f"Received decrypt request with data: {data}, password: {password}, iv: {iv}, tag: {tag}, algorithm: {algorithm}, key_length: {key_length}")

    # Check if all fields are provided
    if not all([data, password, iv, algorithm, key_length]):
        return jsonify({'error': 'All fields are required'}), 400

    try:
        iv = urlsafe_b64decode(iv)
        tag = urlsafe_b64decode(tag) if tag else None
        key_length = int(key_length)
    except Exception as e:
        logging.error(f"Invalid input format: {e}")
        return jsonify({'error': 'Invalid input format'}), 400

    key = get_key(password, key_length)

    try:
        if algorithm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        elif algorithm == 'DES':
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
        elif algorithm == 'Blowfish':
            cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        elif algorithm == 'RC4':
            cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
        else:
            return jsonify({'error': 'Invalid algorithm selected'}), 400

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(urlsafe_b64decode(data)) + decryptor.finalize()
        result = {'plaintext': plaintext.decode()}
        logging.debug(f"Decryption successful, result: {result}")
        return jsonify(result)
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
