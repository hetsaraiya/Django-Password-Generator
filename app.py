from flask import Flask, request, jsonify, render_template
import hashlib
import base64
import os

app = Flask(__name__)

def hash_password(password, salt=None, iterations=390000):
    if salt is None:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip('=')

    dk = hashlib.pbkdf2_hmac(
        'sha256',  # Hashing algorithm
        password.encode('utf-8'),  # Convert the password to bytes
        salt.encode('utf-8'),  # Convert the salt to bytes
        iterations  # Number of iterations
    )
    hashed_password = base64.urlsafe_b64encode(dk).decode('utf-8').rstrip('=')

    return f"pbkdf2_sha256${iterations}${salt}${hashed_password}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/hash', methods=['POST'])
def hash_endpoint():
    data = request.json
    password = data['password']
    salt = data.get('salt')
    iterations = data.get('iterations', 390000)
    hashed_password = hash_password(password, salt, iterations)
    return jsonify({'hashed_password': hashed_password})

if __name__ == '__main__':
    app.run(debug=True)
