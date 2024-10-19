import socket
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import time

# Конфігурація клієнта
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432
SECRET_KEY = b'SharedSecretKey123'  # Попередньо збережене спільне секретне значення

# Генерація випадкових чисел і сесійного ключа
def generate_session_key(secret_key, R_C, R_S):
    combined = secret_key + R_C + R_S
    return hashlib.sha256(combined).digest()

# Шифрування повідомлення
def encrypt_message(key, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Емуляція клієнта
def iot_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        # Генерація випадкового числа клієнта
        R_C = os.urandom(16)
        client_socket.sendall(R_C)

        # Отримання випадкового числа від сервера
        R_S = client_socket.recv(16)

        # Генерація сесійного ключа
        session_key = generate_session_key(SECRET_KEY, R_C, R_S)

        # Шифрування ID клієнта і часової мітки
        client_id = b'Client_01'
        timestamp = str(int(time.time())).encode()
        message = client_id + b'|' + timestamp

        encrypted_message = encrypt_message(session_key, message)
        client_socket.sendall(encrypted_message)

        # Отримання відповідного повідомлення від сервера
        response = client_socket.recv(1024)
        print("Received from server:", response)

iot_client()
