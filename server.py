import socket
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import time

# Конфігурація сервера
HOST = '127.0.0.1'  # Локальний хост (можна змінити на IP сервера, якщо він віддалений)
PORT = 65432        # Порт, на якому буде слухати сервер
SECRET_KEY = b'SharedSecretKey123'  # Попередньо збережений спільний секрет

# Функція для генерації сесійного ключа на основі секрету та випадкових чисел
def generate_session_key(secret_key, R_C, R_S):
    combined = secret_key + R_C + R_S
    return hashlib.sha256(combined).digest()

# Функція для шифрування повідомлення
def encrypt_message(key, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# Функція для дешифрування повідомлення
def decrypt_message(key, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()

    return plaintext

# Реалізація сервера
def iot_server():
    # Створюємо сокет
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))  # Прив'язуємо сервер до хоста і порту
        server_socket.listen()  # Слухаємо вхідні з'єднання
        print(f"Server is listening on {HOST}:{PORT}...")

        # Приймаємо клієнта
        conn, addr = server_socket.accept()
        with conn:
            print(f'Connected by {addr}')

            # 1. Отримання випадкового числа від клієнта
            R_C = conn.recv(16)  # Отримуємо 16 байт випадкового числа від клієнта

            # 2. Генерація випадкового числа сервера
            R_S = os.urandom(16)  # Генеруємо 16 байт випадкового числа
            conn.sendall(R_S)  # Відправляємо це число клієнту

            # 3. Генерація сесійного ключа
            session_key = generate_session_key(SECRET_KEY, R_C, R_S)

            # 4. Отримання зашифрованого повідомлення від клієнта
            encrypted_message = conn.recv(1024)  # Отримуємо зашифроване повідомлення
            decrypted_message = decrypt_message(session_key, encrypted_message)  # Дешифруємо повідомлення

            # 5. Розділяємо повідомлення на ID клієнта та часову мітку
            client_id, timestamp = decrypted_message.split(b'|')
            print(f"Received client ID: {client_id.decode()}, timestamp: {timestamp.decode()}")

            # 6. Формуємо відповідь (наприклад, підтвердження успіху)
            server_response = b'Success|' + str(int(time.time())).encode()
            encrypted_response = encrypt_message(session_key, server_response)  # Шифруємо відповідь
            conn.sendall(encrypted_response)  # Відправляємо відповідь клієнту

# Запускаємо сервер
iot_server()