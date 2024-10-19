import socket
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Серверські параметри
SECRET_KEY = b'secret_shared_key'
SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432

# Хеш-функція для генерації сесійного ключа
def generate_session_key(secret, r_s, r_c):
    return hashlib.sha256(secret + r_s + r_c).digest()

# Функція для шифрування
def encrypt_message(key, message):
    iv = os.urandom(16)  # Ініціалізаційний вектор для AES
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message) + encryptor.finalize()

# Функція для розшифрування
def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]) + decryptor.finalize()

# Ініціалізація сервера
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, SERVER_PORT))
server_socket.listen(1)
print(f"Сервер запущено на {SERVER_IP}:{SERVER_PORT}")

conn, addr = server_socket.accept()
print(f"Підключено: {addr}")

# Етап ініціалізації
r_s = os.urandom(16)
conn.send(r_s)  # Надсилаємо випадкове значення клієнту

r_c = conn.recv(1024)  # Отримуємо випадкове значення клієнта

# Генерація сесійного ключа
session_key = generate_session_key(SECRET_KEY, r_s, r_c)

# Отримуємо зашифроване повідомлення від клієнта
encrypted_message = conn.recv(1024)
client_message = decrypt_message(session_key, encrypted_message)
print(f"Повідомлення від клієнта: {client_message.decode()}")

# Відправляємо зашифроване підтвердження клієнту
server_response = b"Authentication successful"
encrypted_response = encrypt_message(session_key, server_response)
conn.send(encrypted_response)

conn.close()
