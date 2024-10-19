import socket
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Клієнтські параметри
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

# Ініціалізація клієнта
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, SERVER_PORT))

# Етап ініціалізації
r_s = client_socket.recv(1024)  # Отримуємо випадкове значення від сервера
r_c = os.urandom(16)
client_socket.send(r_c)  # Відправляємо своє випадкове значення серверу

# Генерація сесійного ключа
session_key = generate_session_key(SECRET_KEY, r_s, r_c)

# Відправляємо зашифроване повідомлення серверу
message = b"Hello, server!"
encrypted_message = encrypt_message(session_key, message)
client_socket.send(encrypted_message)

# Отримуємо зашифроване підтвердження від сервера
encrypted_response = client_socket.recv(1024)
server_response = decrypt_message(session_key, encrypted_response)
print(f"Повідомлення від сервера: {server_response.decode()}")

client_socket.close()
