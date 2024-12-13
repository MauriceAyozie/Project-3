import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Configuration settings
SERVER_ADDRESS = ('0.0.0.0', 5555)
FILE_PATH = "data.txt"
THREAD_LIMIT = 10
CONNECTION_TIMEOUT = 600  # seconds

# Simulate key and encryption utilities
def generate_key(fragment):
    return bytes([fragment] * 16)  # Placeholder for key generation logic

def encrypt_message(message, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # Using ECB as an example
    encryptor = cipher.encryptor()
    return encryptor.update(message.ljust(16).encode())[:16]

# Client handler
class ClientSession(threading.Thread):
    def __init__(self, connection, address):
        super().__init__()
        self.connection = connection
        self.address = address

    def run(self):
        print(f"[INFO] Handling client at {self.address}")
        self.connection.settimeout(CONNECTION_TIMEOUT)

        try:
            # Check if the file exists
            if not os.path.exists(FILE_PATH):
                self.connection.sendall(b"ERROR: File not found.")
                print(f"[ERROR] File not found: {FILE_PATH}")
                return

            file_size = os.path.getsize(FILE_PATH)
            self.connection.sendall(f"{file_size}".encode())  # Send the file size

            with open(FILE_PATH, "rb") as file:
                file_data = file.read()

            crumbs = [byte for byte in file_data]

            for crumb in crumbs:
                key = generate_key(crumb)
                encrypted_message = encrypt_message("The quick brown fox jumps over the lazy dog.", key)
                self.connection.sendall(encrypted_message)
                print(f"[INFO] Sent encrypted crumb: {crumb}")

                client_status = self.connection.recv(1024).decode()
                if client_status == "100%":
                    print(f"[INFO] Client {self.address} has finished.")
                    return

            print(f"[INFO] All crumbs sent to {self.address}.")

        except Exception as error:
            print(f"[ERROR] Client {self.address} disconnected: {error}")
        finally:
            self.connection.close()

# Main server class
class Server:
    def __init__(self, host, port, thread_limit):
        self.host = host
        self.port = port
        self.thread_limit = thread_limit
        self.active_threads = 0

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"[INFO] Server listening on {self.port}...")

            while True:
                try:
                    conn, addr = server_socket.accept()
                    print(f"[INFO] Connection established with {addr}")

                    if self.active_threads < self.thread_limit:
                        session = ClientSession(conn, addr)
                        session.start()
                        self.active_threads += 1

                        session.join()
                        self.active_threads -= 1
                    else:
                        print("[WARNING] Too many active connections. Connection rejected.")
                        conn.close()

                except KeyboardInterrupt:
                    print("[INFO] Shutting down server...")
                    break

if __name__ == "__main__":
    server = Server(*SERVER_ADDRESS, THREAD_LIMIT)
    server.start()


