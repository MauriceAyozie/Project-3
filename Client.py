import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
BUFFER_SIZE = 1024
OUTPUT_FILE = "received_data.txt"
ENCRYPTION_KEY = b'\x01' * 16  # Replace with the actual key used by the server (must match exactly)

def decrypt_data(encrypted_data, key):
    """Decrypts the encrypted data using AES (ECB mode)."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def save_to_file(data, filepath):
    with open(filepath, "wb") as file:
        file.write(data)
    print(f"[INFO] Data saved to {filepath}")

def connect_to_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            print(f"[INFO] Connecting to the server at {SERVER_HOST}:{SERVER_PORT}...")
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print("[INFO] Connection established. Receiving file size...")

            # Receive the total file size from the server
            file_size_data = client_socket.recv(BUFFER_SIZE).decode()
            if not file_size_data.isdigit():
                print(f"[ERROR] Invalid file size received: {file_size_data}")
                return

            total_size = int(file_size_data)
            print(f"[INFO] File size to be received: {total_size} bytes")

            received_data = bytearray()
            while len(received_data) < total_size:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    print("[WARNING] Connection closed unexpectedly by the server.")
                    break

                # Decrypt the received chunk
                decrypted_chunk = decrypt_data(chunk, ENCRYPTION_KEY)
                received_data.extend(decrypted_chunk)

                # Trim the data to ensure it doesn't exceed the total size
                if len(received_data) > total_size:
                    print(f"[WARNING] Trimming excess data (received: {len(received_data)}, expected: {total_size})")
                    received_data = received_data[:total_size]
                    break

                progress = (len(received_data) / total_size) * 100
                print(f"[INFO] Progress: {progress:.2f}%")

                # Send acknowledgment to the server
                client_socket.sendall(f"{progress:.2f}%".encode())

            # Validate and save the received data
            if len(received_data) == total_size:
                print("[INFO] File transfer complete.")
                save_to_file(received_data, OUTPUT_FILE)
            else:
                print(f"[ERROR] File transfer incomplete. Received {len(received_data)} out of {total_size} bytes.")

        except Exception as e:
            print(f"[ERROR] {e}")

if __name__ == "__main__":
    connect_to_server()