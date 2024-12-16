import os
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Vault setup
VAULT_DIR = "vaults"
os.makedirs(VAULT_DIR, exist_ok=True)  # Create vault directory if it doesn't exist
VAULT_FILE = os.path.join(VAULT_DIR, "vault.json")

# Helper function to generate a random encryption key
def generate_key():
    return get_random_bytes(32)  # AES-256 key

# Function to derive a secure encryption key from the password
def derive_key(password):
    """Derives an AES-256 key from the password using PBKDF2."""
    salt = b"unique_salt_for_vault"  # Store this salt securely (or generate it on vault creation)
    return PBKDF2(password, salt, dkLen=32)  # 32 bytes for AES-256

def encrypt_file(file_path, encryption_key):
    """Encrypt the file using AES-256 and return the encrypted data."""
    cipher = AES.new(encryption_key, AES.MODE_CBC)
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    encrypted_data = cipher.iv + ciphertext  # Prepend IV to the ciphertext for later decryption
    return encrypted_data

def decrypt_file(encrypted_data, encryption_key):
    """Decrypt the encrypted file and return the decrypted data."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

def compute_file_hash(file_path):
    """Compute the SHA256 hash of a file to ensure its integrity."""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        # Read the file in chunks to avoid large memory usage
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def add_file_to_vault(file_path, encryption_key):
    """Encrypt and add a file to the vault."""
    encrypted_data = encrypt_file(file_path, encryption_key)
    
    # Compute file hash for integrity check
    file_hash = compute_file_hash(file_path)
    
    # Load existing vault metadata and add file information
    with open(VAULT_FILE, 'r+') as vault_file:
        vault_data = json.load(vault_file)
        vault_data["files"].append({"name": os.path.basename(file_path), "hash": file_hash})
        vault_file.seek(0)
        json.dump(vault_data, vault_file)

    # Save the encrypted file in the vault directory
    encrypted_file_path = os.path.join(VAULT_DIR, f"{os.path.basename(file_path)}.enc")
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)

    print("File added to vault.")

def extract_file_from_vault(file_name, encryption_key):
    """Extract and decrypt a file from the vault."""
    encrypted_file_path = os.path.join(VAULT_DIR, f"{file_name}.enc")
    
    if os.path.exists(encrypted_file_path):
        # Read encrypted data from the file
        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()

        # Decrypt the file data
        decrypted_data = decrypt_file(encrypted_data, encryption_key)

        # Compute hash of decrypted data
        decrypted_file_hash = hashlib.sha256(decrypted_data).hexdigest()

        # Retrieve file hash from vault metadata
        with open(VAULT_FILE, 'r') as vault_file:
            vault_data = json.load(vault_file)
            file_metadata = next((file for file in vault_data['files'] if file['name'] == file_name), None)
            
            if file_metadata and decrypted_file_hash == file_metadata['hash']:
                # Save the decrypted file to the current directory
                with open(file_name, 'wb') as file:
                    file.write(decrypted_data)
                print(f"File {file_name} extracted successfully.")
            else:
                print("File hash mismatch. The file may have been tampered with.")
    else:
        print("File not found in vault.")

def list_files_in_vault():
    """List files in the vault."""
    with open(VAULT_FILE, 'r') as vault_file:
        vault_data = json.load(vault_file)
        if not vault_data["files"]:
            print("No files in the vault.")
        else:
            print("Files in the vault:")
            for file in vault_data["files"]:
                print(f"Name: {file['name']}, Hash: {file['hash']}")

    



def unlock_vault(password):
    """Unlock the vault by decrypting the vault's metadata using the password."""
    encryption_key = derive_key(password)

    encrypted_file_path = f"{VAULT_FILE}.enc"
    if os.path.exists(encrypted_file_path):
        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()

        decrypted_data = decrypt_file(encrypted_data, encryption_key)
        with open(VAULT_FILE, 'wb') as vault_file:
            vault_file.write(decrypted_data)

        os.remove(encrypted_file_path)  # Remove encrypted vault file
        print("Vault unlocked.")
    else:
        print("Vault is not locked or the encrypted file does not exist.")

def remove_file_from_vault(file_name, encryption_key):
    """Remove a file from the vault."""
    try:
        # Load the vault data
        with open('vaults/vault.json', 'r') as vault_file:
            vault_data = json.load(vault_file)

        # Find and remove the file from the vault
        file_to_remove = None
        for file in vault_data['files']:
            if file['name'] == file_name:
                file_to_remove = file
                break

        if file_to_remove:
            vault_data['files'].remove(file_to_remove)  # Remove the file from the list
            with open('vaults/vault.json', 'w') as vault_file:
                json.dump(vault_data, vault_file, indent=4)  # Save the updated vault data
            return True  # File successfully removed
        else:
            return False  # File not found
    except FileNotFoundError:
        return False  # Vault file not found
    except json.JSONDecodeError:
        return False  # Vault file is corrupted

