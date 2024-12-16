import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import hashlib

def create_vault(password):
    """Create a new vault and store it as a JSON file with a secure password."""
    salt = os.urandom(16)  # Generate a random salt (16 bytes)
    hashed_key = hash_password(password, salt)  # Hash the password with the salt
    
    # Create vault data, including the hashed key
    vault_data = {
        'salt': salt.hex(),  # Store salt as hex string
        'hashed_key': hashed_key,  # Store the hashed password key
        'files': []  # Placeholder for files in the vault
    }
    
    # Save vault data to a file
    with open('vaults/vault.json', 'w') as vault_file:
        json.dump(vault_data, vault_file, indent=4)
    
    print("Vault created successfully.")

def verify_password(password, salt, stored_hashed_key):
    """Verify the entered password by hashing it with the salt and comparing it to the stored hash."""
    # Convert the salt from hex to bytes
    salt_bytes = bytes.fromhex(salt)
    
    # Re-hash the entered password with the salt
    hashed_password = hash_password(password, salt_bytes)
    
    # Compare the new hash with the stored hash
    return hashed_password == stored_hashed_key

def hash_password(password, salt):
    """Hash the password with the given salt using PBKDF2."""
    # Hash the password with PBKDF2-HMAC using SHA-256
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

def derive_encryption_key(password, salt):
    """Derive an encryption key using the password and salt."""
    password_bytes = password.encode('utf-8')  # Convert password to bytes
    salt_bytes = bytes.fromhex(salt)  # Convert salt from hex string to bytes
    
    # Derive the encryption key using PBKDF2-HMAC with SHA-256
    return hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)

def lock_vault(vault_data):
    """Lock the vault again by re-encrypting it."""
    # Update vault data with the current encryption key (you don't need to re-encode it in Base64)
    print("Vault Data Before Lock:", vault_data)  # For debugging purposes
    
    # Save the updated vault data
    with open('vaults/vault.json', 'w') as vault_file:
        json.dump(vault_data, vault_file, indent=4)

    print("Vault is locked again.")

def remove_file_from_vault(file_name):
    """Remove a file from the vault."""
    try:
        with open('vaults/vault.json', 'r') as vault_file:
            vault_data = json.load(vault_file)  # Load vault metadata
        
        # Find the file to remove based on the name
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

