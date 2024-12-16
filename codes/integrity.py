import hashlib

def compute_file_hash(file_path):
    """Compute and return the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def verify_file_integrity(file_path, expected_hash):
    """Verify the integrity of a file by comparing its hash to the expected one."""
    computed_hash = compute_file_hash(file_path)
    return computed_hash == expected_hash
