import os
import argparse
import hashlib
import hmac
import secrets
import string
from pathlib import Path
from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def derive_key(password: str) -> bytes:
    """Derives a 32-byte (256-bit) key from the given password using SHA-256."""
    return hashlib.sha256(password.encode()).digest()


def encrypt_file(file_path: str, output_path: str, password: str):
    """Encrypts a file using AES-256 encryption."""
    key = derive_key(password)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    with open(output_path, 'wb') as f:
        f.write(nonce + tag + ciphertext)
    
    print(f"File encrypted successfully: {output_path}")


def decrypt_file(file_path: str, output_path: str, password: str):
    """Decrypts a file using AES-256 encryption."""
    key = derive_key(password)
    
    with open(file_path, 'rb') as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print(f"File decrypted successfully: {output_path}")
    except ValueError:
        print("Decryption failed. Incorrect password or corrupted file.")


def generate_secure_password(length: int = 32) -> str:
    """Generates a secure random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def check_password_strength(password: str) -> bool:
    """Checks if a password meets security requirements."""
    if len(password) < 12:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in string.punctuation for c in password):
        return False
    return True


def generate_key_file(output_path: str):
    """Generates a secure key file for encryption."""
    key = get_random_bytes(32)
    with open(output_path, 'wb') as f:
        f.write(key)
    print(f"Key file generated successfully: {output_path}")


def ensure_directory_exists(path: str) -> None:
    """Ensures a directory exists, creates it if it doesn't."""
    path = Path(path)
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {path}")


def check_file_exists(path: str) -> bool:
    """Checks if a file exists and is accessible."""
    try:
        return Path(path).exists()
    except Exception:
        return False


def encrypt_directory(dir_path: str, output_path: str, password: str):
    """Encrypts all files in a directory."""
    dir_path = Path(dir_path)
    output_path = Path(output_path)
    
    if not dir_path.exists():
        print(f"Error: Input directory does not exist: {dir_path}")
        return
    
    if not dir_path.is_dir():
        print(f"Error: Input path is not a directory: {dir_path}")
        return
    
    ensure_directory_exists(output_path)
    
    files_to_process = list(dir_path.rglob('*'))
    if not files_to_process:
        print(f"Warning: No files found in directory: {dir_path}")
        return
    
    for file_path in tqdm(files_to_process, desc="Encrypting files"):
        if file_path.is_file():
            rel_path = file_path.relative_to(dir_path)
            output_file = output_path / rel_path
            output_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                encrypt_file(str(file_path), str(output_file), password)
            except Exception as e:
                print(f"Error encrypting {file_path}: {str(e)}")


def decrypt_directory(dir_path: str, output_path: str, password: str):
    """Decrypts all files in a directory."""
    dir_path = Path(dir_path)
    output_path = Path(output_path)
    
    if not dir_path.exists():
        print(f"Error: Input directory does not exist: {dir_path}")
        return
    
    if not dir_path.is_dir():
        print(f"Error: Input path is not a directory: {dir_path}")
        return
    
    ensure_directory_exists(output_path)
    
    files_to_process = list(dir_path.rglob('*'))
    if not files_to_process:
        print(f"Warning: No files found in directory: {dir_path}")
        return
    
    for file_path in tqdm(files_to_process, desc="Decrypting files"):
        if file_path.is_file():
            rel_path = file_path.relative_to(dir_path)
            output_file = output_path / rel_path
            output_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                decrypt_file(str(file_path), str(output_file), password)
            except Exception as e:
                print(f"Error decrypting {file_path}: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description="Secure File Encryption and Decryption Utility")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", action="store_true", help="Encrypt a file or directory")
    group.add_argument("--decrypt", action="store_true", help="Decrypt a file or directory")
    group.add_argument("--generate-key", action="store_true", help="Generate a secure key file")
    parser.add_argument("--file", help="Path to the input file or directory")
    parser.add_argument("--output", help="Path to the output file or directory")
    parser.add_argument("--password", help="Encryption/Decryption password")
    parser.add_argument("--key-file", help="Path to key file (optional)")
    
    args = parser.parse_args()
    
    if args.generate_key:
        if not args.output:
            print("Error: --output is required when generating a key file")
            return
        generate_key_file(args.output)
        return
    
    if not args.file or not args.output or not args.password:
        print("Error: --file, --output, and --password are required for encryption/decryption")
        return
    
    if not check_password_strength(args.password):
        print("Warning: Password does not meet security requirements")
        print("Password should be at least 12 characters long and contain:")
        print("- Uppercase letters")
        print("- Lowercase letters")
        print("- Numbers")
        print("- Special characters")
        if input("Continue anyway? (y/n): ").lower() != 'y':
            return
    
    if os.path.isdir(args.file):
        if args.encrypt:
            encrypt_directory(args.file, args.output, args.password)
        else:
            decrypt_directory(args.file, args.output, args.password)
    else:
        if not check_file_exists(args.file):
            print(f"Error: Input file does not exist: {args.file}")
            return
        if args.encrypt:
            encrypt_file(args.file, args.output, args.password)
        else:
            decrypt_file(args.file, args.output, args.password)


if __name__ == "__main__":
    main()
