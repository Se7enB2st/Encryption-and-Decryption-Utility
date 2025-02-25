import os
import argparse
import hashlib
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


def main():
    parser = argparse.ArgumentParser(description="Secure File Encryption and Decryption Utility")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", action="store_true", help="Encrypt a file")
    group.add_argument("--decrypt", action="store_true", help="Decrypt a file")
    parser.add_argument("--file", required=True, help="Path to the input file")
    parser.add_argument("--output", required=True, help="Path to the output file")
    parser.add_argument("--password", required=True, help="Encryption/Decryption password")
    
    args = parser.parse_args()
    
    if args.encrypt:
        encrypt_file(args.file, args.output, args.password)
    elif args.decrypt:
        decrypt_file(args.file, args.output, args.password)


if __name__ == "__main__":
    main()
