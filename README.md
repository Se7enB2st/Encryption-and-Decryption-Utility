# Secure File Encryption and Decryption Utility

## 📌 Project Overview
This project is a Python-based utility designed to encrypt and decrypt files securely using industry-standard encryption algorithms. It ensures the confidentiality of sensitive data, making it ideal for cybersecurity applications.

## 🚀 Features
- **AES-256 Encryption**: Uses the Advanced Encryption Standard (AES) with a 256-bit key for strong encryption.
- **Secure Key Management**: Generates and stores encryption keys securely.
- **Command-Line Interface (CLI)**: Easily encrypt and decrypt files using simple commands.
- **Cross-Platform Support**: Works on Windows, Linux, and macOS.
- **Directory Encryption**: Encrypt or decrypt entire directories with a single command.
- **Password Strength Checker**: Ensures strong passwords are used for encryption.
- **Progress Tracking**: Visual progress bar for large files and directories.
- **Key File Generation**: Generate secure key files for encryption.

## 🛠 Technologies Used
- **Python 3.x**
- **PyCryptodome** (for AES encryption)
- **Argparse** (for CLI argument parsing)
- **OS & SYS** (for file handling and security features)
- **TQDM** (for progress bars)
- **Pathlib** (for cross-platform path handling)

## 📖 Installation
### Prerequisites
Ensure you have Python installed. You can download it from [Python.org](https://www.python.org/downloads/).

### Install Dependencies
```bash
pip install pycryptodome tqdm
```

## 🔑 Usage
### Basic File Operations
#### Encrypt a File
```bash
python encryptor.py --encrypt --file confidential.txt --output encrypted.dat --password
```

#### Decrypt a File
```bash
python encryptor.py --decrypt --file encrypted.dat --output decrypted.txt --password
```

### Directory Operations
#### Encrypt a Directory
```bash
python encryptor.py --encrypt --file ./sensitive_data/ --output ./encrypted_data/ --password
```

#### Decrypt a Directory
```bash
python encryptor.py --decrypt --file ./encrypted_data/ --output ./decrypted_data/ --password
```

### Key Management
#### Generate a Key File
```bash
python encryptor.py --generate-key --output keyfile.key
```

## 🔒 Security Considerations
- Ensure encryption keys are stored securely and not hardcoded.
- Use strong passwords when deriving keys from user input.
- Implement proper exception handling to prevent data corruption.
- Passwords must be at least 12 characters long and contain:
  - Uppercase letters
  - Lowercase letters
  - Numbers
  - Special characters

## 📜 License
This project is open-source and available under the MIT License.

## 🤝 Contributions
Contributions are welcome! Feel free to fork the repository and submit pull requests.

## 📧 Contact
For any issues or inquiries, reach out via email or GitHub Issues.

---
🔐 **Secure your data with confidence!**

