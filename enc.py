import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from colorama import Fore, Style, init

CHUNK_SIZE = 64 * 1024  # Process files in 64 KB chunks

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(password, plain_file_path, encrypted_file_path):
    try:
        # Derive key from password
        salt = os.urandom(16)
        key = derive_key(password, salt)

        # Generate Initialization Vector
        iv = os.urandom(16)

        # Create a cipher object and encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(plain_file_path, 'rb') as infile, open(encrypted_file_path, 'wb') as outfile:
            outfile.write(salt)  # Save salt
            outfile.write(iv)    # Save IV
            
            while chunk := infile.read(CHUNK_SIZE):
                outfile.write(encryptor.update(chunk))
            outfile.write(encryptor.finalize())
        print(f"{Fore.GREEN}File encrypted successfully.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Error during encryption: {str(e)}{Style.RESET_ALL}")

def decrypt_file(password, encrypted_file_path, decrypted_file_path):
    try:
        with open(encrypted_file_path, 'rb') as infile:
            salt = infile.read(16)
            iv = infile.read(16)
            key = derive_key(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            with open(decrypted_file_path, 'wb') as outfile:
                while chunk := infile.read(CHUNK_SIZE):
                    outfile.write(decryptor.update(chunk))
                outfile.write(decryptor.finalize())
        print(f"{Fore.GREEN}File decrypted successfully.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Error during decryption: {str(e)}{Style.RESET_ALL}")

# Folder encryption/decryption functions remain the same, except now they call the updated encrypt_file/decrypt_file
def encrypt_folder(password, plain_folder_path, encrypted_folder_path):
    for root, _, files in os.walk(plain_folder_path):
        for file in files:
            plain_file_path = os.path.join(root, file)
            relative_path = os.path.relpath(plain_file_path, plain_folder_path)
            encrypted_file_path = os.path.join(encrypted_folder_path, relative_path)

            os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)
            encrypt_file(password, plain_file_path, encrypted_file_path)

def decrypt_folder(password, encrypted_folder_path, decrypted_folder_path):
    for root, _, files in os.walk(encrypted_folder_path):
        for file in files:
            encrypted_file_path = os.path.join(root, file)
            relative_path = os.path.relpath(encrypted_file_path, encrypted_folder_path)
            decrypted_file_path = os.path.join(decrypted_folder_path, relative_path)

            os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)
            decrypt_file(password, encrypted_file_path, decrypted_file_path)

def print_menu():
    print(f"{Fore.CYAN}Menu:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1. Encrypt File")
    print(f"2. Decrypt File")
    print(f"3. Encrypt Folder")
    print(f"4. Decrypt Folder")
    print(f"5. Exit{Style.RESET_ALL}")

def main():
    init(autoreset=True)
    while True:
        print_menu()
        choice = input(f"{Fore.CYAN}Enter your choice (1/2/3/4/5): {Style.RESET_ALL}")

        if choice == "1":
            password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            plain_file_path = input(f"{Fore.CYAN}Enter the path to the plaintext file: {Style.RESET_ALL}")
            encrypted_file_path = input(f"{Fore.CYAN}Enter the path to save the encrypted file: {Style.RESET_ALL}")
            encrypt_file(password, plain_file_path, encrypted_file_path)

        elif choice == "2":
            password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            encrypted_file_path = input(f"{Fore.CYAN}Enter the path to the encrypted file: {Style.RESET_ALL}")
            decrypted_file_path = input(f"{Fore.CYAN}Enter the path to save the decrypted file: {Style.RESET_ALL}")
            decrypt_file(password, encrypted_file_path, decrypted_file_path)

        elif choice == "3":
            password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            plain_folder_path = input(f"{Fore.CYAN}Enter the path to the plaintext folder: {Style.RESET_ALL}")
            encrypted_folder_path = input(f"{Fore.CYAN}Enter the path to save the encrypted folder: {Style.RESET_ALL}")
            encrypt_folder(password, plain_folder_path, encrypted_folder_path)

        elif choice == "4":
            password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            encrypted_folder_path = input(f"{Fore.CYAN}Enter the path to the encrypted folder: {Style.RESET_ALL}")
            decrypted_folder_path = input(f"{Fore.CYAN}Enter the path to save the decrypted folder: {Style.RESET_ALL}")
            decrypt_folder(password, encrypted_folder_path, decrypted_folder_path)

        elif choice == "5":
            print(f"{Fore.CYAN}Exiting the program.{Style.RESET_ALL}")
            break

        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, 3, 4, or 5.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
