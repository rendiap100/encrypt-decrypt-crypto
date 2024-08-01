import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from colorama import Fore, Style, init

def encrypt_file(password, plain_file_path, encrypted_file_path):
    # Derive key from password
    salt = os.urandom(16)  # Use a unique salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate Initialization Vector
    cari_apa_bang = os.urandom(16)

    # Create a cipher object and encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CFB(cari_apa_bang), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Read the plaintext file
    with open(plain_file_path, 'rb') as file:
        plaintext = file.read()

    # Encrypt the data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the salt, Initialization Vector, and encrypted data to a new file
    with open(encrypted_file_path, 'wb') as file:
        file.write(salt)
        file.write(cari_apa_bang)
        file.write(ciphertext)

def decrypt_file(password, encrypted_file_path, decrypted_file_path):
    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as file:
        salt = file.read(16)  # Read the salt
        cari_apa_bang = file.read(16)  # Read the Initialization Vector
        ciphertext = file.read()

    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Create a cipher object and decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CFB(cari_apa_bang), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Write the decrypted data to a new file
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

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
    init(autoreset=True)  # Initialize colorama
    while True:
        print_menu()

        choice = input(f"{Fore.CYAN}Enter your choice (1/2/3/4/5): {Style.RESET_ALL}")

        if choice == "1":
            password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            plain_file_path = input(f"{Fore.CYAN}Enter the path to the plaintext file: {Style.RESET_ALL}")
            encrypted_file_path = input(f"{Fore.CYAN}Enter the path to save the encrypted file: {Style.RESET_ALL}")
            encrypt_file(password, plain_file_path, encrypted_file_path)
            print(f"{Fore.GREEN}File encrypted successfully.{Style.RESET_ALL}")

        elif choice == "2":
            password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            encrypted_file_path = input(f"{Fore.CYAN}Enter the path to the encrypted file: {Style.RESET_ALL}")
            decrypted_file_path = input(f"{Fore.CYAN}Enter the path to save the decrypted file: {Style.RESET_ALL}")
            decrypt_file(password, encrypted_file_path, decrypted_file_path)
            print(f"{Fore.GREEN}File decrypted successfully.{Style.RESET_ALL}")

        elif choice == "3":
            password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            plain_folder_path = input(f"{Fore.CYAN}Enter the path to the plaintext folder: {Style.RESET_ALL}")
            encrypted_folder_path = input(f"{Fore.CYAN}Enter the path to save the encrypted folder: {Style.RESET_ALL}")
            encrypt_folder(password, plain_folder_path, encrypted_folder_path)
            print(f"{Fore.GREEN}Folder encrypted successfully.{Style.RESET_ALL}")

        elif choice == "4":
            password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
            encrypted_folder_path = input(f"{Fore.CYAN}Enter the path to the encrypted folder: {Style.RESET_ALL}")
            decrypted_folder_path = input(f"{Fore.CYAN}Enter the path to save the decrypted folder: {Style.RESET_ALL}")
            decrypt_folder(password, encrypted_folder_path, decrypted_folder_path)
            print(f"{Fore.GREEN}Folder decrypted successfully.{Style.RESET_ALL}")

        elif choice == "5":
            print(f"{Fore.CYAN}Exiting the program.{Style.RESET_ALL}")
            break

        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, 3, 4, or 5.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
