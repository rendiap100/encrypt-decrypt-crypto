from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from colorama import Fore, Style, init

def encrypt_file(password, plain_file_path, encrypted_file_path):
    # Derive key from password
    salt = b'salt123'  # You should use a unique salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate Initialization Vector
    iv = b'iv12345678901234'

    # Create a cipher object and encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Read the plaintext file
    with open(plain_file_path, 'rb') as file:
        plaintext = file.read()

    # Encrypt the data
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Write the encrypted data to a new file
    with open(encrypted_file_path, 'wb') as file:
        file.write(iv)
        file.write(ciphertext)

def decrypt_file(password, encrypted_file_path, decrypted_file_path):
    # Derive key from password
    salt = b'salt123'  # You should use a unique salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as file:
        iv = file.read(16)  # Initialization Vector
        ciphertext = file.read()

    # Create a cipher object and decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Write the decrypted data to a new file
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

def print_menu():
    print(f"{Fore.CYAN}Menu:{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1. Encrypt File")
    print("2. Decrypt File")
    print("3. Exit{Style.RESET_ALL}")

def main():
    while True:
        print_menu()

        choice = input(f"{Fore.CYAN}Enter your choice (1/2/3): {Style.RESET_ALL}")

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
            print(f"{Fore.CYAN}Exiting the program.{Style.RESET_ALL}")
            break

        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
