from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# AES encryption function
def encrypt_message(key, plaintext):
    # Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)

    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Pad the plaintext to be a multiple of the block size (128 bits / 16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return iv + ciphertext

# AES decryption function
def decrypt_message(key, ciphertext):
    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Create a Cipher object using the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

if __name__ == "__main__":
    # Generate a random 32-byte key for AES-256 (can also use 16 bytes for AES-128 or 24 bytes for AES-192)
    key = os.urandom(32)

    # Message to be encrypted
    message = b"Hello, AES Encryption!"

    # Encrypt the message
    ciphertext = encrypt_message(key, message)
    print("\nEncrypted message (hex):", ciphertext.hex())

    # Decrypt the message
    decrypted_message = decrypt_message(key, ciphertext)
    print("Decrypted message:", decrypted_message.decode('utf-8'))