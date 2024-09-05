from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Blowfish encryption function
def encrypt_message(key, plaintext):
    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(Blowfish.block_size)

    # Create a Blowfish cipher object in CBC mode
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)

    # Pad the plaintext to be a multiple of the block size (8 bytes for Blowfish)
    padded_plaintext = pad(plaintext, Blowfish.block_size)

    # Encrypt the padded plaintext
    ciphertext = iv + cipher.encrypt(padded_plaintext)
    return ciphertext

# Blowfish decryption function
def decrypt_message(key, ciphertext):
    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:Blowfish.block_size]
    ciphertext = ciphertext[Blowfish.block_size:]

    # Create a Blowfish cipher object in CBC mode
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)

    # Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)

    # Unpad the plaintext
    plaintext = unpad(padded_plaintext, Blowfish.block_size)
    return plaintext

if __name__ == "__main__":
    # Generate a random key for Blowfish (key size can be between 4 and 56 bytes)
    key = get_random_bytes(16)  # Example: 16-byte key

    # Message to be encrypted
    message = b"Hello, Blowfish Encryption!"

    # Encrypt the message
    ciphertext = encrypt_message(key, message)
    print("\nEncrypted message (hex):", ciphertext.hex())

    # Decrypt the message
    decrypted_message = decrypt_message(key, ciphertext)
    print("Decrypted message:", decrypted_message.decode('utf-8'))