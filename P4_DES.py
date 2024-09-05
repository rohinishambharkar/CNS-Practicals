from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# DES encryption function
def encrypt_message(key, plaintext):
    # Generate a random 8-byte IV (Initialization Vector)
    iv = get_random_bytes(DES.block_size)

    # Create a DES cipher object in CBC mode
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Pad the plaintext to be a multiple of the block size (8 bytes for DES)
    padded_plaintext = pad(plaintext, DES.block_size)

    # Encrypt the padded plaintext
    ciphertext = iv + cipher.encrypt(padded_plaintext)
    return ciphertext

# DES decryption function
def decrypt_message(key, ciphertext):
    # Extract the IV from the beginning of the ciphertext
    iv = ciphertext[:DES.block_size]
    ciphertext = ciphertext[DES.block_size:]

    # Create a DES cipher object in CBC mode
    cipher = DES.new(key, DES.MODE_CBC, iv)

    # Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)

    # Unpad the plaintext
    plaintext = unpad(padded_plaintext, DES.block_size)
    return plaintext

if __name__ == "__main__":
    # Generate a random 8-byte key for DES
    key = get_random_bytes(8) 

    # Message to be encrypted
    message = b"Hello, DES Encryption!"

    # Encrypt the message
    ciphertext = encrypt_message(key, message)
    print("\nEncrypted message (hex):", ciphertext.hex())

    # Decrypt the message
    decrypted_message = decrypt_message(key, ciphertext)
    print("Decrypted message:", decrypted_message.decode('utf-8'))