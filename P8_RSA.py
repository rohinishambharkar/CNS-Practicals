from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Generate RSA private and public keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt a message using the public key
def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Decrypt a message using the private key
def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

if __name__ == "__main__":
    # Generate RSA keys
    private_key, public_key = generate_keys()

    # Message to be encrypted
    message = b"Hello, RSA Encryption!"

    # Encrypt the message
    ciphertext = encrypt_message(public_key, message)
    print("\nEncrypted message:", ciphertext.hex())

    # Decrypt the message
    decrypted_message = decrypt_message(private_key, ciphertext)
    print("\nDecrypted message:", decrypted_message.decode('utf-8'))