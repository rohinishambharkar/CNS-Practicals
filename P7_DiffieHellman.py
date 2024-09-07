from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Generate DH parameters
def generate_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

# Generate private and public keys for a party
def generate_private_key(parameters):
    private_key = parameters.generate_private_key()
    return private_key

# Generate the shared key using a private key and peer's public key
def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    
    # Derive a key from the shared key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    
    return derived_key

if __name__ == "__main__":
    # Generate parameters shared between parties
    parameters = generate_parameters()

    # Generate private and public keys for Alice
    private_key_alice = generate_private_key(parameters)
    public_key_alice = private_key_alice.public_key()

    # Generate private and public keys for Bob
    private_key_bob = generate_private_key(parameters)
    public_key_bob = private_key_bob.public_key()

    # Alice and Bob exchange public keys and generate the shared key
    shared_key_alice = generate_shared_key(private_key_alice, public_key_bob)
    shared_key_bob = generate_shared_key(private_key_bob, public_key_alice)

    # Print the derived shared keys for Alice and Bob
    print("\nShared key (Alice):", shared_key_alice.hex())
    print("Shared key (Bob):", shared_key_bob.hex())

    # Verify that both keys are the same
    assert shared_key_alice == shared_key_bob, "Error: The shared keys do not match!"
    print("Shared keys match. Secure communication can proceed.\n")