import numpy as np

def get_key_matrix(key, n):
    key_matrix = []
    key_index = 0
    for i in range(n):
        row = []
        for j in range(n):
            row.append(ord(key[key_index]) % 65)
            key_index += 1
        key_matrix.append(row)
    return np.array(key_matrix)


def get_text_vector(text, n):
    text_vector = []
    for i in range(n):
        text_vector.append(ord(text[i]) % 65)
    return np.array(text_vector).reshape(n, 1)


def matrix_mod_mult(matrix1, matrix2, mod):
    result = np.dot(matrix1, matrix2) % mod
    return result


def mod_matrix_inverse(matrix, mod):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, mod)
    matrix_mod_inv = (det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % mod)
    return matrix_mod_inv



def encrypt(plain_text, key):
    n = len(key) ** 0.5
    if n != int(n):
        raise ValueError("Invalid key length. Key length must be a perfect square.")
    n = int(n)
    
    key_matrix = get_key_matrix(key, n)
    plain_text = plain_text.upper().replace(" ", "")
    
    while len(plain_text) % n != 0:
        plain_text += 'X'  # Padding with 'X' if not multiple of n
    
    cipher_text = ""
    for i in range(0, len(plain_text), n):
        text_vector = get_text_vector(plain_text[i:i+n], n)
        cipher_vector = matrix_mod_mult(key_matrix, text_vector, 26)
        cipher_text += ''.join(chr(int(num) + 65) for num in cipher_vector)
    
    return cipher_text


def decrypt(cipher_text, key):
    n = len(key) ** 0.5
    if n != int(n):
        raise ValueError("Invalid key length. Key length must be a perfect square.")
    n = int(n)
    
    key_matrix = get_key_matrix(key, n)
    inverse_key_matrix = mod_matrix_inverse(key_matrix, 26)
    
    plain_text = ""
    for i in range(0, len(cipher_text), n):
        text_vector = get_text_vector(cipher_text[i:i+n], n)
        plain_vector = matrix_mod_mult(inverse_key_matrix, text_vector, 26)
        plain_text += ''.join(chr(int(num) + 65) for num in plain_vector)
    
    return plain_text


plain_text = "Shizuka"
key = "GYBNQKURP" 
cipher_text = encrypt(plain_text, key)
decrypted_text = decrypt(cipher_text, key)

print("\n")
print(f"Plaintext: {plain_text}")
print(f"Encrypted Text: {cipher_text}")
print(f"Decrypted Text: {decrypted_text}")