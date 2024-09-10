# Helper function to rotate bits left
def rotate_left(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

# SHA-1 hash function
def sha1(data):
    # Pre-processing
    original_byte_len = len(data)
    original_bit_len = original_byte_len * 8

    # Add a single '1' bit to the message
    data += b'\x80'

    # Pad with zeros until the message length is congruent to 56 (mod 64)
    while len(data) % 64 != 56:
        data += b'\x00'

    # Append the original message length as a 64-bit big-endian integer
    data += original_bit_len.to_bytes(8, byteorder='big')

    # Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 5 primes)
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Process the message in successive 512-bit chunks (64 bytes)
    for i in range(0, len(data), 64):
        chunk = data[i:i+64]
        w = [0] * 80

        # Break chunk into sixteen 32-bit big-endian words w[0..15]
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:(j*4)+4], byteorder='big')

        # Extend the sixteen 32-bit words into eighty 32-bit words
        for j in range(16, 80):
            w[j] = rotate_left(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= j <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (rotate_left(a, 5) + f + e + k + w[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = rotate_left(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Produce the final hash value (big-endian) as a 160-bit number
    return ''.join(format(x, '08x') for x in [h0, h1, h2, h3, h4])

if __name__ == "__main__":
    # Input message
    message = "Hello, SHA-1!"
    
    # Convert the message to bytes
    message_bytes = message.encode('utf-8')

    # Calculate the SHA-1 hash
    hash_result = sha1(message_bytes)
    print(f"SHA-1 Hash of '{message}': {hash_result}")