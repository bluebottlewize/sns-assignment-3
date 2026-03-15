import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------
# 1. Standard Domain Parameters (RFC 5114 - 1024-bit MODP)
# In a real scenario, these must be securely chosen.
# ---------------------------------------------------------
P = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
        "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
        "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
        "DF1FB2BC2E4A4371", 16)

Q = int("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16)

G = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
        "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
        "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
        "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
        "855E6EEB22B3B2E5", 16)

# ---------------------------------------------------------
# 2. Manual Mathematical Operations [cite: 76, 77, 78]
# ---------------------------------------------------------
def mod_exp(base, exp, mod):
    """Manual modular exponentiation (square-and-multiply)."""
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def get_secure_random_zq(q):
    """OS-level secure RNG mapped to Z_q[cite: 75, 91]."""
    # Rejection sampling to ensure uniform distribution
    byte_length = (q.bit_length() + 7) // 8
    while True:
        rand_bytes = os.urandom(byte_length)
        rand_int = int.from_bytes(rand_bytes, 'big')
        if 0 < rand_int < q:
            return rand_int

# ---------------------------------------------------------
# 3. Schnorr Signature Scheme [cite: 82]
# ---------------------------------------------------------
def generate_schnorr_keypair():
    """Generates an independent Schnorr key pair (x_i, y_i)[cite: 83]."""
    x = get_secure_random_zq(Q)               # Private key x_i in Z_q [cite: 85]
    y = mod_exp(G, x, P)                      # Public key y_i = g^{x_i} mod p [cite: 87]
    return x, y

def schnorr_sign(message: bytes, private_key: int, authority_id: str):
    """Generates a Schnorr signature (R_i, s_i) [cite: 88-97]."""
    # 1. Nonce generation: k_i in Z_q [cite: 90, 91]
    k = get_secure_random_zq(Q)
    
    # 2. Commitment: R_i = g^{k_i} mod p [cite: 92, 93]
    R = mod_exp(G, k, P)
    
    # 3. Challenge: e_i = H(m || R_i || ID_i) [cite: 97]
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, 'big')
    id_bytes = authority_id.encode('utf-8')
    
    hasher = hashlib.sha256() [cite: 75]
    hasher.update(message + R_bytes + id_bytes)
    e_bytes = hasher.digest()
    e = int.from_bytes(e_bytes, 'big') % Q
    
    # 4. Signature: s_i = k_i + e_i * x_i mod q [cite: 97]
    s = (k + (e * private_key)) % Q
    
    return R, s

def schnorr_verify(message: bytes, R: int, s: int, public_key: int, authority_id: str):
    """Verifies a single Schnorr signature[cite: 98, 99]."""
    # Recalculate Challenge e_i = H(m || R_i || ID_i) [cite: 99]
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, 'big')
    id_bytes = authority_id.encode('utf-8')
    
    hasher = hashlib.sha256()
    hasher.update(message + R_bytes + id_bytes)
    e_bytes = hasher.digest()
    e = int.from_bytes(e_bytes, 'big') % Q
    
    # Verify: g^{s_i} == R_i * y_i^{e_i} mod p [cite: 99]
    left_side = mod_exp(G, s, P)
    right_side = (R * mod_exp(public_key, e, P)) % P
    
    return left_side == right_side

def verify_multi_signature(message: bytes, signatures: list, public_keys: dict):
    """
    Verifies that a ticket has at least 2 valid signatures 
    from different authorities[cite: 100].
    `signatures` format: [(R, s, authority_id), ...]
    `public_keys` format: {authority_id: public_key}
    """
    valid_count = 0
    seen_authorities = set()
    
    for R, s, auth_id in signatures:
        if auth_id in seen_authorities:
            continue # Prevent replay of same authority
            
        pub_key = public_keys.get(auth_id)
        if pub_key and schnorr_verify(message, R, s, pub_key, auth_id):
            valid_count += 1
            seen_authorities.add(auth_id)
            
    return valid_count >= 2

# ---------------------------------------------------------
# 4. Symmetric Encryption (AES-256-CBC) & PKCS#7 
# ---------------------------------------------------------
def pkcs7_pad(data: bytes) -> bytes:
    """Manual PKCS#7 Padding."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """Manual PKCS#7 Unpadding."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding byte")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC Encryption."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pkcs7_pad(plaintext)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """AES-256-CBC Decryption."""
    iv = ciphertext_with_iv[:16]
    actual_ciphertext = ciphertext_with_iv[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded_data)