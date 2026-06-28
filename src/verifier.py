import hashlib, hmac


# Exact PKCS#1 v1.5 DigestInfo prefixes for standard hash algorithms
HASH_PREFIXES = {
    'SHA256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'SHA384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'SHA512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40'
}


def verify_rsa_pkcs1_v1_5(payload: bytes, signature: bytes, n: int, e: int, hash_alg: str = 'SHA256') -> bool:
    ''' Performs strict, memory-safe RSA PKCS#1 v1.5 signature verification '''
    
    hash_alg = hash_alg.upper().replace('-', '')
    if hash_alg not in HASH_PREFIXES:
        return False
        
    # Hash the payload and prepend the standard ASN.1 prefix
    h = hashlib.new(hash_alg.lower(), payload).digest()
    expected_t = HASH_PREFIXES[hash_alg] + h
    
    # RSA Decryption: m = s^e (mod n)
    s = int.from_bytes(signature, 'big')
    if s >= n: 
        return False
    m = pow(s, e, n)
    
    # Convert decrypted integer back to a zero-padded byte array
    k = (n.bit_length() + 7) // 8
    em = m.to_bytes(k, 'big')
    
    # Strict PKCS#1 v1.5 Padding Validation (0x00 || 0x01 || PS || 0x00 || T)
    ps_len = k - len(expected_t) - 3
    if ps_len < 8:
        return False
        
    expected_em = b'\x00\x01' + (b'\xff' * ps_len) + b'\x00' + expected_t
    
    # Constant-time comparison
    return hmac.compare_digest(em, expected_em)