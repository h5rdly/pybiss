import base64


def _encode_der_len(length: int) -> bytes:
    ''' Encodes ASN.1 DER length field '''

    if length < 128:
        return bytes([length])
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(len_bytes)]) + len_bytes


def _encode_der_int(data: bytes) -> bytes:
    ''' Encodes a PKCS#11 raw integer (like Modulus) into an ASN.1 INTEGER '''

    # Strip leading zeros
    start = 0
    while start < len(data) - 1 and data[start] == 0 and (data[start+1] & 0x80) == 0:
        start += 1
    data = data[start:]
    
    # If the highest bit is set, prepend a 0x00 byte to keep it positive
    if data and (data[0] & 0x80) != 0:
        data = b'\x00' + data
        
    return b'\x02' + _encode_der_len(len(data)) + data


def _encode_der_sequence(content: bytes) -> bytes:
    ''' Wraps content in an ASN.1 SEQUENCE '''

    return b'\x30' + _encode_der_len(len(content)) + content


def build_spkac_payload(modulus: bytes, exponent: bytes, challenge: str) -> bytes:
    ''' Builds the To-Be-Signed (TBS) SPKAC block from raw RSA parameters '''
    
    # Build the RSAPublicKey Sequence
    rsa_pub = _encode_der_int(modulus) + _encode_der_int(exponent)
    rsa_pub_seq = _encode_der_sequence(rsa_pub)

    # Wrap it in a BIT STRING
    bit_string = b'\x00' + rsa_pub_seq  # 0 unused bits
    bs_enc = b'\x03' + _encode_der_len(len(bit_string)) + bit_string

    # Prepend AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1)
    alg_id = b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00'
    spki_der = _encode_der_sequence(alg_id + bs_enc)

    # Attach the Challenge (IA5String)
    chal_bytes = challenge.encode('ascii')
    chal_enc = b'\x16' + _encode_der_len(len(chal_bytes)) + chal_bytes
    
    # Return the PublicKeyAndChallenge Sequence
    return _encode_der_sequence(spki_der + chal_enc)


def assemble_final_spkac(tbs_der: bytes, signature: bytes) -> str:
    ''' Combines the TBS block and signature into the final Base64 string '''
    
    # signatureAlgorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
    alg_id = b'\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0B\x05\x00'
    
    bit_string = b'\x00' + signature
    bs_enc = b'\x03' + _encode_der_len(len(bit_string)) + bit_string
    
    spkac_der = _encode_der_sequence(tbs_der + alg_id + bs_enc)
    return base64.b64encode(spkac_der).decode('utf-8')