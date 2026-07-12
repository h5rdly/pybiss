import sys


from .cert_parser import DerReader


def pad_pkcs1_v15_sha256(hash_bytes: bytes, key_size_bits: int = 2048) -> bytes:
    '''
    Constructs the PKCS#1 v1.5 padding block for a SHA-256 hash.
    This is what you actually send to the smart card to be signed.
    
    Args:
        hash_bytes: The raw 32-byte SHA-256 hash of your document.
        key_size_bits: The size of the RSA key on the card (usually 2048).
    '''

    if len(hash_bytes) != 32:
        raise ValueError('SHA-256 hash must be exactly 32 bytes.')
        
    key_size_bytes = key_size_bits // 8
    
    # The static ASN.1 DER encoding that means 'This is a SHA-256 hash'
    asn1_sha256_oid = bytes.fromhex('3031300d060960864801650304020105000420')
    
    # The payload is the OID + the actual hash
    payload = asn1_sha256_oid + hash_bytes
    
    # PKCS#1 v1.5 padding structure: 00 01 [FF FF ... FF] 00 [Payload]
    pad_len = key_size_bytes - len(payload) - 3
    if pad_len < 8:
        raise ValueError('Key size is too small for this hash/padding.')
        
    return b'\x00\x01' + (b'\xFF' * pad_len) + b'\x00' + payload


def read_binary_file(card_connection, file_id: bytes) -> bytes:
    '''
    Selects a file on the smart card and reads its contents in 256-byte chunks.
    
    Args:
        card_connection: An active SmartCardConnection instance.
        file_id: The 2-byte File ID (e.g., b'\x43\x01').

    '''

    # SELECT FILE APDU
    # CLA=00, INS=A4 (Select), P1=02 (Select EF under current DF), P2=04 (Return FCI), Lc=02
    select_apdu = b'\x00\xA4\x02\x04\x02' + file_id
    resp = card_connection.transmit(select_apdu)
    
    if resp[-2:] != b'\x90\x00':
        raise Exception(f'Failed to select file {file_id.hex()}: {resp[-2:].hex()}')
    
    # READ BINARY APDU
    cert_data = bytearray()
    offset = 0
    
    while True:
        # CLA=00, INS=B0 (Read Binary), P1=High Offset, P2=Low Offset, Le=00 (Expect 256 bytes)
        p1 = (offset >> 8) & 0xFF
        p2 = offset & 0xFF
        read_apdu = bytes([0x00, 0xB0, p1, p2, 0x00])
        
        chunk = card_connection.transmit(read_apdu)
        status_word = chunk[-2:]
        data = chunk[:-2]
        
        if status_word == b'\x90\x00':
            # Success, we got a full 256-byte chunk
            cert_data.extend(data)
            offset += 256
        elif status_word[0] == 0x6C:
            # 6C XX: Wrong length expected. The card has XX bytes left.
            # We re-issue the command asking for exactly XX bytes.
            expected_len = status_word[1]
            read_apdu = bytes([0x00, 0xB0, p1, p2, expected_len])
            chunk = card_connection.transmit(read_apdu)
            if chunk[-2:] == b'\x90\x00':
                cert_data.extend(chunk[:-2])
            break
        elif status_word == b'\x62\x82':
            # 62 82: End of file reached before reading Le bytes
            # The card returned what it had left, and we are done.
            cert_data.extend(data)
            break
        else:
            raise Exception(f'Failed to read binary at offset {offset}: {status_word.hex()}')
            
    return bytes(cert_data)


def ber_tlv(tag: int, value: bytes) -> bytes:
    '''
    Encodes a BER-TLV data object with the standard ISO 7816-4 length forms.
    Needed because template payloads can exceed 127 bytes (e.g. a padded
    RSA signature input is 256 or 384 bytes).
    '''

    n = len(value)
    if n < 0x80:
        length = bytes([n])
    elif n <= 0xFF:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82]) + n.to_bytes(2, 'big')
    return bytes([tag]) + length + value


def build_apdu(cla: int, ins: int, p1: int, p2: int, data: bytes = b'', le: int = None) -> bytes:
    '''
    Safely builds an ISO-7816 APDU.
    Automatically handles Short vs Extended APDU limits.
    '''

    header = bytes([cla, ins, p1, p2])
    lc_val = len(data)
    
    # A Short APDU can handle up to 255 bytes of data and up to 256 bytes of expected response
    if lc_val <= 255 and (le is None or le <= 256):
        # --- Short APDU ---
        apdu = header
        if lc_val > 0:
            apdu += bytes([lc_val]) + data
        if le is not None:
            # Le=256 is encoded as 0x00 in a Short APDU
            apdu += bytes([le % 256])
        return apdu
    else:
        # --- Extended APDU ---
        apdu = header
        if lc_val > 0:
            # Lc is 3 bytes: 00 HighByte LowByte
            apdu += b'\x00' + lc_val.to_bytes(2, 'big') + data
            
        if le is not None:
            # Le=65536 is encoded as 0x0000 in Extended APDU
            le_encoded = le % 65536 
            if lc_val > 0:
                # If Lc was present, Le is 2 bytes at the tail
                apdu += le_encoded.to_bytes(2, 'big')
            else:
                # If no Lc, Le is 3 bytes: 00 HighByte LowByte
                apdu += b'\x00' + le_encoded.to_bytes(2, 'big')
        return apdu


def decode_ecdsa_signature(asn1_sig: bytes, curve_bytes: int = 32) -> bytes:
    '''
    Unwraps an ISO-7816 ASN.1 ECDSA signature (SEQUENCE { r INTEGER, s INTEGER })
    into the raw concatenated r||s format (64 bytes for P-256) expected by standard crypto APIs.
    '''

    reader = DerReader(asn1_sig)
    try:
        tag, val = reader.read_tlv()
        if tag != 0x30:
            return asn1_sig # Failsafe: Card already returned raw bytes
            
        seq = DerReader(val)
        _, r_bytes = seq.read_tlv()
        _, s_bytes = seq.read_tlv()
        
        # ASN.1 integers are signed. If the highest bit is 1, a leading 0x00 is added.
        # We must strip this padding to get the true mathematical integer bytes.
        if len(r_bytes) > curve_bytes and r_bytes[0] == 0x00: r_bytes = r_bytes[1:]
        if len(s_bytes) > curve_bytes and s_bytes[0] == 0x00: s_bytes = s_bytes[1:]
        
        # If the integer is smaller than the curve size, pad it with leading zeros
        r_bytes = r_bytes.rjust(curve_bytes, b'\x00')
        s_bytes = s_bytes.rjust(curve_bytes, b'\x00')
        
        return r_bytes + s_bytes
    except Exception:
        # If parsing fails, return raw bytes and hope the API handles it
        return asn1_sig


