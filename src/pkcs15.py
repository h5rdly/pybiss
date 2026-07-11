import sys, logging

sys.path.append(__file__.rsplit('/', 1)[0])

from sc_apdu import read_binary_file
from cert_parser import DerReader


logger = logging.getLogger(__name__)

# PKCS#15 Standard File IDs
ODF_FILE_ID = b'\x50\x31'

# ASN.1 Context-Specific Tags for PKCS#15
TAG_PRKDF = 0xA0  # Private Keys
TAG_PUKDF = 0xA1  # Public Keys
TAG_CDF   = 0xA4  # Certificates
TAG_AODF  = 0xA8  # Authentication Objects (PINs)


def _extract_path(val: bytes) -> bytes:
    ''' Recursively digs through an ASN.1 sequence to find the OCTET STRING (0x04) file path '''
    
    r = DerReader(val)
    while not r.is_empty():
        tag, data = r.read_tlv()
        if tag == 0x04:  # OCTET STRING (The file path)
            return data
        if tag == 0x30:  # SEQUENCE (If wrapped)
            return _extract_path(data)
    return None


def parse_cdf(cdf_bytes: bytes) -> list[dict]:
    ''' Parses the Certificate Directory File to map Key IDs to Physical File Paths '''
    
    certs = []
    reader = DerReader(cdf_bytes)
    while not reader.is_empty():
        try:
            tag, val = reader.read_tlv()
            if tag != 0x30: continue
            
            record = DerReader(val)
            
            # CommonObjectAttributes
            _, coa_val = record.read_tlv()
            coa = DerReader(coa_val)
            label, auth_id = '', None
            while not coa.is_empty():
                t, d = coa.read_tlv()
                if t == 0x0C: label = d.decode('utf-8', errors='ignore')
                elif t == 0x04: auth_id = d
            
            # ClassAttributes
            _, ca_val = record.read_tlv()
            ca = DerReader(ca_val)
            _, cert_id = ca.read_tlv() # OCTET STRING
            
            # Skip to TypeAttributes [1]
            path = None
            while not record.is_empty():
                t, d = record.read_tlv()
                if t == 0xA1: # [1] TypeAttributes
                    path = _extract_path(d)
                    break
                    
            if path and cert_id:
                certs.append({
                    'id': cert_id, 
                    'label': label, 
                    'path': path, 
                    'auth_id': auth_id
                })
        except Exception:
            continue

    return certs


def parse_prkdf(prkdf_bytes: bytes) -> list[dict]:
    ''' Parses the Private Key Directory File to map Key IDs to PIN References '''

    keys = []
    reader = DerReader(prkdf_bytes)
    while not reader.is_empty():
        try:
            tag, val = reader.read_tlv()
            if tag != 0x30: continue
            
            record = DerReader(val)
            
            # 1. CommonObjectAttributes [Sequence]
            _, coa_val = record.read_tlv()
            coa = DerReader(coa_val)
            label, auth_id = '', None
            while not coa.is_empty():
                t, d = coa.read_tlv()
                if t == 0x0C: 
                    label = d.decode('utf-8', errors='ignore')
                elif t == 0x04: 
                    auth_id = d
            
            # 2. ClassAttributes [Sequence]
            _, ca_val = record.read_tlv()
            ca = DerReader(ca_val)
            
            # Look specifically for the OCTET STRING (0x04) which holds the Key ID
            key_id = None
            while not ca.is_empty():
                t, d = ca.read_tlv()
                if t == 0x04:
                    key_id = d
                    break
            
            if key_id is not None:
                keys.append({
                    'id': key_id, 
                    'label': label, 
                    'auth_id': auth_id
                })
        except Exception as e:
            # Silently skip malformed records
            continue
            
    return keys


def _parse_pin_attributes(pa_val: bytes) -> dict:
    '''
    Parse a PKCS#15 PinAttributes SEQUENCE into the parameters needed to
    build a correct VERIFY APDU:

        pinFlags     BIT STRING           (skipped)
        pinType      ENUMERATED           -> pin_type  (0=bcd, 1=ascii-numeric, ...)
        minLength    INTEGER              -> min_length
        storedLength INTEGER              -> stored_length (the padded PIN length)
        maxLength    INTEGER OPTIONAL
        pinReference [0] INTEGER DEFAULT 0 -> pin_ref
        padChar      OCTET STRING OPTIONAL -> pad_char

    pin_ref prefers the spec's context-[0] tag; if a card (or fixture) encodes
    it as a plain INTEGER instead, the last plain integer is used as a fallback.
    '''

    info = {'pin_ref': None, 'pin_type': None, 'min_length': None,
            'stored_length': None, 'pad_char': None}
    integers = []

    pa = DerReader(pa_val)
    while not pa.is_empty():
        t, d = pa.read_tlv()
        if t == 0x0A:      # ENUMERATED pinType
            info['pin_type'] = int.from_bytes(d, 'big')
        elif t == 0x02:    # INTEGER (minLength, storedLength, maxLength ...)
            integers.append(int.from_bytes(d, 'big'))
        elif t == 0x80:    # context [0] pinReference (spec-correct)
            info['pin_ref'] = int.from_bytes(d, 'big')
        elif t == 0x04:    # OCTET STRING padChar
            info['pad_char'] = d[0] if d else None

    if integers:
        info['min_length'] = integers[0]
    if len(integers) >= 2:
        info['stored_length'] = integers[1]
    # Fallback: card encoded pinReference as a plain trailing INTEGER
    if info['pin_ref'] is None and integers:
        info['pin_ref'] = integers[-1]
        # That trailing integer was pinReference, not storedLength
        if len(integers) == 2:
            info['stored_length'] = None

    return info


def parse_aodf(aodf_bytes: bytes) -> dict:
    ''' Map each logical Auth ID to its PIN parameters (ref, type, padding) '''

    pins = {}
    reader = DerReader(aodf_bytes)
    while not reader.is_empty():
        try:
            tag, val = reader.read_tlv()
            # AODF entries are usually CHOICE. PINs are often [1] (0xA1) or SEQUENCE (0x30)
            if tag not in (0x30, 0xA1): continue

            record = DerReader(val)

            # CommonObjectAttributes
            _, coa_val = record.read_tlv()

            # CommonAuthenticationObjectAttributes -> Contains the logical Auth ID
            _, ca_val = record.read_tlv()
            ca = DerReader(ca_val)
            auth_id = None
            while not ca.is_empty():
                t, d = ca.read_tlv()
                if t == 0x04:  # OCTET STRING
                    auth_id = d
                    break

            # PinAttributes -> physical pinReference + padding parameters
            _, pa_val = record.read_tlv()
            info = _parse_pin_attributes(pa_val)

            if auth_id and info['pin_ref'] is not None:
                pins[auth_id] = info

        except Exception:
            continue

    return pins


# PKCS#15 pinType enumeration (subset we care about)
PIN_TYPE_BCD = 0
PIN_TYPE_ASCII_NUMERIC = 1
PIN_TYPE_UTF8 = 2


def encode_pkcs15_pin(pin: str, pin_info: dict = None) -> bytes:
    '''
    Encodes a PIN for a VERIFY / CHANGE APDU using the card's PinAttributes, 
    or the common B-Trust convention - ASCII, padded to 8 bytes with 0xFF
    '''

    info = pin_info or {}
    stored_length = info.get('stored_length') or 8
    pad_char = info.get('pad_char')
    pad_char = 0xFF if pad_char is None else pad_char
    min_length = info.get('min_length') or 4

    if not min_length <= len(pin) <= stored_length:
        raise ValueError(f'PIN/PUK must be {min_length} to {stored_length} characters long.')

    if info.get('pin_type') == PIN_TYPE_BCD:
        # BCD: two decimal digits per byte, control nibble 0x2, padded with 0xF
        digits = pin + 'F' * (stored_length * 2 - 1 - len(pin))
        body = bytes([len(pin)]) + bytes(
            int(digits[i:i+2], 16) for i in range(0, len(digits), 2)
        )
        return body[:stored_length]

    # ASCII / numeric-ASCII / UTF-8 all encode the digits as bytes, then pad
    return pin.encode('ascii').ljust(stored_length, bytes([pad_char]))


def parse_pkcs15_filesystem(card_connection) -> dict:
    '''
    Crawl the smart card filesystem and returns a mapped dictionary of 
    all Certificates, Private Keys, and PIN References
    '''

    filesystem_map = {
        'certificates': [],
        'private_keys': [],
        'pin_map': {}  
    }
    
    # Read the Object Directory File (ODF)
    try:
        odf_bytes = read_binary_file(card_connection, ODF_FILE_ID)
    except Exception as e:
        raise Exception(f'Failed to read ODF. Is this a PKCS#15 card? {e}')
        
    odf_reader = DerReader(odf_bytes)
    
    cdf_path = None
    prkdf_path = None
    aodf_path = None  
    
    # Find the Pointers for the CDF, PrKDF, and AODF
    while not odf_reader.is_empty():
        tag, val = odf_reader.read_tlv()
        
        # Some card vendors wrap ODF entries in a SEQUENCE (0x30).
        # If we see one, unwrap it to get to the actual CHOICE tag underneath.
        if tag == 0x30:
            inner = DerReader(val)
            if not inner.is_empty():
                tag, val = inner.read_tlv()
                
        if tag == TAG_CDF:
            cdf_path = _extract_path(val)
        elif tag == TAG_PRKDF:
            prkdf_path = _extract_path(val)
        elif tag == TAG_AODF:
            aodf_path = _extract_path(val)

    # Crawl the Certificate Directory
    if cdf_path:
        cdf_bytes = read_binary_file(card_connection, cdf_path)
        filesystem_map['certificates'] = parse_cdf(cdf_bytes)
        
        # Now automatically fetch the physical DER certificates off the hardware
        for cert in filesystem_map['certificates']:
            try:
                cert['der'] = read_binary_file(card_connection, cert['path'])
            except Exception:
                cert['der'] = b''
    
    # Crawl the Private Key Directory
    if prkdf_path:
        prkdf_bytes = read_binary_file(card_connection, prkdf_path)
        filesystem_map['private_keys'] = parse_prkdf(prkdf_bytes)

    # Crawl the Authentication Directory
    if aodf_path:
        try:
            aodf_bytes = read_binary_file(card_connection, aodf_path)
            filesystem_map['pin_map'] = parse_aodf(aodf_bytes)
        except Exception as e:
            logger.exception('Failed to parse AODF. The card might have an unexpected ASN.1 structure: {e}')
            pass
            
    return filesystem_map


