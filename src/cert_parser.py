from datetime import datetime, timezone

class DerReader:

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def is_empty(self) -> bool:
        return self.pos >= len(self.data)


    def read_seq(self):
        ''' Expects a sequence and returns a new reader for its contents '''

        tag, val = self.read_tlv()
        if tag != 0x30:
            raise ValueError(f'Expected SEQUENCE (0x30), got {hex(tag)}')
        return DerReader(val)


    def read_tlv(self) -> tuple[int, bytes]:
        ''' Reads a Tag-Length-Value block and advances the pointer '''

        if self.pos >= len(self.data):
            raise ValueError("Unexpected EOF reading tag")
            
        tag = self.data[self.pos]
        self.pos += 1
        
        if self.pos >= len(self.data):
            raise ValueError("Unexpected EOF reading length")
            
        length = self.data[self.pos]
        self.pos += 1
        
        # Handle multi-byte lengths (e.g. > 127 bytes)
        if length & 0x80:
            num_bytes = length & 0x7F
            if self.pos + num_bytes > len(self.data):
                raise ValueError("Unexpected EOF reading multi-byte length")
                
            length = int.from_bytes(self.data[self.pos:self.pos + num_bytes], 'big')
            self.pos += num_bytes
        
        # Strict bounds check before slicing
        if self.pos + length > len(self.data):
            raise ValueError(f"Unexpected EOF reading value. Needs {length} bytes, but only {len(self.data) - self.pos} left.")
            
        val = self.data[self.pos:self.pos + length]
        self.pos += length

        return tag, val


def _decode_string(tag: int, val: bytes) -> str:
    
    if tag == 0x1E:  # BMPString (Microsoft AD CS often uses this)
        return val.decode('utf-16-be')
    return val.decode('utf-8', errors='ignore')


def _parse_name(name_der: bytes) -> str:
    ''' Extracts the X.509 distinguished name (DN) into a standard format '''

    parts = []
    outer = DerReader(name_der)
    while not outer.is_empty():
        _, set_val = outer.read_tlv()
        set_r = DerReader(set_val)
        while not set_r.is_empty():
            seq_r = DerReader(set_r.read_tlv()[1])
            oid = seq_r.read_tlv()[1]
            str_tag, str_val = seq_r.read_tlv()
            
            label = {
                b'\x55\x04\x03': 'CN',
                b'\x55\x04\x06': 'C',
                b'\x55\x04\x0a': 'O',
                b'\x55\x04\x0b': 'OU'
            }.get(oid, 'Unknown')
            
            parts.append(f'{label}={_decode_string(str_tag, str_val)}')
            
    parts.reverse() # Reverse to match RFC4514 representation
    return ','.join(parts)



def _parse_time(tag: int, val: bytes) -> int:

    s = val.decode('ascii')
    if tag == 0x17:  # UTCTime (YYMMDDHHMMSSZ)
        y = int(s[:2])
        y += 2000 if y < 50 else 1900
        s = f'{y}{s[2:]}'
    
    # GeneralizedTime is already YYYYMMDDHHMMSSZ
    dt = datetime.strptime(s[:14], '%Y%m%d%H%M%S')

    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def parse_certificate(der_bytes: bytes) -> dict:
    ''' Parses an X.509 DER certificate to extract B-Trust metadata '''

    cert = DerReader(der_bytes).read_seq()
    tbs = cert.read_seq()
    
    # Version (Optional [0])
    tag, val = tbs.read_tlv()
    if tag == 0xA0:
        tag, val = tbs.read_tlv() # Move to Serial
        
    # Serial Number
    serial = str(int.from_bytes(val, 'big'))
    
    # Signature Algorithm (Skip)
    tbs.read_tlv() 
    
    # Issuer Name
    _, issuer_val = tbs.read_tlv()
    issuer = _parse_name(issuer_val)
    
    # Validity Timestamps
    validity = DerReader(tbs.read_tlv()[1])
    not_before = _parse_time(*validity.read_tlv())
    not_after = _parse_time(*validity.read_tlv())
    
    # Subject Name
    _, subject_val = tbs.read_tlv()
    subject = _parse_name(subject_val)
    
    # SubjectPublicKeyInfo (SPKI) -> RSA Modulus and Exponent
    _, spki_val = tbs.read_tlv()
    spki = DerReader(spki_val)
    spki.read_tlv() # Skip AlgorithmIdentifier
    bit_string = spki.read_tlv()[1]
    
    pkcs1 = DerReader(bit_string[1:]).read_seq()
    n = int.from_bytes(pkcs1.read_tlv()[1], 'big')
    e = int.from_bytes(pkcs1.read_tlv()[1], 'big')
    
    # Extract Key Usages and AKI from Extensions
    usages, aki = [], ''
    while not tbs.is_empty():
        ext_tag, ext_val = tbs.read_tlv()
        if ext_tag == 0xA3: # Extensions [3]
            ext_seq = DerReader(ext_val).read_seq()
            while not ext_seq.is_empty():
                ext = DerReader(ext_seq.read_tlv()[1])
                oid = ext.read_tlv()[1]
                
                e_tag, e_val = ext.read_tlv()
                if e_tag == 0x01: # Skip Boolean CRITICAL flag
                    e_tag, e_val = ext.read_tlv()
                    
                if oid == b'\x55\x1d\x0f': # Key Usage
                    bits = DerReader(e_val).read_tlv()[1]
                    if len(bits) > 1:
                        b = bits[1]
                        if b & 0x80: usages.append('digitalSignature')
                        if b & 0x40: usages.append('nonRepudiation')
                        if b & 0x20: usages.append('keyEncipherment')
                
                elif oid == b'\x55\x1d\x23': # Authority Key Identifier (AKI)
                    inner = DerReader(e_val).read_seq()
                    if not inner.is_empty():
                        a_tag, a_val = inner.read_tlv()
                        if a_tag == 0x80: # [0] KeyIdentifier
                            aki = a_val.hex().upper()

    return {
        'serial': serial, 'issuer': issuer, 'subject': subject,
        'not_before': not_before, 'not_after': not_after,
        'key_usages': usages, 'aki': aki, 'n': n, 'e': e
    }


def get_x509_subject(der_bytes: bytes) -> str:
    subject_str = parse_certificate(der_bytes)['subject']
    for part in subject_str.split(','):
        if part.startswith('CN='): return part[3:]
    return 'Unknown Subject'


def get_x509_metadata(der_bytes: bytes) -> dict:
    return parse_certificate(der_bytes)


def get_rsa_public_key(der_bytes: bytes) -> tuple[int, int]:
    cert = parse_certificate(der_bytes)
    return cert['n'], cert['e']