import base64
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


def _decode_oid(oid_bytes: bytes) -> str:
    ''' Decodes DER OID content bytes to dotted notation (e.g. 2.5.29.14) '''

    parts = [str(oid_bytes[0] // 40), str(oid_bytes[0] % 40)]
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return '.'.join(parts)


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
    
    # SubjectPublicKeyInfo (SPKI) -> Extract Key Type and Parameters
    _, spki_val = tbs.read_tlv()
    spki = DerReader(spki_val)
    # Read AlgorithmIdentifier
    _, alg_id_val = spki.read_tlv()
    alg_id = DerReader(alg_id_val)
    _, oid = alg_id.read_tlv()
    n, e = 0, 0
    key_type = 'UNKNOWN'
    
    # rsaEncryption OID: 1.2.840.113549.1.1.1
    if oid == b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01':
        key_type = 'RSA'
        bit_string = spki.read_tlv()[1]
        pkcs1 = DerReader(bit_string[1:]).read_seq()
        n = int.from_bytes(pkcs1.read_tlv()[1], 'big')
        e = int.from_bytes(pkcs1.read_tlv()[1], 'big')
        
    # ecPublicKey OID: 1.2.840.10045.2.1
    elif oid == b'\x2a\x86\x48\xce\x3d\x02\x01':
        key_type = 'EC'
        # We don't need to parse the curve parameters for hardware signing
    

    # Extract Key Usages, AKI, SKI and the full extension map
    usages, aki, ski = [], '', ''
    extensions = {}
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

                # Raw extension value (OCTET STRING content) keyed by dotted OID
                extensions[_decode_oid(oid)] = e_val

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

                elif oid == b'\x55\x1d\x0e': # Subject Key Identifier (SKI)
                    ski = DerReader(e_val).read_tlv()[1].hex().upper()

    return {
        'serial': serial, 'issuer': issuer, 'subject': subject,
        'not_before': not_before, 'not_after': not_after,
        'key_usages': usages, 'aki': aki, 'ski': ski, 'n': n, 'e': e,
        'key_type': key_type, 'extensions': extensions,
    }


def pem_to_der(blob: bytes) -> list[bytes]:
    ''' Extract every certificate from a PEM blob. Handles multi-cert bundles '''

    if b'-----BEGIN CERTIFICATE-----' not in blob:
        return [blob]

    ders = []
    for chunk in blob.split(b'-----BEGIN CERTIFICATE-----')[1:]:
        body = chunk.split(b'-----END CERTIFICATE-----')[0]
        try:
            ders.append(base64.b64decode(b''.join(body.split()), validate=True))
        except Exception:
            continue
    return ders


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