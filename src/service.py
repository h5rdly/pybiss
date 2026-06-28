import sys, time, hashlib

sys.path.append(__file__.rsplit('/', 1)[0])

from src.cert_parser import get_x509_metadata, get_x509_subject, get_rsa_public_key
from src.verifier import verify_rsa_pkcs1_v1_5


def _match_selector(metadata: dict, selector: dict) -> bool:
    ''' Verifies if a certificate matches the BISS criteria '''

    if not selector:
        return True

    if issuers := selector.get('issuers'):
        issuer_dn = metadata.get('issuer', '')
        if not any(issuer.lower() in issuer_dn.lower() for issuer in issuers):
            return False

    if akis := selector.get('akis'):
        cert_aki = metadata.get('aki')
        if not any(cert_aki and aki.upper() in cert_aki for aki in akis):
            return False

    if key_usages := selector.get('keyUsages'):
        cert_usages = metadata.get('key_usages', [])
        if any(usage not in cert_usages for usage in key_usages):
            return False

    return True


def filter_certificates(certs: list[dict], selector: dict = None, show_valid_certs: bool = True) -> list[dict]:
    ''' Filter certificates based on selector requirements and validity period '''
    
    filtered = []
    now = int(time.time())

    for c in certs:
        try:
            der_bytes = c['der']
            metadata = get_x509_metadata(der_bytes)
            
            if show_valid_certs:
                if now < metadata.get('not_before', 0) or now > metadata.get('not_after', 0):
                    continue
            
            if _match_selector(metadata, selector):
                c_copy = c.copy()
                c_copy['subject'] = get_x509_subject(der_bytes)
                c_copy['issuer'] = metadata.get('issuer', '')
                c_copy['serial'] = metadata.get('serial', '')
                filtered.append(c_copy)
                
        except Exception:
            continue
            
    return filtered


def verify_server_signature(payload: bytes, signature: bytes, server_cert_der: bytes, hash_alg: str) -> bool:
    
    try:
        # Extract the modulus (n) and exponent (e) directly from the CA certificate
        n, e = get_rsa_public_key(server_cert_der)
        
        alg_lower = hash_alg.replace('-', '').lower()
        if alg_lower == 'sha256':
            payload_hash = hashlib.sha256(payload).digest()
        elif alg_lower == 'sha512':
            payload_hash = hashlib.sha512(payload).digest()
        else:
            return False

        # Scheme A: Signature over ( hash(payload) + payload )
        combined_data = payload_hash + payload
        if verify_rsa_pkcs1_v1_5(combined_data, signature, n, e, hash_alg):
            return True

        # Scheme B: Signature over just the payload
        if verify_rsa_pkcs1_v1_5(payload, signature, n, e, hash_alg):
            return True

        return False
        
    except Exception:
        return False