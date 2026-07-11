import os, sys, time, hashlib

sys.path.append(__file__.replace('\\', '/').rsplit('/', 1)[0])

from cert_parser import get_x509_metadata, get_x509_subject, get_rsa_public_key, pem_to_der
from verifier import verify_rsa_pkcs1_v1_5


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


def filter_certificates(certs: list[dict], selector: dict = None, show_valid_certs: bool = True, now: int = None) -> list[dict]:
    ''' Filter certificates based on selector requirements and validity period (at time `now`) '''

    filtered = []
    now = int(time.time()) if now is None else now

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


def _is_self_signed(meta: dict) -> bool:
    ''' Root certificates carry no AKI, or an AKI equal to their own SKI '''

    return not meta.get('aki') or meta.get('aki') == meta.get('ski')


def _parse_candidates(candidates: list[bytes]) -> list[tuple[bytes, dict]]:
    ''' Parses each candidate DER once, silently skipping malformed ones '''

    parsed = []
    for der in candidates:
        try:
            parsed.append((der, get_x509_metadata(der)))
        except Exception:
            continue
    return parsed


def _walk_chain(leaf_der: bytes, leaf_meta: dict, parsed: list) -> tuple[list[bytes], dict]:
    '''
    Walks leaf -> intermediate(s) -> root by matching each certificate's AKI
    to the issuer's SKI
    '''

    chain = [leaf_der]
    current = leaf_meta

    while len(chain) < 8 and not _is_self_signed(current):
        aki = current.get('aki', '')
        parent = next(
            ((der, meta) for der, meta in parsed
             if meta.get('ski', '') == aki and der not in chain),
            None,
        )
        if not parent:
            break
        chain.append(parent[0])
        current = parent[1]

    return chain, current


def build_certificate_chain(leaf_der: bytes, candidates: list[bytes]) -> list[bytes]:
    ''' Orders certificates leaf -> intermediate(s) -> root '''

    return _walk_chain(leaf_der, get_x509_metadata(leaf_der), _parse_candidates(candidates))[0]


def chain_exists_for_key_identifier(key_identifier: str, candidates: list[bytes]) -> bool:
    '''
    Check if a complete certificate chain (leaf -> self-signed root) can be
    assembled for the certificate whose SKI matches key_identifier, using the
    given candidate certificates
    '''

    if not key_identifier:
        return False
    target = key_identifier.upper()

    parsed = _parse_candidates(candidates)
    leaf = next(((der, meta) for der, meta in parsed
                 if meta.get('ski', '').upper() == target), None)
    if leaf is None:
        return False

    _, tail = _walk_chain(leaf[0], leaf[1], parsed)
    return _is_self_signed(tail)


def load_ca_certificates(certs_dir: str) -> list[bytes]:
    ''' DER of every certificate found under certs_dir (PEM bundles included) '''

    if not os.path.isdir(certs_dir):
        return []

    ders = []
    for name in sorted(os.listdir(certs_dir)):
        if not name.lower().endswith(('.pem', '.crt', '.cer', '.der')):
            continue
        try:
            with open(os.path.join(certs_dir, name), 'rb') as f:
                ders.extend(pem_to_der(f.read()))
        except Exception:
            continue
    return ders


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