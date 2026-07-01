import sys, unittest
from ctypes import (sizeof, c_ulong)

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.pkcs11_types import CKA_CLASS, CKO_CERTIFICATE, CKA_TOKEN, CKA_LABEL, CK_ATTRIBUTE
from src.hardware import _pack_template


class TestPkcs11Funcs(unittest.TestCase):
    ''' Tests the C-bindings and memory allocations for PKCS#11 '''

    def test_pack_template_memory_safety(self):
        ''' 
        Python dictionaries are safely converted to C-struct arrays
        and the memory references are kept alive to prevent Garbage Collection.
        '''
        
        template_dict = {
            CKA_CLASS: CKO_CERTIFICATE,
            CKA_TOKEN: True,
            CKA_LABEL: "Test Certificate"
        }
        
        # Call our packing helper
        c_attrs, refs = _pack_template(template_dict)
        
        # Ensure the array is the correct length
        assert len(c_attrs) == 3
        assert type(c_attrs[0]).__name__ == 'CK_ATTRIBUTE'
        
        # Ensure references are kept alive
        # We passed 3 values, so we should have 3 ctypes memory references holding the data
        assert len(refs) == 3
        
        # Verify the types were mapped correctly into C memory
        # CKA_CLASS (CKO_CERTIFICATE) should be mapped to a CK_ULONG (int)
        assert c_attrs[0].type == CKA_CLASS
        assert c_attrs[0].ulValueLen == sizeof(c_ulong)
        
        # CKA_LABEL ("Test Certificate") should be mapped to a byte array
        assert c_attrs[2].type == CKA_LABEL
        assert c_attrs[2].ulValueLen == len("Test Certificate".encode('utf-8'))


    def test_pack_template_bytes(self):
        ''' Raw byte arrays (like DER certificates) are packed correctly '''

        fake_der = b'\x30\x82\x01\x0a\x02\x82\x01\x01\x00'
        
        template_dict = {
            # Let's pretend CKA_VALUE is 0x00000011
            0x00000011: fake_der
        }
        
        c_attrs, refs = _pack_template(template_dict)
        
        assert c_attrs[0].type == 0x00000011
        # The length of the C-array should exactly match the length of the python bytes
        assert c_attrs[0].ulValueLen == len(fake_der)
        # The reference array must contain our byte array to prevent GC
        assert len(refs[0]) == len(fake_der)


if __name__ == '__main__':
    unittest.main()