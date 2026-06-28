import ctypes, sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.pkcs11_types import CK_VERSION, CK_MECHANISM, CK_ATTRIBUTE, CK_TOKEN_INFO
from src.pkcs11_funcs import CK_FUNCTION_LIST


class TestPkcs11Types(unittest.TestCase):
    '''
    Sanity checks to ensure memory alignment matches the PKCS#11 C specification.
    Failure here means Python will segfault when calling the real DLL.
    '''

    def test_struct_packing(self):
        ''' Verify that all structures are 1-byte packed '''

        assert hasattr(CK_VERSION, '_pack_')
        assert CK_VERSION._pack_ == 1
        
        assert hasattr(CK_MECHANISM, '_pack_')
        assert CK_MECHANISM._pack_ == 1
        
        assert hasattr(CK_ATTRIBUTE, '_pack_')
        assert CK_ATTRIBUTE._pack_ == 1
        
        assert hasattr(CK_FUNCTION_LIST, '_pack_')
        assert CK_FUNCTION_LIST._pack_ == 1


    def test_version_struct_size(self):
        ''' CK_VERSION consists of two CK_BYTEs (uint8). Expected size: 2 bytes '''

        assert ctypes.sizeof(CK_VERSION) == 2


    def test_token_info_struct_size(self):
        ''' 
        Verify CK_TOKEN_INFO memory layout. 
        It contains fixed size char arrays and ULONGs.
        '''

        info = CK_TOKEN_INFO()
        
        # The label should be exactly 32 bytes
        assert ctypes.sizeof(info.label) == 32
        # The serial number should be exactly 16 bytes
        assert ctypes.sizeof(info.serialNumber) == 16
        # Hardware version is our 2-byte struct
        assert ctypes.sizeof(info.hardwareVersion) == 2


    def test_function_list_ordering(self):
        ''' 
        Validates the exact offset of critical C functions.
        If a field is missing, these offsets will shift and cause segfaults
        '''

        # We can extract the names of the fields in order
        fields = [f[0] for f in CK_FUNCTION_LIST._fields_]
        
        # Verify the first few are correct
        assert fields[0] == 'version'
        assert fields[1] == 'C_Initialize'
        assert fields[2] == 'C_Finalize'
        
        # Verify Session management is in the right place
        assert 'C_OpenSession' in fields
        assert 'C_CloseSession' in fields
        assert 'C_Login' in fields
        
        # Verify our new object management functions exist
        assert 'C_CreateObject' in fields
        assert 'C_GenerateKeyPair' in fields
        
        # Ensure C_GetAttributeValue is strictly BEFORE C_FindObjectsInit
        getattr_idx = fields.index('C_GetAttributeValue')
        findinit_idx = fields.index('C_FindObjectsInit')
        assert getattr_idx < findinit_idx, "Memory alignment mismatch!"


if __name__ == '__main__':
    unittest.main()