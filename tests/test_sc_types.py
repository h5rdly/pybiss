import ctypes, sys, unittest

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src.sc_types import (
    SCARDCONTEXT, SCARDHANDLE, DWORD, MAX_ATR_SIZE,
    SCARD_IO_REQUEST, SCARD_READERSTATE,
    SCARD_S_SUCCESS, SCARD_W_REMOVED_CARD, SCARD_STATE_PRESENT
)


class TestSCTypes(unittest.TestCase):
    '''
    Sanity checks to ensure memory alignment and type definitions match 
    the native PC/SC C specification for the current operating system.
    '''

    def test_platform_handle_types(self):
        '''
        Verify that handles are mapped to the correct ctypes based on the OS.
        Windows uses pointers (c_void_p), Linux/macOS uses integers (c_long).
        Failure here causes immediate segfaults on 64-bit systems.
        '''

        if sys.platform == 'win32':
            assert SCARDCONTEXT == ctypes.c_void_p
            assert SCARDHANDLE == ctypes.c_void_p
        else:
            assert SCARDCONTEXT == ctypes.c_long
            assert SCARDHANDLE == ctypes.c_long


    def test_io_request_struct(self):
        ''' 
        Verify SCARD_IO_REQUEST memory layout.
        It consists of two DWORDs. Since PC/SC uses native alignment,
        the size should be exactly twice the size of the native DWORD.
        '''
        
        fields = [f[0] for f in SCARD_IO_REQUEST._fields_]
        
        assert fields[0] == 'dwProtocol'
        assert fields[1] == 'cbPciLength'
        
        expected_size = 2 * ctypes.sizeof(DWORD)
        assert ctypes.sizeof(SCARD_IO_REQUEST) == expected_size


    def test_readerstate_struct(self):
        '''
        Verify SCARD_READERSTATE memory layout and field ordering.
        This structure is passed back and forth for state monitoring.
        '''

        fields = [f[0] for f in SCARD_READERSTATE._fields_]
        
        assert fields[0] == 'szReader'
        assert fields[1] == 'pvUserData'
        assert fields[2] == 'dwCurrentState'
        assert fields[3] == 'dwEventState'
        assert fields[4] == 'cbAtr'
        assert fields[5] == 'rgbAtr'
        
        rs = SCARD_READERSTATE()
        
        # The ATR buffer must be exactly MAX_ATR_SIZE (33 bytes)
        assert ctypes.sizeof(rs.rgbAtr) == 33
        assert MAX_ATR_SIZE == 33


    def test_critical_constants(self):
        ''' Ensure critical hex codes weren't truncated or mistyped '''
        
        assert SCARD_S_SUCCESS == 0x00000000
        assert SCARD_W_REMOVED_CARD == 0x80100069
        assert SCARD_STATE_PRESENT == 0x0020


if __name__ == '__main__':
    unittest.main()