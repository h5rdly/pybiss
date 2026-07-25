import sys, unittest
from ctypes import sizeof

sys.path.append(__file__.replace('\\', '/').rsplit('/', 2)[0])

from src import sc_types


def _pcsc_or_skip():
    try:
        return sc_types.pcsc()
    except (OSError, NotImplementedError) as e:
        raise unittest.SkipTest(f'no PC/SC library on this box: {e}')


class TestPcscAbi(unittest.TestCase):

    def setUp(self):
        self.p = _pcsc_or_skip()

    def test_struct_size_matches_what_the_library_reports(self):
        '''
        cbPciLength in the exported T0 PCI block IS the library's own
        sizeof(SCARD_IO_REQUEST). If our declaration disagrees, every
        SCardTransmit gets a malformed PCI block.
        '''

        assert self.p.g_rgSCardT0Pci.cbPciLength == sizeof(sc_types.SCARD_IO_REQUEST), (
            'SCARD_IO_REQUEST size disagrees with the PC/SC library - '
            'the DWORD width in sc_types is wrong for this platform')

    def test_protocol_constants_read_back_correctly(self):
        # A wrong DWORD width shows up here first: on macOS with c_ulong this
        # read 0x800000001 (both of Apple's uint32 fields at once) instead of 1.
        assert self.p.g_rgSCardT0Pci.dwProtocol == sc_types.SCARD_PROTOCOL_T0
        assert self.p.g_rgSCardT1Pci.dwProtocol == sc_types.SCARD_PROTOCOL_T1

    def test_declared_widths_match_the_platform(self):
        ''' The widths each PC/SC implementation actually uses '''

        if sys.platform == 'darwin':
            # Apple: DWORD=uint32_t, LONG=int32_t, SCARDCONTEXT=int32_t
            expected = 4
        elif sys.platform == 'win32':
            expected = 4                      # LLP64: Win32 DWORD is 32-bit
        else:
            expected = sizeof(sc_types.c_ulong)   # pcsc-lite: unsigned long
        assert sizeof(sc_types.DWORD) == expected
        assert sizeof(sc_types.LONG) == expected

    def test_every_scard_function_bound(self):
        for fn in ('SCardEstablishContext_fn', 'SCardListReaders_fn', 'SCardConnect_fn',
                   'SCardTransmit_fn', 'SCardDisconnect_fn', 'SCardReleaseContext_fn',
                   'SCardBeginTransaction_fn', 'SCardEndTransaction_fn', 'SCardStatus_fn'):
            assert callable(getattr(self.p, fn)), f'{fn} not bound'


if __name__ == '__main__':
    unittest.main()
