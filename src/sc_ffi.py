import sys
from ctypes import byref, c_ubyte, create_string_buffer
from contextlib import contextmanager

sys.path.append(__file__.rsplit('/', 1)[0])

from src.sc_types import * 


# --- High-Level Pythonic Encapsulation ---

def establish_context() -> SCARDCONTEXT:
    ''' Initializes the PC/SC subsystem '''

    hcontext = SCARDCONTEXT()
    res = SCardEstablishContext_fn(SCARD_SCOPE_USER, None, None, byref(hcontext))
    if res != SCARD_S_SUCCESS:
        raise Exception(f'SCardEstablishContext failed: {hex(res)}')
    return hcontext


def release_context(hcontext: SCARDCONTEXT):
    ''' Frees the PC/SC subsystem resources '''
    SCardReleaseContext_fn(hcontext)


def disconnect_card(hcard: SCARDHANDLE, disposition=SCARD_RESET_CARD):
    ''' Disconnects from the card '''

    SCardDisconnect_fn(hcard, disposition)


def list_readers(hcontext: SCARDCONTEXT) -> list[str]:
    ''' Returns a list of connected smart card readers '''

    length = DWORD(0)
    # First pass: get required buffer length
    res = SCardListReaders_fn(hcontext, None, None, byref(length))
    if res != SCARD_S_SUCCESS:
        return []
    
    # Second pass: fetch the readers
    buffer = create_string_buffer(length.value)
    res = SCardListReaders_fn(hcontext, None, buffer, byref(length))
    if res != SCARD_S_SUCCESS:
        return []
    
    # PC/SC returns a double-null terminated array of strings
    raw_bytes = buffer.raw[:length.value - 2] 
    return [r.decode('utf-8', errors='ignore') for r in raw_bytes.split(b'\x00') if r]


def connect_card(hcontext: SCARDCONTEXT, reader_name: str):
    ''' Connects to a card in the specified reader '''

    hcard = SCARDHANDLE()
    active_proto = DWORD()
    
    res = SCardConnect_fn(
        hcontext, 
        reader_name.encode('utf-8'), 
        SCARD_SHARE_SHARED, 
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, 
        byref(hcard), 
        byref(active_proto)
    )
    if res != SCARD_S_SUCCESS:
        raise Exception(f'SCardConnect failed: {hex(res)}')
    return hcard, active_proto.value


def get_atr(hcard: SCARDHANDLE) -> bytes:
    ''' Retrieves the Answer To Reset (ATR) bytes of the connected card '''

    reader_len = DWORD(0)
    state = DWORD()
    protocol = DWORD()
    atr_len = DWORD(MAX_ATR_SIZE)
    atr_buf = (c_ubyte * MAX_ATR_SIZE)()
    
    res = SCardStatus_fn(hcard, None, byref(reader_len), byref(state), byref(protocol), atr_buf, byref(atr_len))
    if res != SCARD_S_SUCCESS:
        raise Exception(f'SCardStatus failed: {hex(res)}')
        
    return bytes(atr_buf[:atr_len.value])


@contextmanager
def transaction(hcard: SCARDHANDLE):
    '''
    Context manager to lock the card for exclusive access.
    Usage:
        with transaction(card_handle):
            transmit_apdu(...)
            transmit_apdu(...)
    '''

    res = SCardBeginTransaction_fn(hcard)
    if res != SCARD_S_SUCCESS:
        raise Exception(f'SCardBeginTransaction failed: {hex(res)}')
    try:
        yield
    finally:
        # End transaction and leave the card in its current state
        SCardEndTransaction_fn(hcard, SCARD_LEAVE_CARD)


def transmit_apdu(hcard: SCARDHANDLE, apdu_bytes: bytes, protocol: int = SCARD_PROTOCOL_T0) -> bytes:
    ''' Sends an APDU to the card and returns the response '''

    apdu_length = len(apdu_bytes)
    send_buffer = (c_ubyte * apdu_length).from_buffer_copy(apdu_bytes)
    
    recv_length = DWORD(MAX_BUFFER_SIZE_EXTENDED)
    recv_buffer = (c_ubyte * recv_length.value)()
    
    pci_pointer = byref(g_rgSCardT0Pci) if protocol == SCARD_PROTOCOL_T0 else byref(g_rgSCardT1Pci)
    
    res = SCardTransmit_fn(
        hcard,
        pci_pointer,
        send_buffer,
        DWORD(apdu_length),
        None,
        recv_buffer,
        byref(recv_length)
    )
    
    if res != SCARD_S_SUCCESS:
        raise Exception(f'SCardTransmit failed: {hex(res)}')
        
    return bytes(recv_buffer[:recv_length.value])


# --- The High-Level Context Manager ---

class SmartCardConnection:
    '''
    A high-level context manager that handles the full lifecycle of a smart card connection.
    Automatically establishes context, finds the reader, connects, and cleans up on exit.
    '''

    def __init__(self, reader_index: int = 0):

        self.reader_index = reader_index
        self.hcontext = None
        self.hcard = None
        self.protocol = None

    def __enter__(self):

        # Establish PC/SC Context
        self.hcontext = establish_context()
        
        # Find Readers
        readers = list_readers(self.hcontext)
        if not readers:
            # Clean up context before raising exception
            release_context(self.hcontext)
            raise Exception('No smart card readers detected.')
            
        if self.reader_index >= len(readers):
            release_context(self.hcontext)
            raise Exception(f'Reader index {self.reader_index} out of bounds. Found {len(readers)} readers.')

        # Connect to Card
        try:
            self.hcard, self.protocol = connect_card(self.hcontext, readers[self.reader_index])
        except Exception as e:
            release_context(self.hcontext)
            raise Exception(f'Failed to connect to card in reader {readers[self.reader_index]}: {e}')
            
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):

        # Safely teardown everything in reverse order
        if self.hcard:
            disconnect_card(self.hcard)
        if self.hcontext:
            release_context(self.hcontext)


    def transmit(self, apdu_bytes: bytes) -> bytes:
        ''' Helper to transmit an APDU using the active protocol '''

        return transmit_apdu(self.hcard, apdu_bytes, self.protocol)

    def transaction(self):
        ''' Helper to lock the card (returns the contextmanager from sc_ffi) '''

        return transaction(self.hcard)
        
    def get_atr(self) -> bytes:
        ''' Helper to get the ATR '''
        return get_atr(self.hcard)


# --- Example Specific B-Trust Usage ---

def verify_btrust_pin(pin_string: str):
    ''' Verify a PIN on a B-Trust card '''

    # This block automatically connects to the first reader
    # and cleans up memory / disconnects when the block ends.
    with SmartCardConnection() as card:
        
        print(f'Card ATR: {card.get_atr().hex().upper()}')
        
        # Lock the card so background OS processes don't interrupt the sequence
        with card.transaction():
            
            # Select the B-Trust / PKCS#15 Applet
            # (Example AID, replace with exact B-Trust AID from OpenSC logs)
            select_apdu = b'\x00\xA4\x04\x00\x0C\xA0\x00\x00\x00\x18\x80\x00\x00\x00\x06\x62'
            resp = card.transmit(select_apdu)
            
            if resp[-2:] != b'\x90\x00':
                raise Exception(f'Applet selection failed: {resp[-2:].hex()}')
            print('Applet selected successfully.')
            
            # Format the PIN APDU
            # B-Trust usually expects ASCII PIN padded with 0xFF.
            pin_bytes = pin_string.encode('ascii').ljust(8, b'\xFF')
            verify_apdu = b'\x00\x20\x00\x81\x08' + pin_bytes
            
            resp = card.transmit(verify_apdu)
            
            if resp[-2:] == b'\x90\x00':
                print('PIN Verified Successfully!')
            elif resp[-2] == 0x63:
                # 0x63 0xCX means Verification Failed, X retries remaining
                retries_left = resp[-1] & 0x0F
                print(f'Incorrect PIN! {retries_left} retries remaining.')
            elif resp[-2:] == b'\x69\x83':
                print('Card is blocked!')
            else:
                print(f'Unknown PIN error: {resp[-2:].hex()}')

