import json


class TracingConnection:
    '''
    Transparent wrapper around a SmartCardConnection (or any object exposing
    transmit()/get_atr()/transaction()) that records every APDU exchange
    '''

    def __init__(self, connection):
        self._conn = connection
        self.atr = None
        self.exchanges = []  # list of {'apdu': hex, 'response': hex}

    def get_atr(self) -> bytes:
        atr = self._conn.get_atr()
        self.atr = atr.hex().upper()
        return atr

    def transmit(self, apdu_bytes: bytes) -> bytes:
        response = self._conn.transmit(apdu_bytes)
        self.exchanges.append({
            'apdu': apdu_bytes.hex().upper(),
            'response': response.hex().upper(),
        })
        return response

    def transaction(self):
        # Pass the card lock straight through if the underlying connection has one
        return self._conn.transaction()

    def to_dict(self) -> dict:
        if self.atr is None:
            try:
                self.get_atr()
            except Exception:
                pass
        return {'atr': self.atr, 'exchanges': self.exchanges}

    def save(self, path: str):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2)


class ReplayConnection:
    ''' Replay a recorded trace as a SmartCardConnection, with no hardware '''
   
    def __init__(self, atr: bytes = b'', exchanges: list = None, sequential: bool = False):
        '''  When an APDU appears multiple times, its responses are returned in recorded 
             order. Set sequential=True to instead replay strictly in the recorded order
        '''
        
        self.atr = atr
        self.exchanges = exchanges or []
        self.sequential = sequential
        self._pos = 0
        # apdu (bytes) -> queue of response bytes, preserving recorded order
        self._by_apdu = {}
        for ex in self.exchanges:
            apdu = bytes.fromhex(ex['apdu'])
            self._by_apdu.setdefault(apdu, []).append(bytes.fromhex(ex['response']))

    @classmethod
    def from_dict(cls, data: dict, sequential: bool = False) -> 'ReplayConnection':
        atr = bytes.fromhex(data.get('atr') or '')
        return cls(atr=atr, exchanges=data.get('exchanges', []), sequential=sequential)

    @classmethod
    def load(cls, path: str, sequential: bool = False) -> 'ReplayConnection':
        with open(path, 'r', encoding='utf-8') as f:
            return cls.from_dict(json.load(f), sequential=sequential)

    def get_atr(self) -> bytes:
        return self.atr

    def transmit(self, apdu_bytes: bytes) -> bytes:
        if self.sequential:
            if self._pos >= len(self.exchanges):
                raise Exception('Replay exhausted: no more recorded exchanges')
            ex = self.exchanges[self._pos]
            if bytes.fromhex(ex['apdu']) != apdu_bytes:
                raise Exception(
                    f"Replay mismatch at step {self._pos}: "
                    f"expected {ex['apdu']}, got {apdu_bytes.hex().upper()}"
                )
            self._pos += 1
            return bytes.fromhex(ex['response'])

        queue = self._by_apdu.get(apdu_bytes)
        if not queue:
            raise Exception(f'No recorded response for APDU {apdu_bytes.hex().upper()}')
        # Repeat the last response once a single-shot APDU's queue is drained
        return queue.pop(0) if len(queue) > 1 else queue[0]
