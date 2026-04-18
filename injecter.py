import sys
from abc import ABC, abstractmethod
from typing import Optional

from pydivert import WinDivert, Packet


class TcpInjector(ABC):
    def __init__(self, w_filter: str, max_packets: int = 65535):
        self._filter = w_filter
        self._max_packets = max_packets
        self._divert: Optional[WinDivert] = None
        self._running = False

    @abstractmethod
    def inject(self, packet: Packet):
        raise NotImplementedError

    def start(self):
        if self._running:
            return
        self._divert = WinDivert(self._filter)
        self._running = True
        self._loop()

    def stop(self):
        self._running = False
        if self._divert:
            try:
                self._divert.close()
            except:
                pass
            self._divert = None

    def _loop(self):
        try:
            with self._divert:
                while self._running:
                    try:
                        packet = self._divert.recv(self._max_packets)
                        if not packet:
                            continue
                        self.inject(packet)
                    except KeyboardInterrupt:
                        break
                    except Exception:
                        continue
        finally:
            self.stop()
