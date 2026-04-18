from abc import ABC, abstractmethod

from pydivert import WinDivert, Packet


# from pydivert.consts import *


class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        # self.interface_ipv4 = interface_ipv4
        # self.interface_ipv6 = interface_ipv6
        # ip_filter = ip4_filter = ip6_filter = ""
        # if self.interface_ipv4:
        #     ip4_filter = "(ip.SrcAddr == " + self.interface_ipv4 + " or ip.DstAddr == " + self.interface_ipv4 + ")"
        #     ip_filter = ip4_filter
        # if self.interface_ipv6:
        #     ip6_filter = "(ipv6.SrcAddr == " + self.interface_ipv6 + " or ipv6.DstAddr == " + self.interface_ipv6 + ")"
        #     ip_filter = ip6_filter
        # if self.interface_ipv4 and self.interface_ipv6:
        #     ip_filter = "(" + ip4_filter + " or " + ip6_filter + ")"
        #
        # self.filter = "tcp"
        # if ip_filter:
        #     self.filter += " and " + ip_filter
        self.w: WinDivert = WinDivert(w_filter)

    @abstractmethod
    def inject(self, packet: Packet):
        raise NotImplementedError("inject must be implemented by subclasses")

    def run(self):
        with self.w:
            while True:
                packet = self.w.recv(65575)
                self.inject(packet)
