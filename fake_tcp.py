import sys
import threading
import time
from pydivert import Packet
from monitor_connection import MonitorConnection
from injecter import TcpInjector


class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock, src_ip, dst_ip, src_port, dst_port, fake_data, bypass_method, peer_sock):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.t2a_event = threading.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock


class FakeTcpInjector(TcpInjector):

    def __init__(self, w_filter, connections):
        super().__init__(w_filter)
        self.connections = connections

    def _get_conn(self, packet):
        if packet.is_inbound:
            return (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
        if packet.is_outbound:
            return (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
        return None

    def fake_send(self, packet, conn):
        time.sleep(0.001)
        if not conn.monitor:
            return

        packet.tcp.psh = True
        packet.tcp.payload = conn.fake_data

        if packet.ipv4:
            packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff

        if conn.bypass_method != "wrong_seq":
            return

        packet.tcp.seq_num = (conn.syn_seq + 1 - len(conn.fake_data)) & 0xffffffff
        conn.w.send(packet, True)

    def handle_outbound(self, packet, conn):
        if conn.sch_fake_sent:
            conn.monitor = False
            return

        if packet.tcp.syn and not packet.tcp.ack:
            conn.syn_seq = packet.tcp.seq_num
            conn.w.send(packet, False)
            return

        if packet.tcp.ack and conn.syn_seq != -1:
            conn.sch_fake_sent = True
            conn.w.send(packet, False)
            threading.Thread(target=self.fake_send, args=(packet, conn), daemon=True).start()
            return

        conn.w.send(packet, False)

    def handle_inbound(self, packet, conn):
        if conn.syn_seq == -1:
            conn.w.send(packet, False)
            return

        if packet.tcp.syn and packet.tcp.ack:
            conn.syn_ack_seq = packet.tcp.seq_num
            conn.w.send(packet, False)
            return

        if packet.tcp.ack and conn.sch_fake_sent:
            conn.monitor = False
            conn.t2a_msg = "fake_data_ack_recv"
            conn.t2a_event.set()
            return

        conn.w.send(packet, False)

    def inject(self, packet: Packet):
        key = self._get_conn(packet)
        if not key:
            self.w.send(packet, False)
            return

        conn = self.connections.get(key)
        if not conn or not conn.monitor:
            self.w.send(packet, False)
            return

        if packet.is_inbound:
            self.handle_inbound(packet, conn)
        else:
            self.handle_outbound(packet, conn)
