import asyncio
import logging
import socket
import threading
import time

from pydivert import Packet

from monitor_connection import MonitorConnection
from injecter import TcpInjector


LOGGER = logging.getLogger("sni_spoofing.injector")


class FakeInjectiveConnection(MonitorConnection):
    def __init__(
        self,
        sock: socket.socket,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        fake_data: bytes,
        bypass_method: str,
        peer_sock: socket.socket,
    ):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()


class FakeTcpInjector(TcpInjector):
    FAKE_SEND_DELAY_SECONDS = 0.001

    def __init__(
        self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection]
    ):
        super().__init__(w_filter)
        self.connections = connections

    @staticmethod
    def _close_socket_quietly(sock: socket.socket):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

    def _close_connection_sockets_threadsafe(self, connection: FakeInjectiveConnection):
        def closer():
            self._close_socket_quietly(connection.sock)
            self._close_socket_quietly(connection.peer_sock)

        try:
            connection.running_loop.call_soon_threadsafe(closer)
        except Exception:
            closer()

    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        if self.FAKE_SEND_DELAY_SECONDS > 0:
            time.sleep(self.FAKE_SEND_DELAY_SECONDS)
        with connection.thread_lock:
            if not connection.monitor:
                return

            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xFFFF
            # if connection.bypass_method == "wrong_checksum":
            #     ...
            if connection.bypass_method == "wrong_seq":
                packet.tcp.seq_num = (
                    connection.syn_seq + 1 - len(packet.tcp.payload)
                ) & 0xFFFFFFFF
                connection.fake_sent = True
                self.w.send(packet, True)
            else:
                LOGGER.error("Unsupported bypass method: %s", connection.bypass_method)
                connection.monitor = False
                connection.t2a_msg = "unexpected_close"
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)

    def on_unexpected_packet(
        self, packet: Packet, connection: FakeInjectiveConnection, info_m: str
    ):
        LOGGER.warning(
            "%s src=%s:%s dst=%s:%s inbound=%s outbound=%s",
            info_m,
            packet.ip.src_addr,
            packet.tcp.src_port,
            packet.ip.dst_addr,
            packet.tcp.dst_port,
            packet.is_inbound,
            packet.is_outbound,
        )
        self._close_connection_sockets_threadsafe(connection)
        connection.monitor = False
        connection.t2a_msg = "unexpected_close"
        connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        self.w.send(packet, False)

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.syn_seq == -1:
            self.on_unexpected_packet(
                packet, connection, "unexpected inbound packet, no syn sent!"
            )
            return
        if (
            packet.tcp.ack
            and packet.tcp.syn
            and (not packet.tcp.rst)
            and (not packet.tcp.fin)
            and (len(packet.tcp.payload) == 0)
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected inbound syn-ack packet, seq change! "
                    + str(seq_num)
                    + " "
                    + str(connection.syn_ack_seq),
                )
                return
            if ack_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected inbound syn-ack packet, ack not matched! "
                    + str(ack_num)
                    + " "
                    + str(connection.syn_seq),
                )
                return
            connection.syn_ack_seq = seq_num
            self.w.send(packet, False)
            return
        if (
            packet.tcp.ack
            and (not packet.tcp.syn)
            and (not packet.tcp.rst)
            and (not packet.tcp.fin)
            and (len(packet.tcp.payload) == 0)
            and connection.fake_sent
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if (
                connection.syn_ack_seq == -1
                or ((connection.syn_ack_seq + 1) & 0xFFFFFFFF) != seq_num
            ):
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected inbound ack packet, seq not matched! "
                    + str(seq_num)
                    + " "
                    + str(connection.syn_ack_seq),
                )
                return
            if ack_num != ((connection.syn_seq + 1) & 0xFFFFFFFF):
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected inbound ack packet, ack not matched! "
                    + str(ack_num)
                    + " "
                    + str(connection.syn_seq),
                )
                return

            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            return
        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")
        return

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.on_unexpected_packet(
                packet,
                connection,
                "unexpected outbound packet, recv packet after fake sent!",
            )
            return
        if (
            packet.tcp.syn
            and (not packet.tcp.ack)
            and (not packet.tcp.rst)
            and (not packet.tcp.fin)
            and (len(packet.tcp.payload) == 0)
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected outbound syn packet, ack_num is not zero!",
                )
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected outbound syn packet, seq not matched! "
                    + str(seq_num)
                    + " "
                    + str(connection.syn_seq),
                )
                return
            connection.syn_seq = seq_num
            self.w.send(packet, False)
            return
        if (
            packet.tcp.ack
            and (not packet.tcp.syn)
            and (not packet.tcp.rst)
            and (not packet.tcp.fin)
            and (len(packet.tcp.payload) == 0)
        ):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if (
                connection.syn_seq == -1
                or ((connection.syn_seq + 1) & 0xFFFFFFFF) != seq_num
            ):
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected outbound ack packet, seq not matched! "
                    + str(seq_num)
                    + " "
                    + str(connection.syn_seq),
                )
                return
            if connection.syn_ack_seq == -1 or ack_num != (
                (connection.syn_ack_seq + 1) & 0xFFFFFFFF
            ):
                self.on_unexpected_packet(
                    packet,
                    connection,
                    "unexpected outbound ack packet, ack not matched! "
                    + str(ack_num)
                    + " "
                    + str(connection.syn_ack_seq),
                )
                return

            self.w.send(packet, False)
            connection.sch_fake_sent = True
            threading.Thread(
                target=self.fake_send_thread, args=(packet, connection), daemon=True
            ).start()
            return
        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")
        return

    def inject(self, packet: Packet):
        if packet.is_inbound:
            c_id = (
                packet.ip.dst_addr,
                packet.tcp.dst_port,
                packet.ip.src_addr,
                packet.tcp.src_port,
            )
            try:
                connection = self.connections[c_id]
            except KeyError:
                self.w.send(packet, False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_inbound_packet(packet, connection)
        elif packet.is_outbound:
            c_id = (
                packet.ip.src_addr,
                packet.tcp.src_port,
                packet.ip.dst_addr,
                packet.tcp.dst_port,
            )
            try:
                connection = self.connections[c_id]
            except KeyError:
                self.w.send(packet, False)
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        self.w.send(packet, False)
                        return
                    self.on_outbound_packet(packet, connection)
        else:
            LOGGER.error("Packet direction is neither inbound nor outbound")
            self.w.send(packet, False)
