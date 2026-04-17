import asyncio
import socket
import threading
import time

from pydivert import Packet

from monitor_connection import MonitorConnection
from injecter import TcpInjector


class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str, peer_sock: socket.socket):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()
        # اضافه شده برای سازگاری با سیستم پاکسازی اتصالات رها شده در main.py
        self.created_at = time.time()


class FakeTcpInjector(TcpInjector):

    def __init__(self, w_filter: str, connections: dict[tuple, FakeInjectiveConnection]):
        super().__init__(w_filter)
        self.connections = connections

    def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
        # یک تاخیر بسیار کوتاه (۵ میلی‌ثانیه) خارج از Lock قرار داده شد 
        # تا سیستم‌عامل فرصت کند پکت ACK اصلی را در شبکه ارسال کند.
        time.sleep(0.005)
        
        with connection.thread_lock:
            if not connection.monitor:
                return

            packet.tcp.psh = True
            packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
            packet.tcp.payload = connection.fake_data
            if packet.ipv4:
                packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff
            
            # if connection.bypass_method == "wrong_checksum":
            #     ...
            
            if connection.bypass_method == "wrong_seq":
                packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
                connection.fake_sent = True
                try:
                    self.w.send(packet, True)
                except Exception as e:
                    print(f"خطا در تزریق پکت جعلی برای کانکشن {connection.id}: {e}")
            else:
                # به جای sys.exit که کل برنامه را می‌بندد، کانکشن فعلی را به عنوان نامعتبر رد می‌کنیم
                print(f"خطا: متد بای‌پس ناشناخته '{connection.bypass_method}'")
                self.on_unexpected_packet(packet, connection, "not implemented method!")

    def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
        # برای جلوگیری از اسپم شدن ترمینال، لاگ‌ها به شکل ساختاریافته چاپ می‌شوند
        # print(f"[{connection.src_port}->{connection.dst_port}] {info_m}")
        
        # بستن امن سوکت‌ها برای جلوگیری از Crash
        try:
            connection.sock.close()
        except Exception:
            pass
            
        try:
            connection.peer_sock.close()
        except Exception:
            pass
            
        connection.monitor = False
        connection.t2a_msg = "unexpected_close"
        
        # اطمینان از باز بودن Loop قبل از ارسال سیگنال
        try:
            if not connection.running_loop.is_closed():
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
        except Exception:
            pass
            
        try:
            self.w.send(packet, False)
        except Exception:
            pass

    def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.syn_seq == -1:
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
            return
            
        if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound syn-ack packet, seq change! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound syn-ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(connection.syn_seq))
                return
            connection.syn_ack_seq = seq_num
            
            try:
                self.w.send(packet, False)
            except Exception:
                pass
            return
            
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (
                not packet.tcp.fin) and (len(packet.tcp.payload) == 0) and connection.fake_sent:
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound ack packet, seq not matched! " + str(seq_num) + " " + str(
                                              connection.syn_ack_seq))
                return
            if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected inbound ack packet, ack not matched! " + str(ack_num) + " " + str(
                                              connection.syn_seq))
                return

            connection.monitor = False
            connection.t2a_msg = "fake_data_ack_recv"
            try:
                if not connection.running_loop.is_closed():
                    connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            except Exception:
                pass
            return
            
        self.on_unexpected_packet(packet, connection, "unexpected inbound packet")
        return

    def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
        if connection.sch_fake_sent:
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet, recv packet after fake sent!")
            return
            
        if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if ack_num != 0:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, ack_num is not zero!")
                return
            if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, seq not matched! " + str(
                    seq_num) + " " + str(connection.syn_seq))
                return
            connection.syn_seq = seq_num
            try:
                self.w.send(packet, False)
            except Exception:
                pass
            return
            
        if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                len(packet.tcp.payload) == 0):
            seq_num = packet.tcp.seq_num
            ack_num = packet.tcp.ack_num
            if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                self.on_unexpected_packet(packet, connection,
                                          "unexpected outbound ack packet, seq not matched! " + str(
                                              seq_num) + " " + str(
                                              connection.syn_seq))
                return
            if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                self.on_unexpected_packet(packet, connection,
                                          "unexpected outbound ack packet, ack not matched! " + str(
                                              ack_num) + " " + str(
                                              connection.syn_ack_seq))
                return

            try:
                self.w.send(packet, False)
            except Exception:
                pass
                
            connection.sch_fake_sent = True
            threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
            return
            
        self.on_unexpected_packet(packet, connection, "unexpected outbound packet")
        return

    def inject(self, packet: Packet):
        if packet.is_inbound:
            c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
            try:
                connection = self.connections[c_id]
            except KeyError:
                try:
                    self.w.send(packet, False)
                except Exception:
                    pass
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        try:
                            self.w.send(packet, False)
                        except Exception:
                            pass
                        return
                    self.on_inbound_packet(packet, connection)
                    
        elif packet.is_outbound:
            c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
            try:
                connection = self.connections[c_id]
            except KeyError:
                try:
                    self.w.send(packet, False)
                except Exception:
                    pass
            else:
                with connection.thread_lock:
                    if not connection.monitor:
                        try:
                            self.w.send(packet, False)
                        except Exception:
                            pass
                        return
                    self.on_outbound_packet(packet, connection)
        else:
            # sys.exit("impossible direction!") به طور کامل حذف شد تا برنامه کرش نکند
            try:
                self.w.send(packet, False)
            except Exception:
                pass
