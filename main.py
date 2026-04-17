import asyncio
import os
import socket
import sys
import traceback
import threading
import json
import time

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    """مسیر قرارگیری فایل اجرایی (PyInstaller) یا اسکریپت جاری را برمی‌گرداند."""
    if getattr(sys, 'frozen', False):
        # در حال اجرا به عنوان فایل EXE تولید شده توسط PyInstaller
        return os.path.dirname(sys.executable)
    else:
        # در حال اجرا به عنوان اسکریپت معمولی پایتون
        return os.path.dirname(os.path.abspath(__file__))


# بارگذاری پیکربندی از فایل config.json
config_path = os.path.join(get_exe_dir(), 'config.json')
try:
    with open(config_path, 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print(f"خطا: فایل پیکربندی در مسیر {config_path} پیدا نشد.")
    sys.exit(1)
except json.JSONDecodeError:
    print(f"خطا: ساختار فایل {config_path} معتبر نیست.")
    sys.exit(1)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

# نگهداری وضعیت تمامی اتصالات فعال جهت مدیریت توسط اینجکتور
fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


async def cleanup_stale_connections():
    """
    تسک پس‌زمینه برای پاکسازی اتصالات رها شده یا قدیمی.
    این تابع از پر شدن حافظه رم در اثر تجمیع کلیدهای دیکشنری جلوگیری می‌کند.
    """
    while True:
        try:
            await asyncio.sleep(60)  # بررسی هر ۶۰ ثانیه یک‌بار
            current_time = time.time()
            stale_keys = []
            
            # پیدا کردن کانکشن‌هایی که بیش از ۶۰ ثانیه از عمرشان می‌گذرد و هنوز فعال هستند
            for conn_id, conn in fake_injective_connections.items():
                # نکته: باید فیلد created_at را به کلاس MonitorConnection اضافه کنید
                conn_age = current_time - getattr(conn, 'created_at', current_time)
                if conn_age > 60:
                    stale_keys.append(conn_id)
            
            for key in stale_keys:
                try:
                    conn = fake_injective_connections[key]
                    conn.monitor = False
                    del fake_injective_connections[key]
                except KeyError:
                    pass
        except Exception as e:
            print(f"خطا در سیستم پاکسازی: {repr(e)}")


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task,
                          first_prefix_data: bytes):
    """
    حلقه اصلی انتقال داده بین سوکت ورودی و خروجی.
    در صورت بروز خطا یا اتمام دیتا، هر دو سوکت را به صورت امن می‌بندد.
    """
    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                data = await loop.sock_recv(sock_1, 65575)
                if not data:
                    break
                
                if first_prefix_data:
                    data = first_prefix_data + data
                    first_prefix_data = b""
                
                await loop.sock_sendall(sock_2, data)
            except (ConnectionResetError, BrokenPipeError, TimeoutError):
                break
            except Exception as e:
                print(f"خطای غیرمنتظره در رله: {repr(e)}")
                break
    finally:
        # بستن امن سوکت‌ها (TCP Half-Close)
        try:
            sock_2.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        sock_1.close()
        sock_2.close()
        
        # لغو تسک متناظر (طرف دیگر رله)
        if not peer_task.done():
            peer_task.cancel()


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    """
    مدیریت هر اتصال ورودی کلاینت.
    ایجاد سوکت خروجی، تزریق پکت جعلی و برقراری رله دوطرفه.
    """
    outgoing_sock = None
    fake_injective_conn = None
    try:
        loop = asyncio.get_running_loop()
        
        # تولید محتوای TLS ClientHello برای تزریق
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            print(f"حالت داده '{DATA_MODE}' پشتیبانی نمی‌شود.")
            incoming_sock.close()
            return

        # ایجاد سوکت برای اتصال به مقصد اصلی
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        
        # تنظیمات بهینه‌سازی سوکت و Keep-Alive برای پایداری در اینترنت ایران
        for s in [incoming_sock, outgoing_sock]:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

        outgoing_sock.bind((INTERFACE_IPV4, 0))
        src_port = outgoing_sock.getsockname()[1]
        
        # تعریف وضعیت اتصال برای اینجکتور WinDivert
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        
        # تنظیم زمان شروع برای جلوگیری از نشت حافظه
        fake_injective_conn.created_at = time.time()
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        
        try:
            # شروع فرآیند Handshake در لایه TCP
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception as e:
            print(f"اتصال به مقصد ({CONNECT_IP}:{CONNECT_PORT}) ناموفق بود: {e}")
            return

        # انتظار برای اتمام تزریق پکت جعلی (SNI Spoofing)
        if BYPASS_METHOD == "wrong_seq":
            try:
                # انتظار حداکثر ۵ ثانیه برای تایید تزریق توسط اینجکتور
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 5)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    return
                if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    pass
            except asyncio.TimeoutError:
                print(f"زمان انتظار برای تزریق پکت به پایان رسید (Timeout).")
                return
        else:
            print(f"متد بای‌پس '{BYPASS_METHOD}' تعریف نشده است.")
            return

        # غیرفعال سازی مانیتورینگ برای این اتصال (چون تزریق با موفقیت انجام شد)
        fake_injective_conn.monitor = False
        if fake_injective_conn.id in fake_injective_connections:
            del fake_injective_connections[fake_injective_conn.id]

        # شروع انتقال دوطرفه ترافیک (Relay)
        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task(), b""))
        
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"")

    except Exception:
        traceback.print_exc()
    finally:
        # اطمینان از پاکسازی دیکشنری و بستن سوکت‌ها در هر شرایطی
        if fake_injective_conn and fake_injective_conn.id in fake_injective_connections:
            fake_injective_conn.monitor = False
            del fake_injective_connections[fake_injective_conn.id]
            
        if outgoing_sock:
            outgoing_sock.close()
        incoming_sock.close()


async def main():
    """نقطه شروع سرور آسینک پایتون."""
    # اجرای سیستم پاکسازی خودکار حافظه
    asyncio.create_task(cleanup_stale_connections())
    
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    except Exception as e:
        print(f"خطا: امکان گوش دادن روی {LISTEN_HOST}:{LISTEN_PORT} وجود ندارد. {e}")
        sys.exit(1)
        
    mother_sock.listen()
    print(f"سرور روی {LISTEN_HOST}:{LISTEN_PORT} با موفقیت اجرا شد.")
    
    loop = asyncio.get_running_loop()
    while True:
        try:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            asyncio.create_task(handle(incoming_sock, addr))
        except Exception as e:
            print(f"خطا در پذیرش اتصال جدید: {repr(e)}")


if __name__ == "__main__":
    # بررسی وجود اینترفیس شبکه معتبر
    if not INTERFACE_IPV4:
        print("خطا: اینترفیس شبکه IPv4 یافت نشد. وضعیت اتصال اینترنت را چک کنید.")
        sys.exit(1)

    # تعریف فیلتر WinDivert بر اساس IP مبدا و مقصد برای افزایش کارایی (Performance)
    w_filter = (
        f"tcp and ("
        f"(ip.SrcAddr == {INTERFACE_IPV4} and ip.DstAddr == {CONNECT_IP}) or "
        f"(ip.SrcAddr == {CONNECT_IP} and ip.DstAddr == {INTERFACE_IPV4})"
        f")"
    )
    
    # راه اندازی اینجکتور در یک ترد (Thread) مجزا برای جلوگیری از مسدود شدن Event Loop
    try:
        fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
        threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    except Exception as e:
        print(f"خطا در راه اندازی اینجکتور (احتمالاً عدم دسترسی Administrator یا نبود درایور WinDivert): {e}")
        sys.exit(1)

    print("---------------------------------------------------------")
    print("SNI-Spoofing Service is Running.")
    print(f"Local Proxy: {LISTEN_HOST}:{LISTEN_PORT}")
    print(f"Targeting: {CONNECT_IP}:{CONNECT_PORT}")
    print("---------------------------------------------------------")
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424")
    print("@patterniha")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nبرنامه توسط کاربر متوقف شد.")
    except Exception as e:
        print(f"\nخطای بحرانی در اجرای برنامه: {traceback.format_exc()}")
