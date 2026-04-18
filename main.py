import asyncio
import ipaddress
import logging
import os
import socket
import subprocess
import sys
import threading
import json
import ctypes
import time

# from utils.proxy_protocols import parse_vless_protocol
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


LOGGER = logging.getLogger("sni_spoofing")


def _is_windows_admin() -> bool:
    if not sys.platform.startswith("win"):
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_as_admin():
    params = subprocess.list2cmdline(sys.argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1,
    )
    if ret <= 32:
        raise RuntimeError(f"failed to request admin privileges, code={ret}")


def _ensure_admin_or_exit():
    if _is_windows_admin():
        return
    _relaunch_as_admin()
    sys.exit(0)


def _is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    if hostname.endswith("."):
        hostname = hostname[:-1]
    labels = hostname.split(".")
    if not labels:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return False
    return True


def _load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    required_keys = [
        "LISTEN_HOST",
        "LISTEN_PORT",
        "FAKE_SNI",
        "CONNECT_IP",
        "CONNECT_PORT",
    ]
    for key in required_keys:
        if key not in cfg:
            raise ValueError(f"missing config key: {key}")

    if not isinstance(cfg["LISTEN_HOST"], str):
        raise ValueError("LISTEN_HOST must be a string")
    if not isinstance(cfg["LISTEN_PORT"], int):
        raise ValueError("LISTEN_PORT must be an integer")
    if not isinstance(cfg["FAKE_SNI"], str):
        raise ValueError("FAKE_SNI must be a string")
    if not isinstance(cfg["CONNECT_IP"], str):
        raise ValueError("CONNECT_IP must be a string")
    if not isinstance(cfg["CONNECT_PORT"], int):
        raise ValueError("CONNECT_PORT must be an integer")

    cfg.setdefault("MAX_CONNECTIONS", 2048)
    cfg.setdefault("MAX_CONNECTIONS_PER_IP", 128)
    cfg.setdefault("HANDSHAKE_TIMEOUT_SEC", 2.0)
    cfg.setdefault("RELAY_IDLE_TIMEOUT_SEC", 120.0)
    cfg.setdefault("CONNECT_TIMEOUT_SEC", 4.0)
    cfg.setdefault("CONNECT_RETRY_COUNT", 2)
    cfg.setdefault("CONNECT_RETRY_DELAY_SEC", 0.25)
    cfg.setdefault("RELAY_BUFFER_SIZE", 65536)
    cfg.setdefault("SOCKET_SNDBUF", 262144)
    cfg.setdefault("SOCKET_RCVBUF", 262144)
    cfg.setdefault("ENABLE_TCP_NODELAY", True)

    if not isinstance(cfg["MAX_CONNECTIONS"], int):
        raise ValueError("MAX_CONNECTIONS must be an integer")
    if not isinstance(cfg["MAX_CONNECTIONS_PER_IP"], int):
        raise ValueError("MAX_CONNECTIONS_PER_IP must be an integer")
    if not isinstance(cfg["HANDSHAKE_TIMEOUT_SEC"], (int, float)):
        raise ValueError("HANDSHAKE_TIMEOUT_SEC must be a number")
    if not isinstance(cfg["RELAY_IDLE_TIMEOUT_SEC"], (int, float)):
        raise ValueError("RELAY_IDLE_TIMEOUT_SEC must be a number")
    if not isinstance(cfg["CONNECT_TIMEOUT_SEC"], (int, float)):
        raise ValueError("CONNECT_TIMEOUT_SEC must be a number")
    if not isinstance(cfg["CONNECT_RETRY_COUNT"], int):
        raise ValueError("CONNECT_RETRY_COUNT must be an integer")
    if not isinstance(cfg["CONNECT_RETRY_DELAY_SEC"], (int, float)):
        raise ValueError("CONNECT_RETRY_DELAY_SEC must be a number")
    if not isinstance(cfg["RELAY_BUFFER_SIZE"], int):
        raise ValueError("RELAY_BUFFER_SIZE must be an integer")
    if not isinstance(cfg["SOCKET_SNDBUF"], int):
        raise ValueError("SOCKET_SNDBUF must be an integer")
    if not isinstance(cfg["SOCKET_RCVBUF"], int):
        raise ValueError("SOCKET_RCVBUF must be an integer")
    if not isinstance(cfg["ENABLE_TCP_NODELAY"], bool):
        raise ValueError("ENABLE_TCP_NODELAY must be true/false")

    if not (1 <= cfg["LISTEN_PORT"] <= 65535):
        raise ValueError("LISTEN_PORT must be in range 1..65535")
    if not (1 <= cfg["CONNECT_PORT"] <= 65535):
        raise ValueError("CONNECT_PORT must be in range 1..65535")
    if not cfg["FAKE_SNI"]:
        raise ValueError("FAKE_SNI must not be empty")
    if not _is_valid_hostname(cfg["FAKE_SNI"]):
        raise ValueError("FAKE_SNI must be a valid hostname")
    if cfg["MAX_CONNECTIONS"] < 1:
        raise ValueError("MAX_CONNECTIONS must be >= 1")
    if cfg["MAX_CONNECTIONS_PER_IP"] < 1:
        raise ValueError("MAX_CONNECTIONS_PER_IP must be >= 1")
    if not (0.5 <= float(cfg["HANDSHAKE_TIMEOUT_SEC"]) <= 60):
        raise ValueError("HANDSHAKE_TIMEOUT_SEC must be in range 0.5..60")
    if not (1 <= float(cfg["RELAY_IDLE_TIMEOUT_SEC"]) <= 3600):
        raise ValueError("RELAY_IDLE_TIMEOUT_SEC must be in range 1..3600")
    if not (0.2 <= float(cfg["CONNECT_TIMEOUT_SEC"]) <= 60):
        raise ValueError("CONNECT_TIMEOUT_SEC must be in range 0.2..60")
    if not (1 <= int(cfg["CONNECT_RETRY_COUNT"]) <= 10):
        raise ValueError("CONNECT_RETRY_COUNT must be in range 1..10")
    if not (0 <= float(cfg["CONNECT_RETRY_DELAY_SEC"]) <= 10):
        raise ValueError("CONNECT_RETRY_DELAY_SEC must be in range 0..10")
    if not (1024 <= int(cfg["RELAY_BUFFER_SIZE"]) <= 1048576):
        raise ValueError("RELAY_BUFFER_SIZE must be in range 1024..1048576")
    if not (8192 <= int(cfg["SOCKET_SNDBUF"]) <= 10485760):
        raise ValueError("SOCKET_SNDBUF must be in range 8192..10485760")
    if not (8192 <= int(cfg["SOCKET_RCVBUF"]) <= 10485760):
        raise ValueError("SOCKET_RCVBUF must be in range 8192..10485760")

    try:
        ipaddress.ip_address(cfg["CONNECT_IP"])
    except ValueError as exc:
        raise ValueError("CONNECT_IP must be a valid IP address") from exc

    listen_host = cfg["LISTEN_HOST"]
    if listen_host not in ("0.0.0.0", "::"):
        try:
            ipaddress.ip_address(listen_host)
        except ValueError:
            if not _is_valid_hostname(listen_host):
                raise ValueError("LISTEN_HOST must be an IP or hostname")

    return cfg


def _apply_keepalive_opts(sock: socket.socket):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    if hasattr(socket, "TCP_KEEPINTVL"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    if hasattr(socket, "TCP_KEEPCNT"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)


def _apply_performance_opts(sock: socket.socket):
    if ENABLE_TCP_NODELAY:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_SNDBUF)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RCVBUF)


def _close_quietly(*sockets: socket.socket):
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass


def _shutdown_write_quietly(sock: socket.socket):
    try:
        sock.shutdown(socket.SHUT_WR)
    except Exception:
        pass


def _remove_fake_connection(fake_conn: FakeInjectiveConnection):
    fake_conn.monitor = False
    fake_injective_connections.pop(fake_conn.id, None)


def _startup_connectivity_probe() -> bool:
    probe_timeout = min(max(CONNECT_TIMEOUT_SEC, 0.2), 5.0)
    try:
        start = time.perf_counter()
        with socket.create_connection(
            (CONNECT_IP, CONNECT_PORT), timeout=probe_timeout
        ):
            pass
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        LOGGER.info(
            "[startup][ok] outbound probe success target=%s:%s latency=%.1fms iface=%s",
            CONNECT_IP,
            CONNECT_PORT,
            elapsed_ms,
            INTERFACE_IPV4,
        )
        return True
    except Exception as exc:
        LOGGER.error(
            "[startup][fail] outbound probe failed target=%s:%s timeout=%.1fs iface=%s err=%s",
            CONNECT_IP,
            CONNECT_PORT,
            probe_timeout,
            INTERFACE_IPV4,
            exc,
        )
        return False


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, "frozen", False):
        # Running as a PyInstaller EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))


# Build the path to config.json
config_path = os.path.join(get_exe_dir(), "config.json")

# Load the config
config = _load_config(config_path)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
MAX_CONNECTIONS = config["MAX_CONNECTIONS"]
MAX_CONNECTIONS_PER_IP = config["MAX_CONNECTIONS_PER_IP"]
HANDSHAKE_TIMEOUT_SEC = float(config["HANDSHAKE_TIMEOUT_SEC"])
RELAY_IDLE_TIMEOUT_SEC = float(config["RELAY_IDLE_TIMEOUT_SEC"])
CONNECT_TIMEOUT_SEC = float(config["CONNECT_TIMEOUT_SEC"])
CONNECT_RETRY_COUNT = int(config["CONNECT_RETRY_COUNT"])
CONNECT_RETRY_DELAY_SEC = float(config["CONNECT_RETRY_DELAY_SEC"])
RELAY_BUFFER_SIZE = int(config["RELAY_BUFFER_SIZE"])
SOCKET_SNDBUF = int(config["SOCKET_SNDBUF"])
SOCKET_RCVBUF = int(config["SOCKET_RCVBUF"])
ENABLE_TCP_NODELAY = bool(config["ENABLE_TCP_NODELAY"])
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

##################

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}
active_connections_by_ip: dict[str, int] = {}
active_connections_total = 0
connection_guard_lock = asyncio.Lock()

total_upload_bytes = 0
total_download_bytes = 0
window_upload_bytes = 0
window_download_bytes = 0


def _record_transfer(direction: str, size: int):
    global total_upload_bytes
    global total_download_bytes
    global window_upload_bytes
    global window_download_bytes

    if size <= 0:
        return
    if direction == "up":
        total_upload_bytes += size
        window_upload_bytes += size
    else:
        total_download_bytes += size
        window_download_bytes += size


def _bytes_to_human(value: int) -> str:
    if value < 1024:
        return f"{value}B"
    if value < 1024 * 1024:
        return f"{value / 1024.0:.1f}KB"
    if value < 1024 * 1024 * 1024:
        return f"{value / (1024.0 * 1024.0):.2f}MB"
    return f"{value / (1024.0 * 1024.0 * 1024.0):.2f}GB"


async def _speed_reporter():
    global window_upload_bytes
    global window_download_bytes

    while True:
        await asyncio.sleep(1.0)
        up_window = window_upload_bytes
        down_window = window_download_bytes
        window_upload_bytes = 0
        window_download_bytes = 0
        LOGGER.info(
            "[speed] up_bps=%d down_bps=%d total_up=%s total_down=%s active=%d",
            up_window,
            down_window,
            _bytes_to_human(total_upload_bytes),
            _bytes_to_human(total_download_bytes),
            active_connections_total,
        )


async def _register_connection(client_ip: str) -> bool:
    global active_connections_total
    async with connection_guard_lock:
        if active_connections_total >= MAX_CONNECTIONS:
            return False

        current_for_ip = active_connections_by_ip.get(client_ip, 0)
        if current_for_ip >= MAX_CONNECTIONS_PER_IP:
            return False

        active_connections_by_ip[client_ip] = current_for_ip + 1
        active_connections_total += 1
        return True


async def _unregister_connection(client_ip: str):
    global active_connections_total
    async with connection_guard_lock:
        current_for_ip = active_connections_by_ip.get(client_ip, 0)
        if current_for_ip <= 1:
            active_connections_by_ip.pop(client_ip, None)
        else:
            active_connections_by_ip[client_ip] = current_for_ip - 1

        if active_connections_total > 0:
            active_connections_total -= 1


async def relay_main_loop(
    sock_1: socket.socket,
    sock_2: socket.socket,
    peer_task: asyncio.Task | None,
    first_prefix_data: bytes,
    direction: str,
):
    loop = asyncio.get_running_loop()
    while True:
        try:
            data = await asyncio.wait_for(
                loop.sock_recv(sock_1, RELAY_BUFFER_SIZE),
                timeout=RELAY_IDLE_TIMEOUT_SEC,
            )
            if not data:
                if peer_task is not None and not peer_task.done():
                    peer_task.cancel()
                _shutdown_write_quietly(sock_2)
                _close_quietly(sock_1)
                return
            if first_prefix_data:
                data = first_prefix_data + data
                first_prefix_data = b""
            _record_transfer(direction, len(data))
            await loop.sock_sendall(sock_2, data)
        except asyncio.CancelledError:
            if peer_task is not None and not peer_task.done():
                peer_task.cancel()
            _shutdown_write_quietly(sock_2)
            _close_quietly(sock_1, sock_2)
            raise
        except Exception:
            if peer_task is not None and not peer_task.done():
                peer_task.cancel()
            _shutdown_write_quietly(sock_2)
            _close_quietly(sock_1, sock_2)
            return


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    outgoing_sock = None
    fake_injective_conn = None
    oti_task: asyncio.Task | None = None
    client_ip = incoming_remote_addr[0] if incoming_remote_addr else "unknown"
    registered = False
    try:
        registered = await _register_connection(client_ip)
        if not registered:
            LOGGER.warning("Connection rejected by limits for client_ip=%s", client_ip)
            _close_quietly(incoming_sock)
            return

        loop = asyncio.get_running_loop()
        # try:
        #     data = await loop.sock_recv(incoming_sock, 65575)
        #     if not data:
        #         raise ValueError("eof")
        # except Exception:
        #     incoming_sock.close()
        #     return
        # try:
        #     version, uuid_bytes, transport_protocol, remote_address_type, remote_address, remote_port, payload_index = parse_vless_protocol(
        #         data)
        # except Exception as e:
        #     print("No Vless Request!, Connection Closed", repr(e), data)
        #     incoming_sock.close()
        #     return
        # if transport_protocol != "tcp":
        #     print("Transport Protocol Error!, Connection Closed", transport_protocol, data)
        #     incoming_sock.close()
        #     return
        # if remote_address_type == "hostname":
        #     print("hostname address not implemented yet!", data)
        #     incoming_sock.close()
        #     return
        # if remote_address_type == "ipv4":
        #     if not INTERFACE_IPV4:
        #         print("no interface ipv4!", data)
        #         incoming_sock.close()
        #         return
        #     family = socket.AF_INET
        #     src_ip = INTERFACE_IPV4
        #
        # elif remote_address_type == "ipv6":
        #     if not INTERFACE_IPV6:
        #         print("no interface ipv6!", data)
        #         incoming_sock.close()
        #         return
        #     family = socket.AF_INET6
        #     src_ip = INTERFACE_IPV6
        #
        # else:
        #     print(data)
        #     sys.exit("impossible address type!")

        # try:
        #     fake_sni_host, data_mode, bypass_method = UUID_FAKE_MAP[uuid_bytes]
        # except KeyError:
        #     print("unmatched uuid", uuid_bytes)
        #     incoming_sock.close()
        #     return

        # if data_mode == "http":
        #     ...
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32), os.urandom(32), FAKE_SNI, os.urandom(32)
            )
        else:
            LOGGER.error("Unsupported data mode: %s", DATA_MODE)
            _close_quietly(incoming_sock)
            return

        connected = False
        for attempt in range(1, CONNECT_RETRY_COUNT + 1):
            outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            outgoing_sock.setblocking(False)
            outgoing_sock.bind((INTERFACE_IPV4, 0))
            _apply_performance_opts(outgoing_sock)
            _apply_keepalive_opts(outgoing_sock)

            src_port = outgoing_sock.getsockname()[1]
            if src_port == 0:
                LOGGER.error("Failed to allocate local source port")
                _close_quietly(outgoing_sock, incoming_sock)
                return

            fake_injective_conn = FakeInjectiveConnection(
                outgoing_sock,
                INTERFACE_IPV4,
                CONNECT_IP,
                src_port,
                CONNECT_PORT,
                fake_data,
                BYPASS_METHOD,
                incoming_sock,
            )
            fake_injective_connections[fake_injective_conn.id] = fake_injective_conn

            try:
                await asyncio.wait_for(
                    loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT)),
                    timeout=CONNECT_TIMEOUT_SEC,
                )
            except Exception as exc:
                LOGGER.warning(
                    "connect attempt %s/%s failed to %s:%s err=%s",
                    attempt,
                    CONNECT_RETRY_COUNT,
                    CONNECT_IP,
                    CONNECT_PORT,
                    exc,
                )
                _remove_fake_connection(fake_injective_conn)
                _close_quietly(outgoing_sock)
                outgoing_sock = None
                fake_injective_conn = None
                if attempt < CONNECT_RETRY_COUNT and CONNECT_RETRY_DELAY_SEC > 0:
                    await asyncio.sleep(CONNECT_RETRY_DELAY_SEC)
            else:
                connected = True
                break

        if not connected:
            if fake_injective_conn is not None:
                _remove_fake_connection(fake_injective_conn)
            _close_quietly(outgoing_sock, incoming_sock)
            return

        # if bypass_method == "wrong_checksum":
        #     ...

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(
                    fake_injective_conn.t2a_event.wait(), HANDSHAKE_TIMEOUT_SEC
                )
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    pass
                else:
                    raise ValueError(
                        f"unexpected t2a message: {fake_injective_conn.t2a_msg}"
                    )
            except Exception:
                _remove_fake_connection(fake_injective_conn)
                _close_quietly(outgoing_sock, incoming_sock)
                return
        else:
            LOGGER.error("Unknown bypass method: %s", BYPASS_METHOD)
            _remove_fake_connection(fake_injective_conn)
            _close_quietly(outgoing_sock, incoming_sock)
            return

        _remove_fake_connection(fake_injective_conn)

        # early_data = data[payload_index:]
        # if early_data:
        #     try:
        #         sent_len = await loop.sock_sendall(outgoing_sock, early_data)
        #         if sent_len != len(early_data):
        #             raise ValueError("incomplete send")
        #     except Exception:
        #         outgoing_sock.close()
        #         incoming_sock.close()
        #         return

        oti_task = asyncio.create_task(
            relay_main_loop(
                outgoing_sock,
                incoming_sock,
                asyncio.current_task(),
                b"",
                "down",
            )
        )  # bytes([version, 0])
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task, b"", "up")
        await oti_task

    except asyncio.CancelledError:
        if oti_task is not None and not oti_task.done():
            oti_task.cancel()
            await asyncio.gather(oti_task, return_exceptions=True)
        raise

    except Exception:
        LOGGER.exception("connection handler crashed")
        if fake_injective_conn is not None:
            _remove_fake_connection(fake_injective_conn)
        _close_quietly(outgoing_sock, incoming_sock)
    finally:
        if oti_task is not None and not oti_task.done():
            oti_task.cancel()
            await asyncio.gather(oti_task, return_exceptions=True)
        if registered:
            await _unregister_connection(client_ip)


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    _apply_keepalive_opts(mother_sock)
    mother_sock.listen()
    loop = asyncio.get_running_loop()
    handler_tasks: set[asyncio.Task] = set()
    speed_task = asyncio.create_task(_speed_reporter())
    try:
        while True:
            try:
                incoming_sock, addr = await loop.sock_accept(mother_sock)
            except OSError as exc:
                if getattr(exc, "winerror", None) == 10038:
                    LOGGER.warning("Suppressed Windows socket shutdown race: %s", exc)
                    break
                raise

            incoming_sock.setblocking(False)
            _apply_performance_opts(incoming_sock)
            _apply_keepalive_opts(incoming_sock)

            task = asyncio.create_task(handle(incoming_sock, addr))
            handler_tasks.add(task)
            task.add_done_callback(handler_tasks.discard)
    finally:
        speed_task.cancel()
        await asyncio.gather(speed_task, return_exceptions=True)
        _close_quietly(mother_sock)
        if handler_tasks:
            for task in list(handler_tasks):
                task.cancel()
            await asyncio.gather(*list(handler_tasks), return_exceptions=True)


def run_core():
    try:
        _ensure_admin_or_exit()
    except Exception as exc:
        sys.exit(f"Failed to elevate privileges: {exc}")

    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s"
    )

    LOGGER.info(
        "[startup] SMART FOX listen=%s:%s target=%s:%s fake_sni=%s",
        LISTEN_HOST,
        LISTEN_PORT,
        CONNECT_IP,
        CONNECT_PORT,
        FAKE_SNI.decode(errors="ignore"),
    )
    if LISTEN_HOST == "0.0.0.0":
        LOGGER.warning("LISTEN_HOST is 0.0.0.0; service is reachable from the network.")
    if not INTERFACE_IPV4:
        sys.exit("No IPv4 interface available for CONNECT_IP route")
    w_filter = (
        "tcp and "
        + "("
        + "(ip.SrcAddr == "
        + INTERFACE_IPV4
        + " and ip.DstAddr == "
        + CONNECT_IP
        + ")"
        + " or "
        + "(ip.SrcAddr == "
        + CONNECT_IP
        + " and ip.DstAddr == "
        + INTERFACE_IPV4
        + ")"
        + ")"
    )
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    _startup_connectivity_probe()
    print("SMART FOX")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except OSError as exc:
        if getattr(exc, "winerror", None) == 10038:
            LOGGER.warning("Suppressed Windows socket shutdown race: %s", exc)
        else:
            raise
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        try:
            loop.run_until_complete(loop.shutdown_default_executor())
        except Exception:
            pass
        loop.close()


if __name__ == "__main__":
    run_core()
