import asyncio
import json
import os
import socket
import sys
import threading
import traceback
from typing import Optional

try:
    from utils.network_tools import get_default_interface_ipv4
    from utils.packet_templates import ClientHelloMaker
except ModuleNotFoundError:
    from network_tools import get_default_interface_ipv4
    from packet_templates import ClientHelloMaker

from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir() -> str:
    """Return the directory where the executable or script is located."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


config_path = os.path.join(get_exe_dir(), "config.json")
with open(config_path, "r", encoding="utf-8") as f:
    config = json.load(f)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}
fake_injective_connections_lock = threading.Lock()


def register_fake_connection(connection: FakeInjectiveConnection) -> None:
    with fake_injective_connections_lock:
        fake_injective_connections[connection.id] = connection


def unregister_fake_connection(connection: FakeInjectiveConnection) -> None:
    with fake_injective_connections_lock:
        fake_injective_connections.pop(connection.id, None)


def shutdown_socket(sock: Optional[socket.socket], how: int) -> None:
    if sock is None:
        return
    try:
        fileno = sock.fileno()
    except OSError:
        return
    if fileno == -1:
        return

    try:
        sock.shutdown(how)
    except OSError:
        pass


async def close_socket(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return

    shutdown_socket(sock, socket.SHUT_RDWR)

    try:
        sock.close()
    except OSError:
        pass


async def relay_main_loop(
    read_sock: socket.socket,
    write_sock: socket.socket,
    first_prefix_data: bytes = b"",
) -> str:
    loop = asyncio.get_running_loop()

    try:
        if first_prefix_data:
            await loop.sock_sendall(write_sock, first_prefix_data)

        while True:
            data = await loop.sock_recv(read_sock, 65575)
            if not data:
                return "eof"

            await loop.sock_sendall(write_sock, data)

    except asyncio.CancelledError:
        raise
    except (ConnectionError, OSError):
        return "socket_error"


async def relay_bidirectional(incoming_sock: socket.socket, outgoing_sock: socket.socket) -> None:
    client_to_server = asyncio.create_task(relay_main_loop(incoming_sock, outgoing_sock))
    server_to_client = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock))

    task_to_peer_write = {
        client_to_server: outgoing_sock,
        server_to_client: incoming_sock,
    }

    pending = {client_to_server, server_to_client}

    try:
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                exc = task.exception()
                if exc is not None:
                    for other in pending:
                        other.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    raise exc

                result = task.result()

                if result == "eof":
                    shutdown_socket(task_to_peer_write[task], socket.SHUT_WR)
                    continue

                if result == "socket_error":
                    for other in pending:
                        other.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    return
    finally:
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


async def handle(incoming_sock: socket.socket, incoming_remote_addr) -> None:
    outgoing_sock = None
    fake_injective_conn = None

    try:
        loop = asyncio.get_running_loop()

        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32),
                os.urandom(32),
                FAKE_SNI,
                os.urandom(32),
            )
        else:
            sys.exit("impossible mode!")

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

        src_port = outgoing_sock.getsockname()[1]
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
        register_fake_connection(fake_injective_conn)

        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            return

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
            except asyncio.TimeoutError:
                return

            if fake_injective_conn.t2a_msg == "unexpected_close":
                return
            if fake_injective_conn.t2a_msg != "fake_data_ack_recv":
                sys.exit("impossible t2a msg!")
        else:
            sys.exit("unknown bypass method!")

        fake_injective_conn.monitor = False
        unregister_fake_connection(fake_injective_conn)

        await relay_bidirectional(incoming_sock, outgoing_sock)

    except asyncio.CancelledError:
        raise
    except Exception:
        traceback.print_exc()
    finally:
        if fake_injective_conn is not None:
            fake_injective_conn.monitor = False
            unregister_fake_connection(fake_injective_conn)

        await close_socket(outgoing_sock)
        await close_socket(incoming_sock)


async def main() -> None:
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    mother_sock.listen()

    loop = asyncio.get_running_loop()
    try:
        while True:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            asyncio.create_task(handle(incoming_sock, addr))
    finally:
        await close_socket(mother_sock)


if __name__ == "__main__":
    w_filter = (
        "tcp and ("
        + "(ip.SrcAddr == " + INTERFACE_IPV4 + " and ip.DstAddr == " + CONNECT_IP + ")"
        + " or "
        + "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + INTERFACE_IPV4 + ")"
        + ")"
    )
    fake_tcp_injector = FakeTcpInjector(
        w_filter,
        fake_injective_connections,
        fake_injective_connections_lock,
    )
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    print("هشن شومافر تیامح دینکیم هدافتسا دازآ تنرتنیا هب یسرتسد یارب همانرب نیا زا رگا")
    print("دراد امش تیامح هب زاین هک مراد رظن رد دازآ تنرتنیا هب ناریا مدرم مامت یسرتسد یارب یدایز یاه همانرب و اه هژورپ")
    print()
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424\n")
    print("@patterniha")
    asyncio.run(main())
