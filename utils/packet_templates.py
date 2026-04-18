import struct


class ClientHelloMaker:
    tls_ch_template_str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    tls_ch_template = bytes.fromhex(tls_ch_template_str)
    template_sni = "mci.ir".encode()
    static1 = tls_ch_template[:11]
    static2 = b"\x20"
    static3 = tls_ch_template[76:120]
    static4 = tls_ch_template[127 + len(template_sni) : 262 + len(template_sni)]
    static5 = b"\x00\x15"
    ##############
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_client_hello_with(
        cls, rnd: bytes, sess_id: bytes, target_sni: bytes, key_share: bytes
    ) -> bytes:  # rnd,sess_id,key_share: 32 bytes
        if len(rnd) != 32 or len(sess_id) != 32 or len(key_share) != 32:
            raise ValueError("rnd, sess_id and key_share must be 32 bytes each")
        if not target_sni:
            raise ValueError("target_sni must not be empty")
        if any(b > 0x7F for b in target_sni):
            raise ValueError("target_sni must be ASCII")
        if len(target_sni) > 219:
            raise ValueError("target_sni is too long for the template")

        server_name_ext = (
            struct.pack("!H", len(target_sni) + 5)
            + struct.pack("!H", len(target_sni) + 3)
            + b"\x00"
            + struct.pack("!H", len(target_sni))
            + target_sni
        )
        padding_ext = struct.pack("!H", 219 - len(target_sni)) + (
            b"\x00" * (219 - len(target_sni))
        )
        return (
            cls.static1
            + rnd
            + cls.static2
            + sess_id
            + cls.static3
            + server_name_ext
            + cls.static4
            + key_share
            + cls.static5
            + padding_ext
        )
        # rnd-> [11:43)  sess_id-> [44:76) key_share-> [262+len(target_sni):294+len(target_sni))

    @classmethod
    def parse_client_hello(cls, client_hello_bytes: bytes):
        if len(client_hello_bytes) != 517:
            raise ValueError("client_hello_bytes must be exactly 517 bytes")

        rnd = client_hello_bytes[11:43]
        sess_id = client_hello_bytes[44:76]
        sni_len = struct.unpack("!H", client_hello_bytes[125:127])[0]
        if sni_len == 0:
            raise ValueError("SNI length must be non-zero")
        if 127 + sni_len > len(client_hello_bytes):
            raise ValueError("invalid SNI length in client hello")

        tls_sni_bytes = client_hello_bytes[127 : 127 + sni_len]
        if any(b > 0x7F for b in tls_sni_bytes):
            raise ValueError("client hello SNI must be ASCII")
        tls_sni = tls_sni_bytes.decode("ascii")
        ks_ind = 262 + len(tls_sni_bytes)
        if ks_ind + 32 > len(client_hello_bytes):
            raise ValueError("invalid key_share position in client hello")

        key_share = client_hello_bytes[ks_ind : ks_ind + 32]
        rebuilt = cls.get_client_hello_with(rnd, sess_id, tls_sni_bytes, key_share)
        if rebuilt != client_hello_bytes:
            raise ValueError("client hello does not match expected template")

        return rnd, sess_id, tls_sni, key_share

    @classmethod
    def get_client_response_with(cls, app_data1: bytes):
        return (
            cls.tls_change_cipher
            + cls.tls_app_data_header
            + struct.pack("!H", len(app_data1))
            + app_data1
        )

    @classmethod
    def parse_client_response(cls, client_response_bytes: bytes):
        if len(client_response_bytes) < 11:
            raise ValueError("client_response_bytes is too short")

        app_data1 = client_response_bytes[11:]
        if cls.get_client_response_with(app_data1) != client_response_bytes:
            raise ValueError("client response does not match expected template")

        return app_data1


class ServerHelloMaker:
    tls_sh_template_str = "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e"
    tls_sh_template = bytes.fromhex(tls_sh_template_str)
    static1 = tls_sh_template[:11]
    static2 = b"\x20"
    static3 = tls_sh_template[76:95]
    tls_change_cipher = b"\x14\x03\x03\x00\x01\x01"
    tls_app_data_header = b"\x17\x03\x03"

    @classmethod
    def get_server_hello_with(
        cls, rnd: bytes, sess_id: bytes, key_share: bytes, app_data1: bytes
    ):
        return (
            cls.static1
            + rnd
            + cls.static2
            + sess_id
            + cls.static3
            + key_share
            + cls.tls_change_cipher
            + cls.tls_app_data_header
            + struct.pack("!H", len(app_data1))
            + app_data1
        )

    @classmethod
    def parse_server_hello(cls, server_hello_bytes: bytes):
        if len(server_hello_bytes) < 159:
            raise ValueError("server_hello_bytes is too short")

        rnd = server_hello_bytes[11:43]
        sess_id = server_hello_bytes[44:76]
        key_share = server_hello_bytes[95:127]
        app_data1 = server_hello_bytes[138:]
        if (
            cls.get_server_hello_with(rnd, sess_id, key_share, app_data1)
            != server_hello_bytes
        ):
            raise ValueError("server hello does not match expected template")

        return rnd, sess_id, key_share, app_data1
