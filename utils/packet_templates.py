import struct


class TLSCodecError(Exception):
    pass


class ClientHelloMaker:
    TEMPLATE = bytes.fromhex(
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d500"
    )

    TLS_CH_HDR_LEN = 11
    RANDOM_LEN = 32
    SESSION_LEN = 32
    KEY_SHARE_LEN = 32

    @classmethod
    def build(cls, rnd, sess_id, sni, key_share):
        if len(rnd) != cls.RANDOM_LEN:
            raise TLSCodecError("invalid random length")
        if len(sess_id) != cls.SESSION_LEN:
            raise TLSCodecError("invalid session id length")
        if len(key_share) != cls.KEY_SHARE_LEN:
            raise TLSCodecError("invalid key share length")

        server_name = (
            struct.pack("!H", len(sni) + 5)
            + struct.pack("!H", len(sni) + 3)
            + b"\x00"
            + struct.pack("!H", len(sni))
            + sni
        )

        padding_len = max(0, 219 - len(sni))
        padding = struct.pack("!H", padding_len) + (b"\x00" * padding_len)

        return (
            cls.TEMPLATE[:11]
            + rnd
            + b"\x20"
            + sess_id
            + cls.TEMPLATE[76:120]
            + server_name
            + cls.TEMPLATE[120:]
            + key_share
            + padding
        )

    @classmethod
    def parse(cls, data: bytes):
        try:
            rnd = data[11:43]
            sess_id = data[44:76]

            sni_len = struct.unpack("!H", data[125:127])[0]
            sni_start = 127
            sni_end = sni_start + sni_len
            sni = data[sni_start:sni_end].decode()

            key_share = data[262 + len(sni):262 + len(sni) + 32]

            return rnd, sess_id, sni, key_share
        except Exception as e:
            raise TLSCodecError(str(e))


class ServerHelloMaker:
    TEMPLATE = bytes.fromhex(
        "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e"
    )

    @classmethod
    def build(cls, rnd, sess_id, key_share, app_data):
        return (
            cls.TEMPLATE[:11]
            + rnd
            + b"\x20"
            + sess_id
            + cls.TEMPLATE[76:95]
            + key_share
            + b"\x14\x03\x03\x00\x01\x01"
            + b"\x17\x03\x03"
            + struct.pack("!H", len(app_data))
            + app_data
        )

    @classmethod
    def parse(cls, data: bytes):
        try:
            rnd = data[11:43]
            sess_id = data[44:76]
            key_share = data[95:127]
            app_data = data[138:]
            return rnd, sess_id, key_share, app_data
        except Exception as e:
            raise TLSCodecError(str(e))
