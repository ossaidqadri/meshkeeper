"""IEEE 1905.1 CMDU framing and the EasyMesh TLVs this prototype needs."""

import struct
from dataclasses import dataclass, field

ETH_P_1905 = 0x893A
MCAST_1905 = bytes.fromhex("0180c2000013")

MSG_TOPOLOGY_DISCOVERY = 0x0000
MSG_VENDOR_SPECIFIC = 0x0004
MSG_AP_AUTOCONFIG_SEARCH = 0x0007
MSG_AP_AUTOCONFIG_RESPONSE = 0x0008
MSG_AP_AUTOCONFIG_WSC = 0x0009

FLAG_LAST_FRAGMENT = 0x80
FLAG_RELAY = 0x40

TLV_END = 0x00
TLV_AL_MAC = 0x01
TLV_SEARCHED_ROLE = 0x0D
TLV_AUTOCONFIG_FREQ_BAND = 0x0E
TLV_SUPPORTED_ROLE = 0x0F
TLV_SUPPORTED_FREQ_BAND = 0x10
TLV_WSC = 0x11
TLV_SUPPORTED_SERVICE = 0x80
TLV_SEARCHED_SERVICE = 0x81
TLV_AP_RADIO_IDENTIFIER = 0x82
TLV_AP_RADIO_BASIC_CAPS = 0x85
TLV_MULTI_AP_PROFILE = 0xB3

ROLE_REGISTRAR = 0x00
SERVICE_CONTROLLER = 0x00
SERVICE_AGENT = 0x01
BAND_24 = 0x00
BAND_5 = 0x01

MSG_NAMES = {
    0x0000: "topology discovery",
    0x0001: "topology notification",
    0x0002: "topology query",
    0x0003: "topology response",
    0x0004: "vendor specific",
    0x0007: "AP-autoconfig search",
    0x0008: "AP-autoconfig response",
    0x0009: "AP-autoconfig WSC",
    0x000A: "AP-autoconfig renew",
}


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


@dataclass
class Cmdu:
    dst: bytes
    src: bytes
    msg_type: int
    mid: int
    fragment: int
    flags: int
    tlvs: list[tuple[int, bytes]] = field(default_factory=list)

    @property
    def name(self) -> str:
        return MSG_NAMES.get(self.msg_type, f"type 0x{self.msg_type:04x}")

    def tlv(self, t: int) -> bytes | None:
        return next((v for tt, v in self.tlvs if tt == t), None)

    def all(self, t: int) -> list[bytes]:
        return [v for tt, v in self.tlvs if tt == t]


def parse_frame(frame: bytes) -> Cmdu | None:
    if len(frame) < 22 or struct.unpack_from(">H", frame, 12)[0] != ETH_P_1905:
        return None
    version, _, msg_type, mid, fragment, flags = struct.unpack_from(">BBHHBB", frame, 14)
    if version != 0:
        return None
    cmdu = Cmdu(frame[0:6], frame[6:12], msg_type, mid, fragment, flags)
    i = 22
    while i + 3 <= len(frame):
        t, n = struct.unpack_from(">BH", frame, i)
        i += 3
        if t == TLV_END:
            break
        if i + n > len(frame):
            return None
        cmdu.tlvs.append((t, frame[i : i + n]))
        i += n
    return cmdu


def build_frame(dst: bytes, src: bytes, msg_type: int, mid: int, tlvs: list[tuple[int, bytes]], flags: int = FLAG_LAST_FRAGMENT) -> bytes:
    body = b"".join(struct.pack(">BH", t, len(v)) + v for t, v in tlvs) + b"\x00\x00\x00"
    frame = dst + src + struct.pack(">H", ETH_P_1905) + struct.pack(">BBHHBB", 0, 0, msg_type, mid, 0, flags) + body
    if len(frame) > 1514:
        raise ValueError(f"CMDU of {len(frame)} bytes needs fragmentation, which this prototype does not do")
    return frame.ljust(60, b"\x00")
