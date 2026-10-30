"""WSC (Wi-Fi Simple Configuration) M1 parsing and M2 building, registrar side.

Follows the WSC 2.0 spec as used by EasyMesh AP-Autoconfiguration: DH group 5,
HMAC-SHA256 KDF, AES-128-CBC encrypted settings.
"""

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RFC 3526 1536-bit MODP group (group 5), generator 2.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2
DH_LEN = 192

ATTR_VERSION = 0x104A
ATTR_MSG_TYPE = 0x1022
ATTR_UUID_E = 0x1047
ATTR_UUID_R = 0x1048
ATTR_MAC = 0x1020
ATTR_ENROLLEE_NONCE = 0x101A
ATTR_REGISTRAR_NONCE = 0x1039
ATTR_PUBLIC_KEY = 0x1032
ATTR_AUTH_TYPE_FLAGS = 0x1004
ATTR_ENCR_TYPE_FLAGS = 0x1010
ATTR_CONN_TYPE_FLAGS = 0x100D
ATTR_CONFIG_METHODS = 0x1008
ATTR_MANUFACTURER = 0x1021
ATTR_MODEL_NAME = 0x1023
ATTR_MODEL_NUMBER = 0x1024
ATTR_SERIAL_NUMBER = 0x1042
ATTR_PRIMARY_DEV_TYPE = 0x1054
ATTR_DEV_NAME = 0x1011
ATTR_RF_BANDS = 0x103C
ATTR_ASSOC_STATE = 0x1002
ATTR_CONFIG_ERROR = 0x1009
ATTR_DEV_PASSWORD_ID = 0x1012
ATTR_OS_VERSION = 0x102D
ATTR_VENDOR_EXT = 0x1049
ATTR_ENCR_SETTINGS = 0x1018
ATTR_AUTHENTICATOR = 0x1005
ATTR_SSID = 0x1045
ATTR_AUTH_TYPE = 0x1003
ATTR_ENCR_TYPE = 0x100F
ATTR_NETWORK_KEY = 0x1027
ATTR_KEY_WRAP_AUTH = 0x101E

MSG_M1 = 0x04
MSG_M2 = 0x05

AUTH_WPA2PSK = 0x0020
AUTH_SAE = 0x0040
ENCR_AES = 0x0008

WFA_OUI = b"\x00\x37\x2a"
WFA_ELEM_VERSION2 = 0x00
WFA_ELEM_MULTI_AP = 0x06
MULTI_AP_TEARDOWN = 0x10
MULTI_AP_FRONTHAUL = 0x20
MULTI_AP_BACKHAUL = 0x40

RF_BAND_24 = 0x01
RF_BAND_5 = 0x02

KDF_LABEL = b"Wi-Fi Easy and Secure Key Derivation"


def attr(t: int, value: bytes) -> bytes:
    return struct.pack(">HH", t, len(value)) + value


def parse_attrs(data: bytes) -> dict[int, bytes]:
    """Parse WSC attributes; the first occurrence of each type wins."""
    out: dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(data):
        t, n = struct.unpack_from(">HH", data, i)
        i += 4
        if i + n > len(data):
            raise ValueError(f"WSC attribute 0x{t:04x} overruns message")
        out.setdefault(t, data[i : i + n])
        i += n
    return out


def wfa_vendor_ext(*elems: tuple[int, bytes]) -> bytes:
    body = WFA_OUI + b"".join(bytes([t, len(v)]) + v for t, v in elems)
    return attr(ATTR_VENDOR_EXT, body)


@dataclass(frozen=True)
class M1:
    raw: bytes
    mac: bytes
    nonce: bytes
    public_key: bytes
    rf_bands: int
    auth_flags: int
    encr_flags: int


def parse_m1(raw: bytes) -> M1:
    a = parse_attrs(raw)
    if a.get(ATTR_MSG_TYPE) != bytes([MSG_M1]):
        raise ValueError("not an M1")
    for t in (ATTR_MAC, ATTR_ENROLLEE_NONCE, ATTR_PUBLIC_KEY, ATTR_RF_BANDS):
        if t not in a:
            raise ValueError(f"M1 lacks attribute 0x{t:04x}")
    if len(a[ATTR_PUBLIC_KEY]) != DH_LEN or len(a[ATTR_ENROLLEE_NONCE]) != 16:
        raise ValueError("M1 public key or nonce has the wrong length")
    return M1(
        raw=raw,
        mac=a[ATTR_MAC],
        nonce=a[ATTR_ENROLLEE_NONCE],
        public_key=a[ATTR_PUBLIC_KEY],
        rf_bands=a[ATTR_RF_BANDS][0],
        auth_flags=int.from_bytes(a.get(ATTR_AUTH_TYPE_FLAGS, b"\x00\x00"), "big"),
        encr_flags=int.from_bytes(a.get(ATTR_ENCR_TYPE_FLAGS, b"\x00\x00"), "big"),
    )


@dataclass(frozen=True)
class Keys:
    auth_key: bytes
    key_wrap_key: bytes
    emsk: bytes


def derive_keys(dh_shared: int, enrollee_nonce: bytes, enrollee_mac: bytes, registrar_nonce: bytes) -> Keys:
    dhkey = hashlib.sha256(dh_shared.to_bytes(DH_LEN, "big")).digest()
    kdk = hmac.new(dhkey, enrollee_nonce + enrollee_mac + registrar_nonce, hashlib.sha256).digest()
    total_bits = 640
    stream = b"".join(
        hmac.new(kdk, struct.pack(">I", i) + KDF_LABEL + struct.pack(">I", total_bits), hashlib.sha256).digest()
        for i in range(1, 4)
    )[: total_bits // 8]
    return Keys(auth_key=stream[:32], key_wrap_key=stream[32:48], emsk=stream[48:80])


@dataclass(frozen=True)
class BssConfig:
    ssid: str
    passphrase: str
    auth: int = AUTH_WPA2PSK
    multi_ap: int = MULTI_AP_FRONTHAUL


def encrypted_settings(keys: Keys, bss: BssConfig, bssid: bytes, iv: bytes | None = None) -> bytes:
    plain = (
        attr(ATTR_SSID, bss.ssid.encode())
        + attr(ATTR_AUTH_TYPE, struct.pack(">H", bss.auth))
        + attr(ATTR_ENCR_TYPE, struct.pack(">H", ENCR_AES))
        + attr(ATTR_NETWORK_KEY, bss.passphrase.encode())
        + attr(ATTR_MAC, bssid)
        + wfa_vendor_ext((WFA_ELEM_MULTI_AP, bytes([bss.multi_ap])))
    )
    plain += attr(ATTR_KEY_WRAP_AUTH, hmac.new(keys.auth_key, plain, hashlib.sha256).digest()[:8])
    pad = 16 - len(plain) % 16
    plain += bytes([pad]) * pad
    iv = iv or os.urandom(16)
    enc = Cipher(algorithms.AES(keys.key_wrap_key), modes.CBC(iv)).encryptor()
    return attr(ATTR_ENCR_SETTINGS, iv + enc.update(plain) + enc.finalize())


def build_m2(
    m1: M1,
    bss: BssConfig,
    registrar_uuid: bytes,
    device_name: str = "multiap-ctl",
    *,
    priv: int | None = None,
    registrar_nonce: bytes | None = None,
    iv: bytes | None = None,
) -> bytes:
    """priv, registrar_nonce and iv are random unless given (fixed values are for test vectors)."""
    priv = priv or int.from_bytes(os.urandom(DH_LEN), "big") % (DH_P - 2) + 1
    pub = pow(DH_G, priv, DH_P).to_bytes(DH_LEN, "big")
    peer = int.from_bytes(m1.public_key, "big")
    if not 1 < peer < DH_P - 1:
        raise ValueError("M1 public key out of range")
    registrar_nonce = registrar_nonce or os.urandom(16)
    keys = derive_keys(pow(peer, priv, DH_P), m1.nonce, m1.mac, registrar_nonce)

    body = (
        attr(ATTR_VERSION, b"\x10")
        + attr(ATTR_MSG_TYPE, bytes([MSG_M2]))
        + attr(ATTR_ENROLLEE_NONCE, m1.nonce)
        + attr(ATTR_REGISTRAR_NONCE, registrar_nonce)
        + attr(ATTR_UUID_R, registrar_uuid)
        + attr(ATTR_PUBLIC_KEY, pub)
        + attr(ATTR_AUTH_TYPE_FLAGS, struct.pack(">H", AUTH_WPA2PSK | AUTH_SAE))
        + attr(ATTR_ENCR_TYPE_FLAGS, struct.pack(">H", ENCR_AES))
        + attr(ATTR_CONN_TYPE_FLAGS, b"\x01")
        + attr(ATTR_CONFIG_METHODS, struct.pack(">H", 0x0080))
        + attr(ATTR_MANUFACTURER, b"OpenWrt")
        + attr(ATTR_MODEL_NAME, b"multiap-ctl")
        + attr(ATTR_MODEL_NUMBER, b"1")
        + attr(ATTR_SERIAL_NUMBER, b"1")
        + attr(ATTR_PRIMARY_DEV_TYPE, bytes.fromhex("0006 0050f204 0001".replace(" ", "")))
        + attr(ATTR_DEV_NAME, device_name.encode())
        + attr(ATTR_RF_BANDS, bytes([m1.rf_bands]))
        + attr(ATTR_ASSOC_STATE, b"\x00\x00")
        + attr(ATTR_CONFIG_ERROR, b"\x00\x00")
        + attr(ATTR_DEV_PASSWORD_ID, b"\x00\x04")
        + attr(ATTR_OS_VERSION, struct.pack(">I", 0x80000000))
        + wfa_vendor_ext((WFA_ELEM_VERSION2, b"\x20"))
        + encrypted_settings(keys, bss, m1.mac, iv)
    )
    authenticator = hmac.new(keys.auth_key, m1.raw + body, hashlib.sha256).digest()[:8]
    return body + attr(ATTR_AUTHENTICATOR, authenticator)
