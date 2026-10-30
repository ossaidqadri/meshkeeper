import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import wsc


def make_m1(priv: int, mac: bytes, nonce: bytes, rf_bands: int) -> bytes:
    pub = pow(wsc.DH_G, priv, wsc.DH_P).to_bytes(wsc.DH_LEN, "big")
    return (
        wsc.attr(wsc.ATTR_VERSION, b"\x10")
        + wsc.attr(wsc.ATTR_MSG_TYPE, bytes([wsc.MSG_M1]))
        + wsc.attr(wsc.ATTR_UUID_E, os.urandom(16))
        + wsc.attr(wsc.ATTR_MAC, mac)
        + wsc.attr(wsc.ATTR_ENROLLEE_NONCE, nonce)
        + wsc.attr(wsc.ATTR_PUBLIC_KEY, pub)
        + wsc.attr(wsc.ATTR_RF_BANDS, bytes([rf_bands]))
    )


def test_m2_decrypts_and_authenticates_as_the_enrollee_would():
    priv = int.from_bytes(os.urandom(wsc.DH_LEN), "big") % (wsc.DH_P - 2) + 1
    mac, nonce = bytes.fromhex("020000a0d950"), os.urandom(16)
    m1 = wsc.parse_m1(make_m1(priv, mac, nonce, wsc.RF_BAND_5))
    bss = wsc.BssConfig(ssid="MK 5GHz", passphrase="exactly8")

    m2 = wsc.build_m2(m1, bss, registrar_uuid=os.urandom(16))
    a = wsc.parse_attrs(m2)
    assert a[wsc.ATTR_MSG_TYPE] == bytes([wsc.MSG_M2])
    assert a[wsc.ATTR_ENROLLEE_NONCE] == nonce

    # Enrollee side: derive the same keys from its private key.
    shared = pow(int.from_bytes(a[wsc.ATTR_PUBLIC_KEY], "big"), priv, wsc.DH_P)
    keys = wsc.derive_keys(shared, nonce, mac, a[wsc.ATTR_REGISTRAR_NONCE])

    body = m2[: -(4 + 8)]
    assert a[wsc.ATTR_AUTHENTICATOR] == hmac.new(keys.auth_key, m1.raw + body, hashlib.sha256).digest()[:8]

    blob = a[wsc.ATTR_ENCR_SETTINGS]
    dec = Cipher(algorithms.AES(keys.key_wrap_key), modes.CBC(blob[:16])).decryptor()
    plain = dec.update(blob[16:]) + dec.finalize()
    plain = plain[: -plain[-1]]
    settings, kwa = plain[:-12], plain[-12:]
    assert kwa[:4] == struct.pack(">HH", wsc.ATTR_KEY_WRAP_AUTH, 8)
    assert kwa[4:] == hmac.new(keys.auth_key, settings, hashlib.sha256).digest()[:8]

    s = wsc.parse_attrs(settings)
    assert s[wsc.ATTR_SSID] == b"MK 5GHz"
    assert s[wsc.ATTR_NETWORK_KEY] == b"exactly8"
    assert s[wsc.ATTR_AUTH_TYPE] == struct.pack(">H", wsc.AUTH_WPA2PSK)
    assert s[wsc.ATTR_VENDOR_EXT] == wsc.WFA_OUI + bytes([wsc.WFA_ELEM_MULTI_AP, 1, wsc.MULTI_AP_FRONTHAUL])


def test_kdf_is_deterministic_and_splits_640_bits():
    k1 = wsc.derive_keys(12345, b"n" * 16, b"m" * 6, b"r" * 16)
    k2 = wsc.derive_keys(12345, b"n" * 16, b"m" * 6, b"r" * 16)
    assert k1 == k2
    assert (len(k1.auth_key), len(k1.key_wrap_key), len(k1.emsk)) == (32, 16, 32)
