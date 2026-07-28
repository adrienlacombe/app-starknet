from hashlib import sha256
from hmac import new as hmac_new

import pytest
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

from application_client.response_unpacker import Errors
from utils import read_lines_from_file


CLA = 0x5A
INS_DERIVE_STRK20_VIEWING_KEY = 0x08
STARK_CURVE_ORDER = int(
    "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f", 16
)
REDUCTION_LIMIT = 2**256 - (2**256 % STARK_CURVE_ORDER)
DOMAIN_SEPARATOR = b"STRK20_ACCOUNT_LEAF_V1"

COMMON_CONTEXT = (
    (1).to_bytes(4, "big")
    + int.from_bytes(b"SN_SEPOLIA", "big").to_bytes(32, "big")
    + (0x1234).to_bytes(32, "big")
    + (0x5678).to_bytes(32, "big")
    + (0).to_bytes(16, "big")
)

SPECULOS_VIEWING_KEY = bytes.fromhex(
    "0112115824d48d5338ceea1c3665d7e4630738c27ccfcbd10c0b5d17bcf51114"
)
SPECULOS_REJECTION_VIEWING_KEY = bytes.fromhex(
    "0005cae77026d7ca9a333af7bcbfc65636a882840a03a3fc3a63699b7f372cab"
)


def derive_reference(account_leaf: bytes, context: bytes):
    assert len(account_leaf) == 32
    assert len(context) == 116

    for counter in range(2**32):
        digest = hmac_new(
            account_leaf,
            DOMAIN_SEPARATOR + context + counter.to_bytes(4, "big"),
            sha256,
        ).digest()
        candidate = int.from_bytes(digest, "big")
        if candidate >= REDUCTION_LIMIT:
            continue
        reduced = candidate % STARK_CURVE_ORDER
        if reduced == 0:
            continue
        viewing_key = min(reduced, STARK_CURVE_ORDER - reduced)
        if 1 <= viewing_key < STARK_CURVE_ORDER // 2:
            return counter, digest, reduced, viewing_key.to_bytes(32, "big")
    raise AssertionError("counter exhausted")


def test_account_leaf_v1_primary_snip_vector():
    counter, digest, reduced, viewing_key = derive_reference(
        (1).to_bytes(32, "big"), COMMON_CONTEXT
    )

    assert counter == 0
    assert digest.hex() == "3ed14752a332877b8097f5bc9b24c89689a29a5d10266060345df8685c8efdad"
    assert (
        reduced
        == int("06d14752a33287048097f5bc9b24c898851b195c83d081015f8f889c9c22e164", 16)
    )
    assert (
        viewing_key.hex()
        == "012eb8ad5ccd790c7f680a4364db37673265f91147173130bed719a511a36bcb"
    )


def test_account_leaf_v1_rejection_sampling_snip_vector():
    counter, digest, reduced, viewing_key = derive_reference(
        (5).to_bytes(32, "big"), COMMON_CONTEXT
    )

    rejected = hmac_new(
        (5).to_bytes(32, "big"),
        DOMAIN_SEPARATOR + COMMON_CONTEXT + (0).to_bytes(4, "big"),
        sha256,
    ).digest()
    assert rejected.hex() == "fd90c57fe6b814ea57268d16153d1c86312344f3e5e77ec22630ad48e6e9b96c"
    assert int.from_bytes(rejected, "big") >= REDUCTION_LIMIT
    assert counter == 1
    assert digest.hex() == "ae52983668004e406e69bfc4a7acfa9765c032128ee6705566e0eb44bde2061a"
    assert (
        reduced
        == int("0652983668004cdb6e69bfc4a7acfa9d5829af10e9e4d238e8759be17c9db13f", 16)
    )
    assert (
        viewing_key.hex()
        == "01ad67c997ffb3359196403b585305625f57635ce102dff935f1066031289bf0"
    )


def exchange_and_approve(apdu, firmware, backend, navigator):
    with backend.exchange_async_raw(apdu):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "Derive private",
            )
        else:
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT,
                [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS,
                ],
                "Derive private",
            )

    return backend.last_async_response.data


def test_derive_strk20_viewing_key(firmware, backend, navigator):
    apdu = bytes.fromhex(read_lines_from_file("samples/apdu/strk20_viewing_key.dat")[0])

    assert (
        exchange_and_approve(apdu, firmware, backend, navigator) == SPECULOS_VIEWING_KEY
    )


def test_derive_strk20_viewing_key_retries_rejected_digest(
    firmware, backend, navigator
):
    apdu = bytearray.fromhex(
        read_lines_from_file("samples/apdu/strk20_viewing_key.dat")[0]
    )
    pool_offset = 5 + 24 + 4 + 32 + 32
    apdu[pool_offset : pool_offset + 32] = (0x16).to_bytes(32, "big")

    assert (
        exchange_and_approve(bytes(apdu), firmware, backend, navigator)
        == SPECULOS_REJECTION_VIEWING_KEY
    )


def test_derive_strk20_viewing_key_can_be_refused(firmware, backend, navigator):
    apdu = bytes.fromhex(read_lines_from_file("samples/apdu/strk20_viewing_key.dat")[0])

    with pytest.raises(ExceptionRAPDU) as error:
        with backend.exchange_async_raw(apdu):
            if firmware.device.startswith("nano"):
                navigator.navigate_until_text(
                    NavInsID.RIGHT_CLICK,
                    [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK],
                    "Derive private",
                )
            else:
                navigator.navigate_until_text(
                    NavInsID.SWIPE_CENTER_TO_LEFT,
                    [
                        NavInsID.USE_CASE_REVIEW_REJECT,
                        NavInsID.USE_CASE_CHOICE_CONFIRM,
                        NavInsID.USE_CASE_STATUS_DISMISS,
                    ],
                    "Derive private",
                )

    assert error.value.status == Errors.SW_DENY
    assert error.value.data == b""


@pytest.mark.parametrize(
    ("payload_mutator", "expected_status"),
    [
        (lambda payload: payload[:-1], Errors.SW_WRONG_APDU_LENGTH),
        (
            lambda payload: payload[:24] + (2).to_bytes(4, "big") + payload[28:],
            0xFF04,
        ),
        (
            lambda payload: (
                payload[:28]
                + int(
                    "0800000000000011000000000000000000000000000000000000000000000001", 16
                ).to_bytes(32, "big")
                + payload[60:]
            ),
            0xFF05,
        ),
        (
            lambda payload: payload[:-16] + (1).to_bytes(16, "big"),
            0xFF06,
        ),
        (
            lambda payload: (0x8000002C).to_bytes(4, "big") + payload[4:],
            0xFF00,
        ),
    ],
)
def test_derive_strk20_viewing_key_rejects_invalid_input(
    backend, payload_mutator, expected_status
):
    apdu = bytes.fromhex(read_lines_from_file("samples/apdu/strk20_viewing_key.dat")[0])
    payload = payload_mutator(apdu[5:])

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(
            cla=CLA,
            ins=INS_DERIVE_STRK20_VIEWING_KEY,
            data=payload,
        )

    assert error.value.status == expected_status


def test_derive_strk20_viewing_key_rejects_parameters(backend):
    payload = bytes.fromhex(
        read_lines_from_file("samples/apdu/strk20_viewing_key.dat")[0]
    )[5:]

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(
            cla=CLA,
            ins=INS_DERIVE_STRK20_VIEWING_KEY,
            p1=1,
            data=payload,
        )

    assert error.value.status == Errors.SW_WRONG_P1P2
