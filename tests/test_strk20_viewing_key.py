from hashlib import sha256
from hmac import new as hmac_new

import pytest
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID

from application_client.response_unpacker import Errors
from utils import ROOT_SCREENSHOT_PATH, read_lines_from_file


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

# Stark curve, used to check the public-key matching required by SNIP-44
# "Implementation". Recovery accepts a derived key only when x(k * G) equals
# the public key registered on-chain, so the scalar alone is not enough.
STARK_FIELD_PRIME = 2**251 + 17 * 2**192 + 1
STARK_CURVE_A = 1
STARK_CURVE_B = 0x6F21413EFBE40DE150E596D72F7A8C5609AD26C15C915C1F4CDFCB99CEE9E89
STARK_GENERATOR = (
    0x1EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA,
    0x5668060AA49730B7BE4801DF46EC62DE53ECD11ABE43A32873000C36E8DC1F,
)
STARK_LOWER_HALF_BOUNDARY = STARK_CURVE_ORDER // 2


def _point_add(first, second):
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 + y2) % STARK_FIELD_PRIME == 0:
        return None
    if first == second:
        slope = (3 * x1 * x1 + STARK_CURVE_A) * pow(2 * y1, -1, STARK_FIELD_PRIME)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, STARK_FIELD_PRIME)
    slope %= STARK_FIELD_PRIME
    x3 = (slope * slope - x1 - x2) % STARK_FIELD_PRIME
    return (x3, (slope * (x1 - x3) - y1) % STARK_FIELD_PRIME)


def stark_public_key_x(scalar: int) -> int:
    assert 1 <= scalar < STARK_CURVE_ORDER
    result, addend = None, STARK_GENERATOR
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    assert result is not None
    return result[0]


def assert_canonical_viewing_key(viewing_key: bytes) -> int:
    """A conforming device returns a canonical scalar: SNIP-44 requires
    1 <= k < floor(n / 2), strictly, and the point must be on the curve."""
    assert len(viewing_key) == 32
    scalar = int.from_bytes(viewing_key, "big")
    assert 1 <= scalar < STARK_LOWER_HALF_BOUNDARY
    x = stark_public_key_x(scalar)
    y_squared = (x**3 + STARK_CURVE_A * x + STARK_CURVE_B) % STARK_FIELD_PRIME
    assert pow(y_squared, (STARK_FIELD_PRIME - 1) // 2, STARK_FIELD_PRIME) == 1
    return x


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
    # SNIP-44 "Primary vector" public_key_x.
    assert stark_public_key_x(int.from_bytes(viewing_key, "big")) == int(
        "0435ada564d3bb1c5ac7caac8aa5fdc7dfa5de1aea83ff660099ea619a08c7a5", 16
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
    # SNIP-44 "Rejection-sampling vector" public_key_x.
    assert stark_public_key_x(int.from_bytes(viewing_key, "big")) == int(
        "04366caa68f40c9467a805b2646bcca3ac60c320c165564f69bc2de4b668e7ed", 16
    )


def exchange_and_approve(apdu, firmware, backend, navigator, test_name):
    with backend.exchange_async_raw(apdu):
        if firmware.device.startswith("nano"):
            navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                "Derive private",
                ROOT_SCREENSHOT_PATH,
                test_name,
            )
        else:
            navigator.navigate_until_text_and_compare(
                NavInsID.SWIPE_CENTER_TO_LEFT,
                [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS,
                ],
                "Derive private",
                ROOT_SCREENSHOT_PATH,
                test_name,
            )

    return backend.last_async_response.data


def test_derive_strk20_viewing_key(firmware, backend, navigator, test_name):
    apdu = bytes.fromhex(read_lines_from_file("samples/apdu/strk20_viewing_key.dat")[0])

    viewing_key = exchange_and_approve(apdu, firmware, backend, navigator, test_name)

    assert viewing_key == SPECULOS_VIEWING_KEY
    assert_canonical_viewing_key(viewing_key)


def test_derive_strk20_viewing_key_retries_rejected_digest(
    firmware, backend, navigator, test_name
):
    apdu = bytearray.fromhex(
        read_lines_from_file("samples/apdu/strk20_viewing_key.dat")[0]
    )
    pool_offset = 5 + 24 + 4 + 32 + 32
    apdu[pool_offset : pool_offset + 32] = (0x16).to_bytes(32, "big")

    viewing_key = exchange_and_approve(
        bytes(apdu), firmware, backend, navigator, test_name
    )

    assert viewing_key == SPECULOS_REJECTION_VIEWING_KEY
    assert_canonical_viewing_key(viewing_key)


def test_derive_strk20_viewing_key_can_be_refused(
    firmware, backend, navigator, test_name
):
    apdu = bytes.fromhex(read_lines_from_file("samples/apdu/strk20_viewing_key.dat")[0])

    with pytest.raises(ExceptionRAPDU) as error:
        with backend.exchange_async_raw(apdu):
            if firmware.device.startswith("nano"):
                navigator.navigate_until_text_and_compare(
                    NavInsID.RIGHT_CLICK,
                    [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK],
                    "Derive private",
                    ROOT_SCREENSHOT_PATH,
                    test_name,
                )
            else:
                navigator.navigate_until_text_and_compare(
                    NavInsID.SWIPE_CENTER_TO_LEFT,
                    [
                        NavInsID.USE_CASE_REVIEW_REJECT,
                        NavInsID.USE_CASE_CHOICE_CONFIRM,
                        NavInsID.USE_CASE_STATUS_DISMISS,
                    ],
                    "Derive private",
                    ROOT_SCREENSHOT_PATH,
                    test_name,
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
