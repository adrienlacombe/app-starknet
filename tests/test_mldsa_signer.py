import hashlib

import pytest

from application_client.response_unpacker import (
    Errors,
    unpack_mldsa_transfer_chunk,
)
from mldsa import VerificationError, VerificationKey
from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import NavIns, NavInsID


CLA = 0x5A
INS_GET_MLDSA44_PUBLIC_KEY = 0x09
INS_SIGN_MLDSA44_HASH = 0x0A
INS_READ_MLDSA_TRANSFER = 0x0B
MLDSA_TRANSFER_VERSION = 1
MLDSA44_ALGORITHM_ID = 1
MLDSA_PUBLIC_KEY_KIND = 1
MLDSA_SIGNATURE_KIND = 2
MLDSA_PUBLIC_KEY_LEN = 1312
MLDSA_SIGNATURE_LEN = 2420
MLDSA_CHUNK_LEN = 240

DERIVATION_PATH = bytes.fromhex(
    "80000a55c741e9c9c47a6028800000008000000000000000"
)
ALTERNATE_DERIVATION_PATH = DERIVATION_PATH[:-4] + (1).to_bytes(4, "big")
TEST_HASH_BE = bytes.fromhex(
    "0123456789abcdef00112233445566778899aabbccddeeff1020304050607080"
)
EXPECTED_PUBLIC_KEY_SHA256 = (
    "a493ee97abfd8b6c9a07df38c13b2c52e8bc820f30bbdec7d8303f16f37a9102"
)


def apdu(ins: int, p1: int, p2: int, data: bytes = b"") -> bytes:
    assert len(data) <= 255
    return bytes([CLA, ins, p1, p2, len(data)]) + data


def collect_transfer(
    backend,
    first_response: bytes,
    expected_kind: int,
    expected_total_len: int,
) -> bytes:
    first = unpack_mldsa_transfer_chunk(first_response)
    assert first.version == MLDSA_TRANSFER_VERSION
    assert first.algorithm == MLDSA44_ALGORITHM_ID
    assert first.kind == expected_kind
    assert first.total_len == expected_total_len
    assert first.offset == 0

    output = bytearray(first.data)
    chunks_read = 1
    max_chunks = (expected_total_len + MLDSA_CHUNK_LEN - 1) // MLDSA_CHUNK_LEN
    while len(output) < first.total_len:
        assert chunks_read < max_chunks
        offset = len(output)
        assert offset % MLDSA_CHUNK_LEN == 0
        response = backend.exchange_raw(
            apdu(
                INS_READ_MLDSA_TRANSFER,
                offset >> 8,
                offset & 0xFF,
                first.session_id.to_bytes(4, "big"),
            )
        ).data
        chunk = unpack_mldsa_transfer_chunk(response)
        assert chunk.version == first.version
        assert chunk.algorithm == first.algorithm
        assert chunk.kind == first.kind
        assert chunk.session_id == first.session_id
        assert chunk.total_len == first.total_len
        assert chunk.offset == offset
        output.extend(chunk.data)
        chunks_read += 1

    assert len(output) == first.total_len
    assert chunks_read == max_chunks
    return bytes(output)


def get_public_key(backend, path: bytes = DERIVATION_PATH) -> tuple[bytes, int]:
    response = backend.exchange_raw(
        apdu(INS_GET_MLDSA44_PUBLIC_KEY, 0, 0, path)
    ).data
    first = unpack_mldsa_transfer_chunk(response)
    public_key = collect_transfer(
        backend,
        response,
        MLDSA_PUBLIC_KEY_KIND,
        MLDSA_PUBLIC_KEY_LEN,
    )
    return public_key, first.session_id


def pack_cairo_felts(value: bytes) -> list[int]:
    return [
        int.from_bytes(value[offset : offset + 31], "little")
        for offset in range(0, len(value), 31)
    ]


def unpack_cairo_felts(felts: list[int], value_len: int) -> bytes:
    padded = b"".join(felt.to_bytes(31, "little") for felt in felts)
    assert padded[value_len:] == bytes(len(padded) - value_len)
    return padded[:value_len]


def get_setting_position(firmware: Firmware, setting_idx: int, per_page: int) -> tuple[int, int]:
    if firmware == Firmware.STAX:
        screen_height, screen_width, header_height, footer_height = 672, 400, 88, 92
    elif firmware == Firmware.FLEX:
        screen_height, screen_width, header_height, footer_height = 600, 480, 96, 96
    else:
        screen_height, screen_width, header_height, footer_height = 400, 300, 60, 96

    index_in_page = setting_idx % per_page
    setting_height = (screen_height - header_height - footer_height) // per_page
    y = header_height + setting_height * index_in_page + setting_height // 2
    return screen_width // 2, y


def enable_blind_signing(firmware, navigator) -> None:
    if firmware.device.startswith("nano"):
        navigator.navigate(
            [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK],
            screen_change_before_first_instruction=False,
        )
    else:
        settings_per_page = 3 if firmware == Firmware.STAX else 2
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavIns(
                    NavInsID.TOUCH,
                    get_setting_position(firmware, 0, settings_per_page),
                ),
            ],
            screen_change_before_first_instruction=False,
        )


def navigate_one(navigator, instruction) -> None:
    navigator.navigate(
        [instruction],
        screen_change_before_first_instruction=False,
    )


def screen_text(backend) -> str:
    return "".join(
        event.get("text", "")
        for event in backend.get_current_screen_content()["events"]
    )


def visible_hex(backend) -> str:
    hex_characters = set("0123456789ABCDEF")
    return "".join(
        text
        for event in backend.get_current_screen_content()["events"]
        if (text := event.get("text", "")) and set(text) <= hex_characters
    )


def approve_hash(firmware, backend, navigator) -> None:
    assert "Blind signing ahead" in screen_text(backend)
    expected_hash = TEST_HASH_BE.hex().upper()

    if firmware.device.startswith("nano"):
        navigate_one(navigator, NavInsID.BOTH_CLICK)
        assert "Review ML-DSA-44 hash" in screen_text(backend)

        navigate_one(navigator, NavInsID.RIGHT_CLICK)
        displayed_hash = visible_hex(backend)
        navigate_one(navigator, NavInsID.RIGHT_CLICK)
        displayed_hash += visible_hex(backend)
        assert displayed_hash == expected_hash

        navigate_one(navigator, NavInsID.RIGHT_CLICK)
        assert "Sign with ML-DSA-44?" in screen_text(backend)
        navigate_one(navigator, NavInsID.BOTH_CLICK)
    else:
        navigate_one(navigator, NavInsID.CENTERED_FOOTER_TAP)
        displayed_hash = ""
        for _ in range(4):
            displayed_hash += visible_hex(backend)
            if displayed_hash == expected_hash:
                break
            navigate_one(navigator, NavInsID.SWIPE_CENTER_TO_LEFT)
        assert displayed_hash == expected_hash

        for _ in range(4):
            if "Sign with ML-DSA-44?" in screen_text(backend):
                break
            navigate_one(navigator, NavInsID.SWIPE_CENTER_TO_LEFT)
        else:
            pytest.fail("ML-DSA signing review never reached its approval screen")
        navigate_one(navigator, NavInsID.USE_CASE_REVIEW_CONFIRM)


def approve_public_key_review(firmware, backend, navigator) -> None:
    if firmware.device.startswith("nano"):
        navigate_instruction = NavInsID.RIGHT_CLICK
        targets = ("Approve",)
        validation_instruction = NavInsID.BOTH_CLICK
    else:
        navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
        targets = ("Confirm", "Approve")
        validation_instruction = NavInsID.USE_CASE_CHOICE_CONFIRM

    algorithm_seen = False
    fingerprint = ""
    for _ in range(12):
        current_text = screen_text(backend)
        algorithm_seen |= "ML-DSA-44" in current_text
        fingerprint += visible_hex(backend)
        if any(target in current_text for target in targets):
            break
        navigate_one(navigator, navigate_instruction)
    else:
        pytest.fail("ML-DSA public-key review never reached its approval screen")

    assert algorithm_seen
    assert fingerprint == EXPECTED_PUBLIC_KEY_SHA256.upper()
    navigate_one(navigator, validation_instruction)
    if not firmware.device.startswith("nano"):
        navigate_one(navigator, NavInsID.USE_CASE_STATUS_DISMISS)


def test_mldsa_public_key_is_stable_chunked_and_session_bound(backend):
    public_key, old_session = get_public_key(backend)
    assert len(public_key) == MLDSA_PUBLIC_KEY_LEN

    repeated_public_key, new_session = get_public_key(backend)
    assert repeated_public_key == public_key
    assert new_session != old_session
    assert hashlib.sha256(public_key).hexdigest() == EXPECTED_PUBLIC_KEY_SHA256

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(
            apdu(
                INS_READ_MLDSA_TRANSFER,
                0,
                0,
                old_session.to_bytes(4, "big"),
            )
        )
    assert error.value.status == Errors.SW_BAD_STATE

    alternate_public_key, _ = get_public_key(backend, ALTERNATE_DERIVATION_PATH)
    assert alternate_public_key != public_key

    packed_felts = pack_cairo_felts(public_key)
    assert len(packed_felts) == 43
    assert packed_felts[-1] < 1 << 80
    assert unpack_cairo_felts(packed_felts, len(public_key)) == public_key


def test_mldsa_public_key_confirmation_accepted(
    firmware,
    backend,
    navigator,
):
    with backend.exchange_async_raw(
        apdu(INS_GET_MLDSA44_PUBLIC_KEY, 1, 0, DERIVATION_PATH)
    ):
        approve_public_key_review(firmware, backend, navigator)

    public_key = collect_transfer(
        backend,
        backend.last_async_response.data,
        MLDSA_PUBLIC_KEY_KIND,
        MLDSA_PUBLIC_KEY_LEN,
    )
    assert hashlib.sha256(public_key).hexdigest() == EXPECTED_PUBLIC_KEY_SHA256


def test_mldsa_public_key_confirmation_rejected(
    firmware,
    backend,
    navigator,
):
    with pytest.raises(ExceptionRAPDU) as error:
        with backend.exchange_async_raw(
            apdu(INS_GET_MLDSA44_PUBLIC_KEY, 1, 0, DERIVATION_PATH)
        ):
            if firmware.device.startswith("nano"):
                navigator.navigate_until_text(
                    NavInsID.RIGHT_CLICK,
                    [NavInsID.BOTH_CLICK],
                    "Reject",
                )
            else:
                navigator.navigate(
                    [
                        NavInsID.USE_CASE_CHOICE_REJECT,
                        NavInsID.USE_CASE_STATUS_DISMISS,
                    ]
                )
    assert error.value.status == Errors.SW_DENY


def test_mldsa_rejects_invalid_state_and_transfer_offsets(backend):
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(
            apdu(INS_READ_MLDSA_TRANSFER, 0, 0, (1).to_bytes(4, "big"))
        )
    assert error.value.status == Errors.SW_BAD_STATE

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 1, 0, TEST_HASH_BE))
    assert error.value.status == Errors.SW_BAD_STATE

    invalid_path = bytes(4) + DERIVATION_PATH[4:]
    with pytest.raises(ExceptionRAPDU):
        backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 0, 0, invalid_path))
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 1, 0, TEST_HASH_BE))
    assert error.value.status == Errors.SW_BAD_STATE

    _, session_id = get_public_key(backend)
    for offset in (1, 1440):
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange_raw(
                apdu(
                    INS_READ_MLDSA_TRANSFER,
                    offset >> 8,
                    offset & 0xFF,
                    session_id.to_bytes(4, "big"),
                )
            )
        assert error.value.status == Errors.SW_WRONG_P1P2

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(
            apdu(INS_READ_MLDSA_TRANSFER, 0, 0, session_id.to_bytes(4, "big")[:-1])
        )
    assert error.value.status == Errors.SW_WRONG_APDU_LENGTH


def test_mldsa_signing_requires_blind_signing(
    firmware,
    backend,
    navigator,
):
    backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 0, 0, DERIVATION_PATH))
    with pytest.raises(ExceptionRAPDU) as error:
        with backend.exchange_async_raw(
            apdu(INS_SIGN_MLDSA44_HASH, 1, 0, TEST_HASH_BE)
        ):
            if firmware.device.startswith("nano"):
                navigator.navigate_until_text(
                    NavInsID.RIGHT_CLICK,
                    [NavInsID.BOTH_CLICK],
                    "Reject transaction",
                )
            else:
                navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT])
    assert error.value.status == Errors.SW_DENY

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 1, 0, TEST_HASH_BE))
    assert error.value.status == Errors.SW_BAD_STATE


def test_mldsa_signs_cairo_little_endian_hash(firmware, backend, navigator):
    enable_blind_signing(firmware, navigator)
    public_key, _ = get_public_key(backend)

    backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 0, 0, DERIVATION_PATH))
    with backend.exchange_async_raw(
        apdu(INS_SIGN_MLDSA44_HASH, 1, 0, TEST_HASH_BE)
    ):
        approve_hash(firmware, backend, navigator)

    signature = collect_transfer(
        backend,
        backend.last_async_response.data,
        MLDSA_SIGNATURE_KIND,
        MLDSA_SIGNATURE_LEN,
    )
    assert len(signature) == MLDSA_SIGNATURE_LEN

    verification_key = VerificationKey(public_key)
    verification_key.verify(signature, TEST_HASH_BE[::-1])
    with pytest.raises(VerificationError):
        verification_key.verify(signature, TEST_HASH_BE)

    packed_felts = pack_cairo_felts(signature)
    assert len(packed_felts) == 79
    assert packed_felts[-1] < 1 << 16
    assert unpack_cairo_felts(packed_felts, len(signature)) == signature

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 1, 0, TEST_HASH_BE))
    assert error.value.status == Errors.SW_BAD_STATE


def test_mldsa_rejects_noncanonical_starknet_hash(backend):
    starknet_prime = (2**251 + 17 * 2**192 + 1).to_bytes(32, "big")
    backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 0, 0, DERIVATION_PATH))
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 1, 0, starknet_prime))
    assert error.value.status == Errors.SW_BAD_DATA

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu(INS_SIGN_MLDSA44_HASH, 1, 0, TEST_HASH_BE))
    assert error.value.status == Errors.SW_BAD_STATE
