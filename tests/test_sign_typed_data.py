import pytest

from application_client.response_unpacker import unpack_get_public_key_response, unpack_sign_tx_response, Errors
from ragger.navigator import NavInsID, NavIns
from utils import ROOT_SCREENSHOT_PATH, read_lines_from_file, call_external_binary
from ragger.firmware import Firmware

CHECK_SIGNATURE_BINARY_PATH = "tools/check-signature/target/debug/check-signature"

def get_setting_position(firmware: Firmware, setting_idx: int, per_page: int) -> tuple[int, int]:
    if firmware == Firmware.STAX:
        screen_height = 672
        screen_width = 400
        header_height = 88
        footer_height = 92
    elif firmware == Firmware.FLEX:
        screen_height = 600
        screen_width = 480
        header_height = 96
        footer_height = 96
    elif firmware == Firmware.APEX_P:
        screen_height = 400
        screen_width = 300
        header_height = 60
        footer_height = 96

    index_in_page = setting_idx % per_page
    usable_height = screen_height - (header_height + footer_height)
    setting_height = usable_height // per_page
    offset = (setting_height * index_in_page) + (setting_height // 2)
    return screen_width // 2, header_height + offset

# In those tests we check the behavior of the device when asked to sign a SNIP-12 typed data message (clear signing)


# Test 1: Clear sign a simple Transfer message (2 message fields: amount, recipient)
def test_snip12_clear_sign_transfer(firmware, backend, navigator, test_name):

    # First we need to get the public key of the device in order to verify the signature
    file_path = 'samples/apdu/dpath_0.dat'
    apdus = read_lines_from_file(file_path)
    response = backend.exchange_raw(bytes.fromhex(apdus[0])).data
    public_key_x, _ = unpack_get_public_key_response(response)

    # Send the sign typed data device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    file_path = 'samples/apdu/snip12_transfer.dat'
    all_apdus = read_lines_from_file(file_path)

    # send all apdus except last one
    for apdu in all_apdus[:-1]:
        backend.exchange_raw(bytes.fromhex(apdu))

    # send last apdu and yield the response
    with backend.exchange_async_raw(bytes.fromhex(all_apdus[-1])):
        if firmware.device.startswith("nano"):
            # Nano screens: Review message > amount > recipient(1/2) > recipient(2/2) > Sign Message?
            navigator.navigate_until_text_and_compare(NavIns(NavInsID.WAIT, (0,)),
                                              [
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.BOTH_CLICK
                                              ],
                                              "Review message",
                                              path=ROOT_SCREENSHOT_PATH,
                                              test_case_name=test_name)
        else:
            # Touch screens (stax/flex): 3 pages (title, fields, confirm) -> 2 swipes
            navigator.navigate_until_text_and_compare(NavIns(NavInsID.WAIT, (0,)),
                                                      [
                                                          NavInsID.SWIPE_CENTER_TO_LEFT,
                                                          NavInsID.SWIPE_CENTER_TO_LEFT,
                                                          NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                          NavInsID.USE_CASE_STATUS_DISMISS
                                                      ],
                                                      "Review message",
                                                      path=ROOT_SCREENSHOT_PATH,
                                                      test_case_name=test_name)

    response = backend.last_async_response.data

    # Response format: hash(32) + sig_len(1) + r(32) + s(32) + v(1)
    hash, r, s, _ = unpack_sign_tx_response(response)

    # Verify the signature
    binary_path = CHECK_SIGNATURE_BINARY_PATH
    args = ["-t", hash.hex(),
            "-p", public_key_x.hex(),
            "-r", r.hex(),
            "-s", s.hex()]
    stdout, stderr = call_external_binary(binary_path, *args)

    if stdout:
        result = stdout.lower() == "true"
        print(f"Result as boolean: {result}")
        assert(result)
    if stderr:
        print("Standard Error:")
        print(stderr)
        assert(False)


# Test 2: Clear sign an Order message (4 message fields: maker, price, qty, side)
def test_snip12_clear_sign_order(firmware, backend, navigator, test_name):

    # First we need to get the public key of the device
    file_path = 'samples/apdu/dpath_0.dat'
    apdus = read_lines_from_file(file_path)
    response = backend.exchange_raw(bytes.fromhex(apdus[0])).data
    public_key_x, _ = unpack_get_public_key_response(response)

    # Send the sign typed data device instruction.
    file_path = 'samples/apdu/snip12_order.dat'
    all_apdus = read_lines_from_file(file_path)

    # send all apdus except last one
    for apdu in all_apdus[:-1]:
        backend.exchange_raw(bytes.fromhex(apdu))

    # send last apdu and yield the response
    with backend.exchange_async_raw(bytes.fromhex(all_apdus[-1])):
        if firmware.device.startswith("nano"):
            # Nano screens: Review > maker(1/2) > maker(2/2) > price > qty > side > Sign Message?
            navigator.navigate_until_text_and_compare(NavIns(NavInsID.WAIT, (0,)),
                                              [
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.RIGHT_CLICK,
                                                  NavInsID.BOTH_CLICK
                                              ],
                                              "Review message",
                                              path=ROOT_SCREENSHOT_PATH,
                                              test_case_name=test_name)
        elif firmware.device == "flex":
            # Flex: 4 pages (title, maker+price+qty, side, confirm) -> 3 swipes
            navigator.navigate_until_text_and_compare(NavIns(NavInsID.WAIT, (0,)),
                                                      [
                                                          NavInsID.SWIPE_CENTER_TO_LEFT,
                                                          NavInsID.SWIPE_CENTER_TO_LEFT,
                                                          NavInsID.SWIPE_CENTER_TO_LEFT,
                                                          NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                          NavInsID.USE_CASE_STATUS_DISMISS
                                                      ],
                                                      "Review message",
                                                      path=ROOT_SCREENSHOT_PATH,
                                                      test_case_name=test_name)
        else:
            # Stax: 3 pages (title, all fields, confirm) -> 2 swipes
            navigator.navigate_until_text_and_compare(NavIns(NavInsID.WAIT, (0,)),
                                                      [
                                                          NavInsID.SWIPE_CENTER_TO_LEFT,
                                                          NavInsID.SWIPE_CENTER_TO_LEFT,
                                                          NavInsID.USE_CASE_REVIEW_CONFIRM,
                                                          NavInsID.USE_CASE_STATUS_DISMISS
                                                      ],
                                                      "Review message",
                                                      path=ROOT_SCREENSHOT_PATH,
                                                      test_case_name=test_name)

    response = backend.last_async_response.data

    hash, r, s, _ = unpack_sign_tx_response(response)

    # Verify the signature
    binary_path = CHECK_SIGNATURE_BINARY_PATH
    args = ["-t", hash.hex(),
            "-p", public_key_x.hex(),
            "-r", r.hex(),
            "-s", s.hex()]
    stdout, stderr = call_external_binary(binary_path, *args)

    if stdout:
        result = stdout.lower() == "true"
        print(f"Result as boolean: {result}")
        assert(result)
    if stderr:
        print("Standard Error:")
        print(stderr)
        assert(False)


# Test 3: Blind sign a complex message (9 fields exceeds MAX_DISPLAY_FIELDS=8, fallback to blind signing)
def test_snip12_blind_sign_complex(firmware, backend, navigator, test_name):

    # Enable blind signing in settings
    if firmware.device.startswith("nano"):
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.BOTH_CLICK,
            NavInsID.BOTH_CLICK
        ]
        navigator.navigate(instructions, screen_change_before_first_instruction=False)
    else:
        settings_per_page = 3 if firmware == Firmware.STAX else 2
        instructions = [
            NavInsID.USE_CASE_HOME_SETTINGS,
            NavIns(NavInsID.TOUCH, get_setting_position(firmware, 0, settings_per_page)),
        ]
        navigator.navigate(instructions, screen_change_before_first_instruction=False)

    # First we need to get the public key of the device
    file_path = 'samples/apdu/dpath_0.dat'
    apdus = read_lines_from_file(file_path)
    response = backend.exchange_raw(bytes.fromhex(apdus[0])).data
    public_key_x, _ = unpack_get_public_key_response(response)

    # Send the sign typed data device instruction (complex message with 9 fields).
    file_path = 'samples/apdu/snip12_complex.dat'
    all_apdus = read_lines_from_file(file_path)

    # send all apdus except last one
    for apdu in all_apdus[:-1]:
        backend.exchange_raw(bytes.fromhex(apdu))

    # send last apdu and yield the response
    with backend.exchange_async_raw(bytes.fromhex(all_apdus[-1])):
        if firmware.device.startswith("nano"):
            # Nano blind signing: Blind > Hash(1/2) > Hash(2/2) > Sign Hash?
            navigator.navigate_until_text_and_compare(
                NavIns(NavInsID.WAIT, (0,)),
                [
                    NavInsID.BOTH_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.RIGHT_CLICK,
                    NavInsID.BOTH_CLICK
                ],
                "Blind",
                path=ROOT_SCREENSHOT_PATH,
                test_case_name=test_name
            )
        else:
            # Touch blind signing: "Blind signing ahead" > tap footer > swipe hash pages > confirm
            navigator.navigate_until_text_and_compare(
                NavIns(NavInsID.WAIT, (0,)),
                [
                    NavInsID.CENTERED_FOOTER_TAP,
                    NavInsID.SWIPE_CENTER_TO_LEFT,
                    NavInsID.SWIPE_CENTER_TO_LEFT,
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                "Blind signing ahead",
                path=ROOT_SCREENSHOT_PATH,
                test_case_name=test_name
            )

    response = backend.last_async_response.data

    hash, r, s, _ = unpack_sign_tx_response(response)

    # Verify the signature
    binary_path = CHECK_SIGNATURE_BINARY_PATH
    args = ["-t", hash.hex(),
            "-p", public_key_x.hex(),
            "-r", r.hex(),
            "-s", s.hex()]
    stdout, stderr = call_external_binary(binary_path, *args)

    if stdout:
        result = stdout.lower() == "true"
        print(f"Result as boolean: {result}")
        assert(result)
    if stderr:
        print("Standard Error:")
        print(stderr)
        assert(False)
