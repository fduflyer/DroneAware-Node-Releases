#!/usr/bin/env python3
"""Unit tests for Sniffle Remote ID advertisement extraction."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile

from sniffle_backend import SerialTimeoutException, SniffleBackend, extract_sniffle_advertisement


class FakeAdvertisement:
    def __init__(self, adv_data: bytes) -> None:
        self.adv_data = adv_data
        self.AdvA = bytes.fromhex("010203040506")
        self.rssi = -67
        self.chan = 37
        self.TxPower = 12


class SniffleAdvertisementTests(unittest.TestCase):
    def test_extracts_remote_id_service_data(self) -> None:
        service_data = b"\x0d\x01" + bytes(range(25))
        field = bytes([1 + 2 + len(service_data), 0x16]) + b"\xfa\xff" + service_data
        capture = extract_sniffle_advertisement(
            FakeAdvertisement(b"\x02\x01\x06" + field),
            profile="bt5-coded",
        )

        self.assertIsNotNone(capture)
        self.assertEqual(capture["service_data"], service_data)
        self.assertEqual(capture["source_mac"], "06:05:04:03:02:01")
        self.assertEqual(capture["rssi"], -67)
        self.assertEqual(capture["channel"], 37)
        self.assertEqual(capture["tx_power"], 12)
        self.assertEqual(capture["profile"], "bt5-coded")

    def test_ignores_other_service_uuids(self) -> None:
        field = b"\x05\x16\x34\x12\x0d\x00"
        self.assertIsNone(extract_sniffle_advertisement(FakeAdvertisement(field)))

    def test_rejects_truncated_ad_structure(self) -> None:
        self.assertIsNone(
            extract_sniffle_advertisement(FakeAdvertisement(b"\x1e\x16\xfa\xff\x0d"))
        )

    def test_uses_cached_mac_for_auxiliary_fragment(self) -> None:
        service_data = b"\x0d" + bytes(range(25))
        field = bytes([1 + 2 + len(service_data), 0x16]) + b"\xfa\xff" + service_data
        message = FakeAdvertisement(field)
        message.AdvA = None
        capture = extract_sniffle_advertisement(
            message,
            fallback_mac="AA:BB:CC:DD:EE:FF",
        )
        self.assertEqual(capture["source_mac"], "AA:BB:CC:DD:EE:FF")


class FakeSerial:
    def __init__(self) -> None:
        self.reset_count = 0
        self.closed = False

    def reset_input_buffer(self) -> None:
        self.reset_count += 1

    def close(self) -> None:
        self.closed = True


class FakeHardware:
    def __init__(self) -> None:
        self.ser = FakeSerial()
        self.profiles = []
        self.cancelled = False

    def setup_sniffer(self, **kwargs) -> None:
        self.profiles.append(kwargs)

    def recv_and_decode(self):
        raise SerialTimeoutException()

    def cancel_recv(self) -> None:
        self.cancelled = True


class SniffleBackendTests(unittest.IsolatedAsyncioTestCase):
    async def test_rotates_all_profiles_without_marker_flush(self) -> None:
        hardware = FakeHardware()

        class PhyMode:
            PHY_2M = "2m"

        class SnifferMode:
            PASSIVE_SCAN = "passive"

        with NamedTemporaryFile() as serial_device:
            backend = SniffleBackend(
                python_path=str(Path(__file__).parent),
                serial_port=serial_device.name,
                coded_seconds=0.001,
                extended_seconds=0.001,
                legacy_seconds=0.001,
                serial_timeout=0.001,
            )
            backend._load_api = lambda: (
                lambda **kwargs: hardware,
                PhyMode,
                SnifferMode,
            )
            await backend.run(lambda capture: None, cycles=1)

        self.assertEqual(len(hardware.profiles), 3)
        self.assertEqual(hardware.ser.reset_count, 3)
        self.assertTrue(hardware.cancelled)
        self.assertTrue(hardware.ser.closed)
        self.assertFalse(backend.healthy)

        coded, extended, legacy = hardware.profiles
        self.assertEqual((coded["ext_adv"], coded["coded_phy"]), (True, True))
        self.assertEqual((extended["ext_adv"], extended["coded_phy"]), (True, False))
        self.assertEqual((legacy["ext_adv"], legacy["coded_phy"]), (False, False))


if __name__ == "__main__":
    unittest.main()
