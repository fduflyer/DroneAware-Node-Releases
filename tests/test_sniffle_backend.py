#!/usr/bin/env python3
"""Unit tests for Sniffle Remote ID advertisement extraction."""

from __future__ import annotations

import base64
import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile

from sniffle_backend import (
    SerialTimeoutException,
    SniffleBackend,
    extract_sniffle_advertisement,
    synchronize_hardware,
)


def marker_record(marker: bytes) -> bytes:
    """Build one complete Sniffle marker record as the parser expects it."""
    payload = bytes([8, 0x12]) + b"\x00\x00\x00\x00" + marker
    return base64.b64encode(payload) + b"\r\n"


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
        self.timeout = 0.5
        self.closed = False
        self.pending: list[bytes] = []
        self.reset_count = 0

    def reset_input_buffer(self) -> None:  # must stay unused
        self.reset_count += 1

    def readline(self) -> bytes:
        return self.pending.pop(0) if self.pending else b""

    def close(self) -> None:
        self.closed = True


class FakeHardware:
    def __init__(self, *, stale_lines: int = 2) -> None:
        self.ser = FakeSerial()
        self.profiles: list[dict] = []
        self.markers: list[bytes] = []
        self.cancelled = False
        self.stale_lines = stale_lines

    def setup_sniffer(self, **kwargs) -> None:
        self.profiles.append(kwargs)

    def cmd_marker(self, marker: bytes) -> None:
        self.markers.append(marker)
        # A truncated record plus a complete stale one, then our marker.
        self.ser.pending = (
            [b"not-a-complete-record"]
            + [base64.b64encode(bytes([6, 0x10]) + b"\x00" * 14) + b"\r\n"] * self.stale_lines
            + [marker_record(marker)]
        )

    def recv_and_decode(self):
        raise SerialTimeoutException()

    def cancel_recv(self) -> None:
        self.cancelled = True


class SynchronizeHardwareTests(unittest.TestCase):
    def test_discards_stale_records_until_marker(self) -> None:
        hardware = FakeHardware(stale_lines=3)
        result = synchronize_hardware(hardware, 5.0)

        self.assertEqual(result["discarded_lines"], 3)
        self.assertEqual(result["invalid_lines"], 1)
        self.assertEqual(hardware.ser.reset_count, 0)
        self.assertEqual(hardware.ser.timeout, 0.5, "original timeout restored")

    def test_raises_when_marker_never_arrives(self) -> None:
        hardware = FakeHardware()
        hardware.cmd_marker = lambda marker: None  # radio never answers

        clock = iter([0.0, 0.0, 10.0])
        with self.assertRaises(SerialTimeoutException):
            synchronize_hardware(hardware, 5.0, monotonic=lambda: next(clock))
        self.assertEqual(hardware.ser.timeout, 0.5, "original timeout restored")

    def test_rejects_non_positive_timeout(self) -> None:
        with self.assertRaises(ValueError):
            synchronize_hardware(FakeHardware(), 0)


class SniffleBackendConfigTests(unittest.TestCase):
    def _backend(self, **overrides):
        options = {
            "python_path": str(Path(__file__).parent),
            "serial_port": __file__,
        }
        options.update(overrides)
        return SniffleBackend(**options)

    def test_rejects_unknown_profile_mode(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._backend(profile_mode="sometimes")
        self.assertIn("SNIFFLE_PROFILE_MODE", str(ctx.exception))

    def test_names_the_setting_behind_an_unparseable_value(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            self._backend(coded_seconds="thirty")
        self.assertIn("SNIFFLE_CODED_SECONDS", str(ctx.exception))

    def test_accepts_config_env_strings(self) -> None:
        backend = self._backend(channel="39", coded_seconds="12.5")
        self.assertEqual(backend.channel, 39)
        self.assertEqual(backend.coded_seconds, 12.5)

    def test_coded_only_dedicates_the_radio(self) -> None:
        backend = self._backend(profile_mode="coded-only")
        self.assertEqual(len(backend.profiles), 1)
        name, extended, coded, dwell = backend.profiles[0]
        self.assertEqual(name, "bt5-coded")
        self.assertEqual((extended, coded), (True, True))
        self.assertIsNone(dwell, "a dedicated radio has no dwell to expire")


class PhyMode:
    PHY_2M = "2m"


class SnifferMode:
    PASSIVE_SCAN = "passive"


class SniffleBackendTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, hardware, **overrides):
        with NamedTemporaryFile() as serial_device:
            options = {
                "python_path": str(Path(__file__).parent),
                "serial_port": serial_device.name,
                "coded_seconds": 0.001,
                "extended_seconds": 0.001,
                "legacy_seconds": 0.001,
                "serial_timeout": 0.001,
            }
            options.update(overrides)
            backend = SniffleBackend(**options)
            backend._load_api = lambda: (lambda **kwargs: hardware, PhyMode, SnifferMode)
            await backend.run(lambda capture: None, cycles=1)
        return backend

    async def test_rotates_all_profiles_and_synchronizes_each(self) -> None:
        hardware = FakeHardware()
        backend = await self._run(hardware)

        self.assertEqual(len(hardware.profiles), 3)
        self.assertEqual(len(hardware.markers), 3, "one marker sync per profile")
        self.assertEqual(len(set(hardware.markers)), 3, "markers must be unique")
        self.assertEqual(backend.sync_count, 3)
        self.assertEqual(
            hardware.ser.reset_count,
            0,
            "reset_input_buffer can truncate a partial record; use the marker",
        )
        self.assertTrue(hardware.cancelled)
        self.assertTrue(hardware.ser.closed)
        self.assertFalse(backend.healthy)

        coded, extended, legacy = hardware.profiles
        self.assertEqual((coded["ext_adv"], coded["coded_phy"]), (True, True))
        self.assertEqual((extended["ext_adv"], extended["coded_phy"]), (True, False))
        self.assertEqual((legacy["ext_adv"], legacy["coded_phy"]), (False, False))

    async def test_coded_only_configures_one_profile(self) -> None:
        hardware = FakeHardware()
        backend = await self._run(hardware, profile_mode="coded-only")

        self.assertEqual(len(hardware.profiles), 1)
        self.assertEqual(backend.sync_count, 1)
        only = hardware.profiles[0]
        self.assertEqual((only["ext_adv"], only["coded_phy"]), (True, True))


if __name__ == "__main__":
    unittest.main()
