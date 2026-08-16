#!/usr/bin/env python3
"""Unit and socket tests for the collector-owned BLE input."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import tempfile
import unittest
from contextlib import suppress

from external_backend import (
    DEFAULT_SOCKET_PATH,
    ExternalBackend,
    ExternalEventError,
    parse_external_event,
)


def valid_event() -> dict:
    return {
        "version": 1,
        "observed_at": "2026-08-11T19:42:03.123Z",
        "receiver": "sonoff-sniffle",
        "profile": "bt5-coded",
        "source_mac": "aa:bb:cc:dd:ee:ff",
        "rssi": -67,
        "channel": 37,
        "tx_power": 12,
        "service_uuid": "0000fffa-0000-1000-8000-00805f9b34fb",
        "service_data_hex": "0d01" + bytes(range(25)).hex(),
    }


class ExternalEventTests(unittest.TestCase):
    def test_normalizes_valid_event(self) -> None:
        capture = parse_external_event(valid_event())

        self.assertEqual(capture["source_mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(capture["receiver"], "sonoff-sniffle")
        self.assertEqual(capture["profile"], "bt5-coded")
        self.assertEqual(capture["service_data"], b"\x0d\x01" + bytes(range(25)))

    def test_rejects_non_remote_id_uuid(self) -> None:
        event = valid_event()
        event["service_uuid"] = "180f"
        with self.assertRaisesRegex(ExternalEventError, "FFFA"):
            parse_external_event(event)

    def test_requires_timezone_on_source_timestamp(self) -> None:
        event = valid_event()
        event["observed_at"] = "2026-08-11T19:42:03"
        with self.assertRaisesRegex(ExternalEventError, "UTC offset"):
            parse_external_event(event)

    def test_rejects_noncanonical_service_data_hex(self) -> None:
        event = valid_event()
        event["service_data_hex"] = "0d 01"
        with self.assertRaisesRegex(ExternalEventError, "paired hexadecimal"):
            parse_external_event(event)

    def test_rejects_out_of_range_metadata(self) -> None:
        event = valid_event()
        event["channel"] = 149
        with self.assertRaisesRegex(ExternalEventError, "between 0 and 39"):
            parse_external_event(event)


class ExternalBackendTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.tempdir.name, "ble-input.sock")
        self.backend = ExternalBackend(
            socket_path=self.socket_path,
            socket_mode=0o600,
        )
        self.received: list[dict] = []
        self.task = asyncio.create_task(self.backend.run(self._capture))
        for _ in range(100):
            if os.path.exists(self.socket_path):
                break
            await asyncio.sleep(0.01)
        else:
            self.fail("external backend did not create its socket")

    async def asyncTearDown(self) -> None:
        self.task.cancel()
        with suppress(asyncio.CancelledError):
            await self.task
        self.tempdir.cleanup()

    def _capture(self, capture: dict) -> bool:
        self.received.append(capture)
        return True

    async def _send(self, payload: bytes) -> dict:
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        writer.write(payload + b"\n")
        await writer.drain()
        response = json.loads(await reader.readline())
        writer.close()
        await writer.wait_closed()
        return response

    async def test_accepts_event_and_restricts_socket_permissions(self) -> None:
        response = await self._send(json.dumps(valid_event()).encode())

        self.assertEqual(response, {"accepted": True})
        self.assertEqual(len(self.received), 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.socket_path).st_mode), 0o600)
        self.assertEqual(self.backend.health(), (True, f"external:{self.socket_path}"))

    async def test_rejects_invalid_event_without_calling_consumer(self) -> None:
        response = await self._send(b'{"version":1}')

        self.assertFalse(response["accepted"])
        self.assertIn("receiver", response["error"])
        self.assertEqual(self.received, [])

    async def test_reports_consumer_rejection(self) -> None:
        self.task.cancel()
        with suppress(asyncio.CancelledError):
            await self.task

        rejecting_backend = ExternalBackend(
            socket_path=self.socket_path,
            socket_mode=0o600,
        )
        self.backend = rejecting_backend
        self.task = asyncio.create_task(rejecting_backend.run(lambda capture: False))
        for _ in range(100):
            if rejecting_backend.health()[0]:
                break
            await asyncio.sleep(0.01)

        response = await self._send(json.dumps(valid_event()).encode())
        self.assertEqual(
            response,
            {"accepted": False, "error": "event was not accepted"},
        )


class ExternalBackendSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_refuses_to_replace_non_socket_path(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            socket_path = os.path.join(tempdir, "ble-input.sock")
            with open(socket_path, "w", encoding="utf-8") as placeholder:
                placeholder.write("do not replace")
            backend = ExternalBackend(socket_path=socket_path)

            with self.assertRaisesRegex(RuntimeError, "non-socket"):
                await backend.run(lambda capture: True)
            with open(socket_path, encoding="utf-8") as placeholder:
                self.assertEqual(placeholder.read(), "do not replace")


class ExternalBackendConfigTests(unittest.TestCase):
    def test_parses_octal_mode_from_config_env(self) -> None:
        backend = ExternalBackend(socket_path="/run/x.sock", socket_mode="0640")
        self.assertEqual(backend.socket_mode, 0o640)

    def test_parses_max_line_bytes_from_config_env(self) -> None:
        backend = ExternalBackend(socket_path="/run/x.sock", max_line_bytes="4096")
        self.assertEqual(backend.max_line_bytes, 4096)

    def test_names_the_setting_behind_an_unparseable_value(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            ExternalBackend(socket_path="/run/x.sock", socket_mode="rw-rw----")
        self.assertIn("EXTERNAL_BLE_SOCKET_MODE", str(ctx.exception))

    def test_empty_socket_path_falls_back_to_the_default(self) -> None:
        self.assertEqual(ExternalBackend(socket_path="").socket_path, DEFAULT_SOCKET_PATH)

    def test_rejects_relative_socket_path(self) -> None:
        with self.assertRaises(ValueError):
            ExternalBackend(socket_path="ble-input.sock")


if __name__ == "__main__":
    unittest.main()
