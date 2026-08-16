#!/usr/bin/env python3
"""Optional Sniffle serial backend for the DroneAware BLE feeder.

The DroneAware release does not bundle Sniffle. Operators point
``SNIFFLE_PYTHON`` at an independently installed Sniffle ``python_cli``
directory, which keeps the projects and their licenses separate.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Callable

try:
    from serial import SerialTimeoutException
except ModuleNotFoundError:  # Allows parser-only tests before build deps install.
    class SerialTimeoutException(Exception):
        pass


log = logging.getLogger("droneaware.ble.sniffle")


def _format_mac(raw: Any) -> str | None:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 6:
        return None
    return ":".join(f"{byte:02X}" for byte in reversed(raw))


def _service_data_from_advertisement(adv_data: bytes) -> bytes | None:
    """Return UUID 0xFFFA service data from a BLE AD structure sequence."""
    offset = 0
    while offset < len(adv_data):
        field_length = adv_data[offset]
        if field_length == 0:
            break
        field_end = offset + 1 + field_length
        if field_end > len(adv_data):
            return None
        ad_type = adv_data[offset + 1]
        value = adv_data[offset + 2:field_end]
        if ad_type == 0x16 and len(value) >= 2 and value[:2] == b"\xfa\xff":
            return value[2:]
        offset = field_end
    return None


def extract_sniffle_advertisement(
    message: Any,
    *,
    fallback_mac: str | None = None,
    profile: str | None = None,
) -> dict[str, Any] | None:
    """Convert a decoded Sniffle advertisement into feeder-neutral fields.

    Sniffle's public packet objects expose ``adv_data``, ``AdvA``, RSSI,
    channel, and optional transmit power attributes. Attribute access keeps
    this module compatible with both legacy and extended advertisement
    subclasses without importing or redistributing Sniffle's GPL code.
    """
    adv_data = getattr(message, "adv_data", None)
    if not isinstance(adv_data, (bytes, bytearray)):
        return None
    service_data = _service_data_from_advertisement(bytes(adv_data))
    if service_data is None:
        return None
    source_mac = _format_mac(getattr(message, "AdvA", None)) or fallback_mac
    return {
        "source_mac": source_mac,
        "rssi": getattr(message, "rssi", None),
        "channel": getattr(message, "chan", None),
        "tx_power": getattr(message, "TxPower", None),
        "service_data": service_data,
        "profile": profile,
    }


def _as_number(name: str, value: Any, cast: Callable[[Any], Any]) -> Any:
    """Coerce one config value, naming the setting when it is unusable.

    Callers pass raw config.env strings so that every SNIFFLE_* validation
    failure surfaces from one place as a ValueError the feeder can report as a
    FAULT reason, rather than as an argparse or int() traceback at startup.
    """
    try:
        return cast(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} is not a valid number: {value!r}") from None


def _decode_complete_line(line: bytes) -> bytes | None:
    """Decode one complete Sniffle record without trusting an unframed header."""
    if not line.endswith(b"\r\n"):
        return None
    encoded = line[:-2]
    if not encoded or len(encoded) % 4:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) < 2 or decoded[0] * 4 != len(encoded):
        return None
    return decoded


def synchronize_hardware(
    hardware: Any,
    timeout_seconds: float,
    *,
    marker_factory: Callable[[int], bytes] = secrets.token_bytes,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Discard complete old records until our marker arrives, within a deadline.

    Sniffle's own ``mark_and_flush()`` reads through a desynchronization path
    that does not honor the serial timeout, so a lost marker reply can hang
    profile rotation forever. Clearing the UART with ``reset_input_buffer()``
    avoids that hang but can cut a partially received record in half, which
    then surfaces as a parser framing error on the next read.

    This keeps the bounded behavior without either failure mode: send a
    cryptographically unique marker, then read only complete CRLF-delimited
    records until that exact marker returns. Every attempt has a real
    monotonic deadline, and exhausting it raises so the caller can fail fast
    instead of leaving an apparently active but frozen receiver.
    """
    if timeout_seconds <= 0:
        raise ValueError("sync timeout must be positive")

    marker = marker_factory(16)
    deadline = monotonic() + timeout_seconds
    original_timeout = hardware.ser.timeout
    discarded_lines = 0
    invalid_lines = 0
    hardware.cmd_marker(marker)
    try:
        while True:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise SerialTimeoutException(
                    f"Sniffle marker was not received within {timeout_seconds:g}s"
                )
            hardware.ser.timeout = (
                remaining
                if original_timeout is None
                else min(float(original_timeout), remaining)
            )
            line = hardware.ser.readline()
            decoded = _decode_complete_line(line)
            if decoded is None:
                invalid_lines += 1
                continue
            if decoded[1] == 0x12 and len(decoded) >= 6 and decoded[6:] == marker:
                return {
                    "discarded_lines": discarded_lines,
                    "invalid_lines": invalid_lines,
                }
            discarded_lines += 1
    finally:
        hardware.ser.timeout = original_timeout


class SniffleBackend:
    """Drive one Sniffle radio over the configured Remote ID BLE profiles."""

    def __init__(
        self,
        *,
        python_path: str,
        serial_port: str,
        baudrate: int = 2_000_000,
        channel: int = 37,
        coded_seconds: float = 30.0,
        extended_seconds: float = 15.0,
        legacy_seconds: float = 15.0,
        serial_timeout: float = 0.5,
        profile_mode: str = "rotate",
        sync_timeout: float = 5.0,
    ) -> None:
        if not python_path:
            raise ValueError("SNIFFLE_PYTHON is required for the Sniffle backend")
        if not serial_port:
            raise ValueError("SNIFFLE_SERIAL is required for the Sniffle backend")
        baudrate = _as_number("SNIFFLE_BAUD", baudrate, int)
        channel = _as_number("SNIFFLE_CHANNEL", channel, int)
        coded_seconds = _as_number("SNIFFLE_CODED_SECONDS", coded_seconds, float)
        extended_seconds = _as_number("SNIFFLE_EXTENDED_SECONDS", extended_seconds, float)
        legacy_seconds = _as_number("SNIFFLE_LEGACY_SECONDS", legacy_seconds, float)
        serial_timeout = _as_number("SNIFFLE_SERIAL_TIMEOUT", serial_timeout, float)
        sync_timeout = _as_number("SNIFFLE_SYNC_TIMEOUT", sync_timeout, float)
        profile_mode = (profile_mode or "rotate").strip().lower() or "rotate"
        if channel not in (37, 38, 39):
            raise ValueError("SNIFFLE_CHANNEL must be 37, 38, or 39")
        if profile_mode not in ("rotate", "coded-only"):
            raise ValueError("SNIFFLE_PROFILE_MODE must be rotate or coded-only")
        for name, dwell in (
            ("SNIFFLE_CODED_SECONDS", coded_seconds),
            ("SNIFFLE_EXTENDED_SECONDS", extended_seconds),
            ("SNIFFLE_LEGACY_SECONDS", legacy_seconds),
            ("SNIFFLE_SYNC_TIMEOUT", sync_timeout),
        ):
            if dwell <= 0:
                raise ValueError(f"{name} must be greater than zero")

        self.python_path = str(Path(python_path).expanduser())
        self.serial_port = str(Path(serial_port).expanduser())
        self.baudrate = baudrate
        self.channel = channel
        self.serial_timeout = serial_timeout
        self.sync_timeout = sync_timeout
        self.profile_mode = profile_mode
        self.coded_seconds = coded_seconds
        if profile_mode == "coded-only":
            # Rotation leaves the coded PHY unwatched for the whole extended
            # plus legacy dwell, which is a deterministic blind window for
            # coded-PHY Remote ID traffic. Dedicating the radio removes that
            # window at the cost of this receiver's coverage of the other two
            # profiles, which an hciN controller alongside it still sees.
            self.profiles = (("bt5-coded", True, True, None),)
        else:
            self.profiles = (
                ("bt5-coded", True, True, coded_seconds),
                ("bt5-extended", True, False, extended_seconds),
                ("bt4-legacy", False, False, legacy_seconds),
            )
        self.hardware: Any = None
        self.healthy = False
        self.sync_count = 0
        self.discarded_lines = 0
        self.current_profile: str | None = None
        self.last_source_mac: str | None = None
        self.source_mac_by_adi: dict[tuple[int, int], str] = {}

    @property
    def label(self) -> str:
        return f"sniffle:{self.serial_port}"

    def health(self) -> tuple[bool, str]:
        return self.healthy and Path(self.serial_port).exists(), self.label

    def _load_api(self) -> tuple[Any, Any, Any]:
        python_path = Path(self.python_path)
        if not python_path.is_dir():
            raise RuntimeError(f"Sniffle Python directory not found: {python_path}")
        if self.python_path not in sys.path:
            sys.path.insert(0, self.python_path)
        try:
            from sniffle.sniffle_hw import PhyMode, SnifferMode, make_sniffle_hw
        except ImportError as error:
            raise RuntimeError(
                f"Could not import Sniffle from {python_path}: {error}"
            ) from error
        return make_sniffle_hw, PhyMode, SnifferMode

    def _configure_profile(
        self,
        hardware: Any,
        phy_mode: Any,
        sniffer_mode: Any,
        profile: tuple[str, bool, bool, float | None],
    ) -> None:
        name, extended, coded, dwell = profile
        log.info(
            "[Sniffle] profile=%s channel=%s dwell_seconds=%s",
            name,
            self.channel,
            "continuous" if dwell is None else f"{dwell:g}",
        )
        hardware.setup_sniffer(
            mode=sniffer_mode.PASSIVE_SCAN,
            chan=self.channel,
            hop3=False,
            ext_adv=extended,
            coded_phy=coded,
            rssi_min=-128,
            phy_preload=phy_mode.PHY_2M,
            validate_crc=True,
        )
        # Drain records written under the previous profile before attributing
        # anything to this one. synchronize_hardware() is bounded and reads
        # only complete records, so a lost marker fails fast here rather than
        # hanging rotation or truncating a partially received record.
        result = synchronize_hardware(hardware, self.sync_timeout)
        self.sync_count += 1
        self.discarded_lines += result["discarded_lines"]
        self.current_profile = name

    def _fallback_mac(self, message: Any) -> str | None:
        source_mac = _format_mac(getattr(message, "AdvA", None))
        adi = getattr(message, "AdvDataInfo", None)
        adi_key = None
        if adi is not None:
            did = getattr(adi, "did", None)
            sid = getattr(adi, "sid", None)
            if isinstance(did, int) and isinstance(sid, int):
                adi_key = (did, sid)
        if source_mac:
            self.last_source_mac = source_mac
            if adi_key is not None:
                self.source_mac_by_adi[adi_key] = source_mac
            return source_mac
        if adi_key is not None and adi_key in self.source_mac_by_adi:
            return self.source_mac_by_adi[adi_key]
        return self.last_source_mac

    async def run(
        self,
        callback: Callable[[dict[str, Any]], None],
        *,
        cycles: int | None = None,
    ) -> None:
        """Capture continuously, or for a bounded number of test cycles."""
        if cycles is not None and cycles < 1:
            raise ValueError("cycles must be at least one when supplied")
        make_sniffle_hw, phy_mode, sniffer_mode = self._load_api()
        if not Path(self.serial_port).exists():
            raise RuntimeError(f"Sniffle serial device not found: {self.serial_port}")
        self.hardware = await asyncio.to_thread(
            make_sniffle_hw,
            serport=self.serial_port,
            baudrate=self.baudrate,
            timeout=self.serial_timeout,
        )
        self.healthy = True
        completed_cycles = 0
        try:
            while cycles is None or completed_cycles < cycles:
                for profile in self.profiles:
                    await asyncio.to_thread(
                        self._configure_profile,
                        self.hardware,
                        phy_mode,
                        sniffer_mode,
                        profile,
                    )
                    dwell = profile[3]
                    if dwell is None:
                        # coded-only dedicates the radio, so there is no dwell
                        # to expire. A bounded test run still needs an exit,
                        # so it borrows the configured coded dwell.
                        dwell = self.coded_seconds if cycles is not None else None
                    deadline = None if dwell is None else time.monotonic() + dwell
                    while deadline is None or time.monotonic() < deadline:
                        try:
                            message = await asyncio.to_thread(
                                self.hardware.recv_and_decode
                            )
                        except SerialTimeoutException:
                            continue
                        if message is None:
                            continue
                        capture = extract_sniffle_advertisement(
                            message,
                            fallback_mac=self._fallback_mac(message),
                            profile=self.current_profile,
                        )
                        if capture is not None:
                            callback(capture)
                completed_cycles += 1
        finally:
            self.healthy = False
            if self.hardware is not None:
                try:
                    self.hardware.cancel_recv()
                except Exception:
                    pass
                try:
                    self.hardware.ser.close()
                except Exception:
                    pass
