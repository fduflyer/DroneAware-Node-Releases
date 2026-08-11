#!/usr/bin/env python3
"""Optional Sniffle serial backend for the DroneAware BLE feeder.

The DroneAware release does not bundle Sniffle. Operators point
``SNIFFLE_PYTHON`` at an independently installed Sniffle ``python_cli``
directory, which keeps the projects and their licenses separate.
"""

from __future__ import annotations

import asyncio
import logging
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


class SniffleBackend:
    """Rotate one Sniffle radio across coded, extended, and legacy BLE."""

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
    ) -> None:
        if not python_path:
            raise ValueError("SNIFFLE_PYTHON is required for the Sniffle backend")
        if not serial_port:
            raise ValueError("SNIFFLE_SERIAL is required for the Sniffle backend")
        if channel not in (37, 38, 39):
            raise ValueError("SNIFFLE_CHANNEL must be 37, 38, or 39")
        for name, dwell in (
            ("SNIFFLE_CODED_SECONDS", coded_seconds),
            ("SNIFFLE_EXTENDED_SECONDS", extended_seconds),
            ("SNIFFLE_LEGACY_SECONDS", legacy_seconds),
        ):
            if dwell <= 0:
                raise ValueError(f"{name} must be greater than zero")

        self.python_path = str(Path(python_path).expanduser())
        self.serial_port = str(Path(serial_port).expanduser())
        self.baudrate = baudrate
        self.channel = channel
        self.serial_timeout = serial_timeout
        self.profiles = (
            ("bt5-coded", True, True, coded_seconds),
            ("bt5-extended", True, False, extended_seconds),
            ("bt4-legacy", False, False, legacy_seconds),
        )
        self.hardware: Any = None
        self.healthy = False
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
        profile: tuple[str, bool, bool, float],
    ) -> None:
        name, extended, coded, dwell = profile
        log.info(
            "[Sniffle] profile=%s channel=%s dwell_seconds=%g",
            name,
            self.channel,
            dwell,
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
        # Sniffle's mark_and_flush() uses a desynchronization read path that
        # does not honor the serial timeout when a marker reply is lost. A
        # missing reply can therefore freeze profile rotation indefinitely.
        # Clearing already-buffered UART input provides the behavior needed
        # here without entering that unbounded loop.
        hardware.ser.reset_input_buffer()
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
                    deadline = time.monotonic() + profile[3]
                    while time.monotonic() < deadline:
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
