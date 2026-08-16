"""Local Unix-socket input for collector-owned BLE Remote ID events."""

from __future__ import annotations

import asyncio
import grp
import inspect
import json
import logging
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Callable


log = logging.getLogger("droneaware.external")

REMOTE_ID_SERVICE_UUID = "0000fffa-0000-1000-8000-00805f9b34fb"
DEFAULT_SOCKET_PATH = "/run/droneaware/ble-input.sock"
DEFAULT_SOCKET_MODE = 0o660
DEFAULT_MAX_LINE_BYTES = 8192
MAX_SERVICE_DATA_BYTES = 2048

_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class ExternalEventError(ValueError):
    """Raised when a local producer sends an invalid event."""


def _as_int(name: str, value: object, base: int = 10) -> int:
    """Coerce one config value, naming the setting when it is unusable.

    main() passes raw config.env strings so that every BLE_INPUT setting that
    fails to parse surfaces from here as a ValueError the feeder can report as
    a FAULT reason, rather than as an int() traceback before startup.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    try:
        return int(str(value).strip(), base)
    except (TypeError, ValueError):
        raise ValueError(f"{name} is not a valid value: {value!r}") from None


def _optional_string(payload: dict, key: str, max_length: int) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ExternalEventError(f"{key} must be a string or null")
    value = value.strip()
    if not value or len(value) > max_length:
        raise ExternalEventError(f"{key} must contain 1-{max_length} characters")
    return value


def _optional_int(
    payload: dict,
    key: str,
    minimum: int,
    maximum: int,
) -> int | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExternalEventError(f"{key} must be an integer or null")
    if not minimum <= value <= maximum:
        raise ExternalEventError(f"{key} must be between {minimum} and {maximum}")
    return value


def _parse_observed_at(payload: dict) -> str | None:
    value = _optional_string(payload, "observed_at", 64)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExternalEventError("observed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ExternalEventError("observed_at must include a UTC offset")
    return value


def parse_external_event(payload: object) -> dict:
    """Validate one protocol-v1 event and return a normalized capture."""
    if not isinstance(payload, dict):
        raise ExternalEventError("event must be a JSON object")
    if payload.get("version") != 1:
        raise ExternalEventError("version must be 1")

    receiver = _optional_string(payload, "receiver", 128)
    if receiver is None:
        raise ExternalEventError("receiver is required")

    source_mac = _optional_string(payload, "source_mac", 17)
    if source_mac is not None and not _MAC_RE.fullmatch(source_mac):
        raise ExternalEventError("source_mac must be a colon-separated MAC address")

    service_uuid = _optional_string(payload, "service_uuid", 64)
    if service_uuid is None:
        raise ExternalEventError("service_uuid is required")
    normalized_uuid = service_uuid.lower().replace("-", "")
    if normalized_uuid not in {"fffa", "0000fffa00001000800000805f9b34fb"}:
        raise ExternalEventError("service_uuid must identify the Remote ID FFFA service")

    service_data_hex = _optional_string(payload, "service_data_hex", 2 * MAX_SERVICE_DATA_BYTES)
    if service_data_hex is None:
        raise ExternalEventError("service_data_hex is required")
    if service_data_hex.startswith(("0x", "0X")):
        raise ExternalEventError("service_data_hex must not include a 0x prefix")
    if len(service_data_hex) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", service_data_hex):
        raise ExternalEventError("service_data_hex must contain paired hexadecimal bytes")
    try:
        service_data = bytes.fromhex(service_data_hex)
    except ValueError as exc:
        raise ExternalEventError("service_data_hex must contain valid hexadecimal") from exc
    if not service_data:
        raise ExternalEventError("service_data_hex must not be empty")
    if len(service_data) > MAX_SERVICE_DATA_BYTES:
        raise ExternalEventError(
            f"service_data_hex exceeds {MAX_SERVICE_DATA_BYTES} decoded bytes"
        )

    return {
        "source_mac": source_mac.upper() if source_mac else None,
        "source_name": _optional_string(payload, "source_name", 255),
        "rssi": _optional_int(payload, "rssi", -127, 20),
        "channel": _optional_int(payload, "channel", 0, 39),
        "tx_power": _optional_int(payload, "tx_power", -127, 127),
        "service_uuid": REMOTE_ID_SERVICE_UUID,
        "service_data": service_data,
        "observed_at": _parse_observed_at(payload),
        "receiver": receiver,
        "profile": _optional_string(payload, "profile", 64),
    }


class ExternalBackend:
    """Accept newline-delimited JSON events over a private Unix socket."""

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        socket_mode: int = DEFAULT_SOCKET_MODE,
        socket_group: str = "",
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    ) -> None:
        socket_path = (str(socket_path).strip() or DEFAULT_SOCKET_PATH)
        socket_mode = _as_int("EXTERNAL_BLE_SOCKET_MODE", socket_mode, 8)
        max_line_bytes = _as_int("EXTERNAL_BLE_MAX_LINE_BYTES", max_line_bytes)
        path = Path(socket_path)
        if not path.is_absolute():
            raise ValueError("external BLE socket path must be absolute")
        if socket_mode & ~0o777:
            raise ValueError("external BLE socket mode must contain permission bits only")
        if max_line_bytes < 256:
            raise ValueError("external BLE maximum line size must be at least 256 bytes")

        self.socket_path = str(path)
        self.socket_mode = socket_mode
        self.socket_group = socket_group.strip()
        self.max_line_bytes = max_line_bytes
        self.label = f"external:{self.socket_path}"
        self.healthy = False
        self._server: asyncio.Server | None = None

    def health(self) -> tuple[bool, str]:
        try:
            socket_present = stat.S_ISSOCK(os.stat(self.socket_path).st_mode)
        except OSError:
            socket_present = False
        return self.healthy and socket_present, self.label

    def _remove_stale_socket(self) -> None:
        try:
            existing = os.lstat(self.socket_path)
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(existing.st_mode):
            raise RuntimeError(
                f"refusing to replace non-socket path at {self.socket_path}"
            )
        os.unlink(self.socket_path)

    def _apply_permissions(self) -> None:
        os.chmod(self.socket_path, self.socket_mode)
        if self.socket_group:
            try:
                group_id = grp.getgrnam(self.socket_group).gr_gid
            except KeyError as exc:
                raise RuntimeError(
                    f"external BLE socket group does not exist: {self.socket_group}"
                ) from exc
            os.chown(self.socket_path, -1, group_id)

    async def _reply(self, writer: asyncio.StreamWriter, payload: dict) -> None:
        writer.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())
        await writer.drain()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        callback: Callable[[dict], object],
    ) -> None:
        try:
            while True:
                try:
                    line = await reader.readline()
                except ValueError:
                    await self._reply(
                        writer,
                        {"accepted": False, "error": "event exceeds maximum line size"},
                    )
                    return
                if not line:
                    return
                if len(line) > self.max_line_bytes:
                    await self._reply(
                        writer,
                        {"accepted": False, "error": "event exceeds maximum line size"},
                    )
                    return
                try:
                    decoded = line.decode("utf-8")
                    capture = parse_external_event(json.loads(decoded))
                    callback_result = callback(capture)
                    if inspect.isawaitable(callback_result):
                        callback_result = await callback_result
                    if callback_result is False:
                        await self._reply(
                            writer,
                            {"accepted": False, "error": "event was not accepted"},
                        )
                        continue
                except (UnicodeDecodeError, json.JSONDecodeError, ExternalEventError) as exc:
                    await self._reply(writer, {"accepted": False, "error": str(exc)})
                    continue
                except Exception:
                    log.exception("External BLE event consumer failed")
                    await self._reply(
                        writer,
                        {"accepted": False, "error": "event consumer failed"},
                    )
                    continue
                await self._reply(writer, {"accepted": True})
        except (ConnectionError, BrokenPipeError):
            return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, BrokenPipeError):
                pass

    async def run(self, callback: Callable[[dict], object]) -> None:
        parent = os.path.dirname(self.socket_path)
        os.makedirs(parent, mode=0o750, exist_ok=True)
        self._remove_stale_socket()

        try:
            # start_unix_server() binds with the process umask, so between the
            # bind and the chmod below the socket carries 0777 & ~umask. Under
            # a permissive umask that is a window in which any local user can
            # connect and inject events. Bind private, then widen to the
            # configured mode.
            previous_umask = os.umask(0o077)
            try:
                self._server = await asyncio.start_unix_server(
                    lambda reader, writer: self._handle_client(reader, writer, callback),
                    path=self.socket_path,
                    limit=self.max_line_bytes + 1,
                )
            finally:
                os.umask(previous_umask)
            self._apply_permissions()
            self.healthy = True
            log.info(
                "External BLE input listening on %s (mode %04o)",
                self.socket_path,
                self.socket_mode,
            )
            async with self._server:
                await self._server.serve_forever()
        finally:
            self.healthy = False
            if self._server is not None:
                self._server.close()
                await self._server.wait_closed()
                self._server = None
            try:
                existing = os.lstat(self.socket_path)
            except FileNotFoundError:
                existing = None
            if existing is not None and stat.S_ISSOCK(existing.st_mode):
                os.unlink(self.socket_path)
