"""ASTM F3411 decode tests for the node feeders.

Vectors were produced by the OpenDroneID reference encoder
(opendroneid-core-c, libopendroneid/opendroneid.c: encodeSystemMessage /
encodeLocationMessage), so they test against the spec's reference
implementation rather than against another copy of our own decoder.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# The decoders are pure stdlib. Stub the hardware/network libraries so the
# tests run on a dev machine without pyserial or bleak installed.
for _name in ("serial", "requests", "flask"):
    try:
        __import__(_name)
    except ImportError:
        sys.modules[_name] = types.ModuleType(_name)
try:
    import bleak  # noqa: F401
except ImportError:
    _bleak = types.ModuleType("bleak")
    _bleak.BleakScanner = object
    _backends = types.ModuleType("bleak.backends")
    _device = types.ModuleType("bleak.backends.device")
    _device.BLEDevice = object
    _scanner = types.ModuleType("bleak.backends.scanner")
    _scanner.AdvertisementData = object
    sys.modules.update({
        "bleak": _bleak, "bleak.backends": _backends,
        "bleak.backends.device": _device, "bleak.backends.scanner": _scanner,
    })

import ble_feeder  # noqa: E402
import wifi_feeder  # noqa: E402

FEEDERS = (("wifi", wifi_feeder), ("ble", ble_feeder))

# encodeSystemMessage(OperatorLocationType, ClassificationType, lat, lon,
#   AreaCount, AreaRadius, AreaCeiling, AreaFloor, CategoryEU, ClassEU,
#   OperatorAltitudeGeo, Timestamp)
SYS_LIVE_UNSET_AREA = bytes.fromhex(   # 1 (live), 0, 40.1234567, -75.4567891,
    "4201875AEA172D3506D301000000000000009F0900258B0E00")  # 1, 0, -1000, -1000, 0, 0, 231.5, 244000000
SYS_TAKEOFF_AREA_EU = bytes.fromhex(   # 0 (takeoff), 1 (EU), 52.1234567, 4.7654321,
    "42048768111FB125D702030005C008E40723000000258B0E00")  # 3, 50, 120, 10, 2, 3, -1000, 244000000
SYS_FIXED_NOLOC = bytes.fromhex(       # 2 (fixed), 0, 0, 0, 1, 0, -1000, -1000, 0, 0, -1000, 0
    "42020000000000000000010000000000000000000000000000")

# encodeLocationMessage(SpeedVertical, lat, lon, AltitudeGeo, Height, Direction, SpeedHorizontal)
LOC_HOVER       = bytes.fromhex("1222B500001E5BEA17673006D300009E09D0070000E8030000")  # 0, ..., 231, 0, 361, 0
LOC_CLIMB       = bytes.fromhex("12205A14071E5BEA17673006D30000D8090C080000E8030000")  # +3.5, ..., 260, 30, 90, 5
LOC_DESCEND     = bytes.fromhex("12225A14F81E5BEA17673006D30000C409F8070000E8030000")  # -4.0, ..., 250, 20, 270, 5
LOC_VS_UNKNOWN  = bytes.fromhex("12200A147E1E5BEA17673006D30000C409F8070000E8030000")  # 63 (unknown)
LOC_VS_MAX_DOWN = bytes.fromhex("12200A14841E5BEA17673006D30000C409F8070000E8030000")  # -62
LOC_NO_FIX      = bytes.fromhex("1222B5000000000000000000000000000000000000E8030000")  # lat/lon 0/0


class SystemMessage(unittest.TestCase):

    def test_operator_altitude_comes_from_bytes_18_19(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                d = f.parse_system_msg(SYS_LIVE_UNSET_AREA)
                self.assertEqual(d["operator_alt_geo"], 231.5)
                # Legacy name now carries the operator altitude it always claimed to.
                self.assertEqual(d["alt_takeoff_geo"], 231.5)

    def test_area_ceiling_and_floor(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                unset = f.parse_system_msg(SYS_LIVE_UNSET_AREA)
                self.assertIsNone(unset["area_ceiling_m"])   # was reported as alt_takeoff_geo = -1000.0
                self.assertIsNone(unset["area_floor_m"])
                area = f.parse_system_msg(SYS_TAKEOFF_AREA_EU)
                self.assertEqual(area["area_ceiling_m"], 120.0)
                self.assertEqual(area["area_floor_m"], 10.0)
                self.assertEqual(area["area_count"], 3)
                self.assertEqual(area["area_radius_m"], 50)
                self.assertIsNone(area["operator_alt_geo"])  # -1000 = unknown

    def test_operator_location_type_ignores_classification_bits(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                self.assertEqual(f.parse_system_msg(SYS_LIVE_UNSET_AREA)["op_location_type"], 1)
                # byte 1 = 0x04: takeoff (0) + EU classification (1 << 2).
                # The old 0x0F mask reported 4, which is not a valid type.
                self.assertEqual(f.parse_system_msg(SYS_TAKEOFF_AREA_EU)["op_location_type"], 0)
                self.assertEqual(f.parse_system_msg(SYS_FIXED_NOLOC)["op_location_type"], 2)

    def test_operator_position(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                d = f.parse_system_msg(SYS_LIVE_UNSET_AREA)
                self.assertAlmostEqual(d["operator_lat"], 40.1234567, places=7)
                self.assertAlmostEqual(d["operator_lon"], -75.4567891, places=7)
                # 0/0 is "unknown", not a pilot standing in the Gulf of Guinea.
                n = f.parse_system_msg(SYS_FIXED_NOLOC)
                self.assertIsNone(n["operator_lat"])
                self.assertIsNone(n["operator_lon"])

    def test_drone_time_unchanged(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                self.assertEqual(f.parse_system_msg(SYS_LIVE_UNSET_AREA)["drone_time"],
                                 244000000 + 1546300800)

    def test_short_message_still_decodes_what_it_has(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                d = f.parse_system_msg(SYS_LIVE_UNSET_AREA[:16])
                self.assertAlmostEqual(d["operator_lat"], 40.1234567, places=7)
                self.assertNotIn("operator_alt_geo", d)


class LocationMessage(unittest.TestCase):

    def vs(self, f, msg):
        return f.parse_location(msg)["vertical_speed"]

    def test_vertical_speed_is_signed(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                self.assertEqual(self.vs(f, LOC_HOVER), 0.0)        # was -62.0
                self.assertEqual(self.vs(f, LOC_CLIMB), 3.5)        # was -58.5
                self.assertEqual(self.vs(f, LOC_DESCEND), -4.0)     # was +62.0
                self.assertEqual(self.vs(f, LOC_VS_MAX_DOWN), -62.0)
                self.assertIsNone(self.vs(f, LOC_VS_UNKNOWN))       # 63 = unknown

    def test_decoder_helper_full_range(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                self.assertEqual(f.decode_vertical_speed(0x00), 0.0)
                self.assertEqual(f.decode_vertical_speed(0x7C), 62.0)
                self.assertIsNone(f.decode_vertical_speed(0x7E))
                self.assertEqual(f.decode_vertical_speed(0xFF), -0.5)
                self.assertEqual(f.decode_vertical_speed(0x84), -62.0)

    def test_rest_of_location_unchanged(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                d = f.parse_location(LOC_HOVER)
                self.assertAlmostEqual(d["latitude"], 40.1234718, places=7)
                self.assertAlmostEqual(d["longitude"], -75.4569113, places=7)
                self.assertEqual(d["altitude_geo"], 231.0)
                self.assertEqual(d["height_agl"], 0.0)
                self.assertEqual(d["heading"], 361)                  # 361 = unknown, per spec
                self.assertEqual(d["height_type"], "Above Takeoff")
                self.assertEqual(f.parse_location(LOC_DESCEND)["heading"], 270)

    def test_height_type_mapping(self):
        # F3411 HeightType bit (byte 1, bit 2): 0 = above takeoff, 1 = AGL.
        agl = bytearray(LOC_HOVER)
        agl[1] |= 0x04
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                self.assertEqual(f.parse_location(LOC_HOVER)["height_type"], "Above Takeoff")
                self.assertEqual(f.parse_location(bytes(agl))["height_type"], "AGL")

    def test_no_fix_position_is_dropped(self):
        for name, f in FEEDERS:
            with self.subTest(feeder=name):
                self.assertEqual(f.parse_location(LOC_NO_FIX), {})


class FeederParity(unittest.TestCase):
    """The two feeders ship separate copies of the decoders; keep them identical."""

    def test_same_output(self):
        for msg in (SYS_LIVE_UNSET_AREA, SYS_TAKEOFF_AREA_EU, SYS_FIXED_NOLOC):
            self.assertEqual(wifi_feeder.parse_system_msg(msg), ble_feeder.parse_system_msg(msg))
        for msg in (LOC_HOVER, LOC_CLIMB, LOC_DESCEND, LOC_VS_UNKNOWN, LOC_VS_MAX_DOWN, LOC_NO_FIX):
            self.assertEqual(wifi_feeder.parse_location(msg), ble_feeder.parse_location(msg))


class SnapshotTrail(unittest.TestCase):
    """Spooled history from older releases still holds 0/0 pre-lock fixes."""

    def test_zero_zero_is_not_a_trail_point(self):
        try:
            import web_ui
        except Exception as e:  # flask missing on this machine
            self.skipTest(f"web_ui not importable: {e}")
        store = web_ui.DetectionStore()
        now = time.time()
        mac = "8c:1e:d9:00:00:01"
        store.add({"t": now - 2, "mac": mac, "type": "Location/Vector", "lat": 0.0, "lon": 0.0, "alt": -1000.0})
        store.add({"t": now - 1, "mac": mac, "type": "Location/Vector", "lat": 40.1234641, "lon": -75.4568655, "alt": 226.0})
        snap = store.snapshot()
        trail = snap["macs"][0]["trail"]
        self.assertEqual(trail, [[40.1234641, -75.4568655, 226.0]])


if __name__ == "__main__":
    unittest.main()
