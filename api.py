from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import psycopg2
from psycopg2 import sql
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import logging
import math
import struct
import json
import os

app = FastAPI()
log = logging.getLogger("droneaware.api")

# CORS CONFIG
origins = [
    "https://flight.droneaware.io",
    "https://www.flight.droneaware.io",
    "https://droneaware.io",
    "https://www.droneaware.io",
    "http://localhost:5180",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# DATABASE CONFIG — set DATABASE_URL in the server environment, never in source
DB_CONN = os.environ["DATABASE_URL"]
RID_MAX_FEEDER_DISTANCE_M = float(os.environ.get("RID_MAX_FEEDER_DISTANCE_M", "64373"))
NODE_LOCATION_TABLE = os.environ.get("RID_NODE_LOCATION_TABLE", "nodes")
NODE_LOCATION_ID_COLUMN = os.environ.get("RID_NODE_LOCATION_ID_COLUMN", "node_id")
NODE_LOCATION_LAT_COLUMN = os.environ.get("RID_NODE_LOCATION_LAT_COLUMN", "lat")
NODE_LOCATION_LON_COLUMN = os.environ.get("RID_NODE_LOCATION_LON_COLUMN", "lon")


def _valid_lat_lon(lat, lon) -> bool:
    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        return False
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distance between two WGS84 coordinates in meters."""
    radius_m = 6371000.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(d_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
    )
    return radius_m * 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


def _lookup_node_location(cur, node_id: str) -> tuple[float, float] | None:
    """Return the trusted server-side feeder location for a node."""
    query = sql.SQL("SELECT {lat}, {lon} FROM {table} WHERE {node_id} = %s LIMIT 1").format(
        lat=sql.Identifier(NODE_LOCATION_LAT_COLUMN),
        lon=sql.Identifier(NODE_LOCATION_LON_COLUMN),
        table=sql.Identifier(NODE_LOCATION_TABLE),
        node_id=sql.Identifier(NODE_LOCATION_ID_COLUMN),
    )
    cur.execute(query, (node_id,))
    row = cur.fetchone()
    if not row:
        return None

    lat, lon = row[0], row[1]
    if not _valid_lat_lon(lat, lon):
        return None
    return float(lat), float(lon)


def _decoded_locations(decoded: dict | None) -> list[tuple[object, object]]:
    """Extract all Location/Vector coordinates from a decoded message or pack."""
    if not decoded:
        return []

    if decoded.get("message_type") == "Message Pack":
        locations = []
        for sub in decoded.get("messages", []):
            locations.extend(_decoded_locations(sub))
        return locations

    if decoded.get("message_type") != "Location/Vector":
        return []

    return [(decoded.get("latitude"), decoded.get("longitude"))]


def _proximity_anomaly(
    decoded: dict | None,
    feeder_location: tuple[float, float],
) -> dict | None:
    """Return anomaly details when decoded drone coordinates are implausible."""
    feeder_lat, feeder_lon = feeder_location

    for lat, lon in _decoded_locations(decoded):
        if not _valid_lat_lon(lat, lon):
            return {
                "reason": "invalid_drone_location",
                "message": f"invalid drone coordinates lat={lat} lon={lon}",
                "drone_lat": lat,
                "drone_lon": lon,
            }

        distance_m = _haversine_m(feeder_lat, feeder_lon, float(lat), float(lon))
        if distance_m > RID_MAX_FEEDER_DISTANCE_M:
            return {
                "reason": "drone_location_too_far",
                "message": (
                    f"drone location {distance_m:.0f}m from feeder "
                    f"(limit {RID_MAX_FEEDER_DISTANCE_M:.0f}m)"
                ),
                "distance_m": distance_m,
                "drone_lat": float(lat),
                "drone_lon": float(lon),
            }

    return None


# ---------------------------------------------------------------------------
# ODID Decoder  (runs server-side — nodes send raw rid_payload_hex)
# ---------------------------------------------------------------------------

MSG_TYPE = {
    0x0: "Basic ID",
    0x1: "Location/Vector",
    0x2: "Authentication",
    0x3: "Self ID",
    0x4: "System",
    0x5: "Operator ID",
    0xF: "Message Pack",
}

ID_TYPE = {
    0: "None",
    1: "Serial Number (ANSI/CTA-2063-A)",
    2: "CAA Assigned",
    3: "UTM Assigned",
    4: "Specific Session ID",
}

UA_TYPE = {
    0: "None",
    1: "Aeroplane",
    2: "Helicopter/Multirotor",
    3: "Gyroplane",
    4: "Hybrid Lift",
    5: "Ornithopter",
    6: "Glider",
    7: "Kite",
    8: "Free Balloon",
    9: "Captive Balloon",
    10: "Airship",
    11: "Free Fall/Parachute",
    12: "Rocket",
    13: "Tethered Powered Aircraft",
    14: "Ground Obstacle",
    255: "Other",
}


def _parse_basic_id(d: bytes) -> dict:
    if len(d) < 25:
        return {}
    return {
        "id_type": ID_TYPE.get((d[1] >> 4) & 0x0F, "Unknown"),
        "ua_type": UA_TYPE.get(d[1] & 0x0F, "Unknown"),
        "uas_id":  d[2:22].rstrip(b"\x00").decode("ascii", errors="replace"),
    }


def _parse_location(d: bytes) -> dict:
    if len(d) < 25:
        return {}
    return {
        "latitude":      round(struct.unpack_from("<i", d, 2)[0] * 1e-7, 7),
        "longitude":     round(struct.unpack_from("<i", d, 6)[0] * 1e-7, 7),
        "altitude_baro": round(struct.unpack_from("<H", d, 10)[0] * 0.5 - 1000.0, 1),
        "altitude_geo":  round(struct.unpack_from("<H", d, 12)[0] * 0.5 - 1000.0, 1),
        "height_agl":    round(struct.unpack_from("<H", d, 14)[0] * 0.5 - 1000.0, 1),
        "ground_speed":  round(d[16] * (0.75 if d[1] & 0x01 else 0.25), 2),
        "vert_speed":    round(d[17] * 0.5 - 62.0, 2),
        "heading":       round(struct.unpack_from("<H", d, 18)[0] * 0.01, 1),
        "ts_past_hour":  round(struct.unpack_from("<H", d, 20)[0] * 0.1, 1),
    }


def _parse_system(d: bytes) -> dict:
    if len(d) < 16:
        return {}
    return {
        "operator_lat":    round(struct.unpack_from("<i", d, 4)[0] * 1e-7, 7),
        "operator_lon":    round(struct.unpack_from("<i", d, 8)[0] * 1e-7, 7),
        "area_count":      d[12],
        "area_radius_m":   d[13] * 10,
        "alt_takeoff_geo": round(struct.unpack_from("<H", d, 14)[0] * 0.5 - 1000.0, 1),
    }


def _parse_operator_id(d: bytes) -> dict:
    if len(d) < 22:
        return {}
    return {
        "operator_id_type": d[1],
        "operator_id":      d[2:22].rstrip(b"\x00").decode("ascii", errors="replace"),
    }


def decode_rid_message(raw: bytes) -> dict | None:
    """Decode a 25-byte ODID message. Returns structured dict or None."""
    if len(raw) < 2:
        return None
    msg_type  = (raw[0] >> 4) & 0x0F
    type_name = MSG_TYPE.get(msg_type, f"Unknown(0x{msg_type:X})")
    result    = {"message_type": type_name}

    if msg_type == 0x0:
        result.update(_parse_basic_id(raw))
    elif msg_type == 0x1:
        result.update(_parse_location(raw))
    elif msg_type == 0x4:
        result.update(_parse_system(raw))
    elif msg_type == 0x5:
        result.update(_parse_operator_id(raw))
    elif msg_type == 0xF:
        msg_size  = raw[1]
        msg_count = raw[2]
        subs = []
        for i in range(msg_count):
            offset = 3 + i * msg_size
            if offset + msg_size <= len(raw):
                sub = decode_rid_message(raw[offset: offset + msg_size])
                if sub:
                    subs.append(sub)
        result["messages"] = subs

    return result


# ---------------------------------------------------------------------------
# Existing manned-aviation endpoint (unchanged)
# ---------------------------------------------------------------------------

@app.get("/api/search")
def search_flights(lat: float, lon: float, time: str):
    """
    Search for flights within ~40 miles of (lat, lon) around the given time.
    Returns up to the last 2 points per aircraft (icao24).
    """
    try:
        try:
            query_time = datetime.fromisoformat(time)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail='Invalid time format. Expected ISO 8601 like "2025-12-01T14:23:00".',
            )

        start_window = query_time - timedelta(minutes=2)
        end_window   = query_time + timedelta(minutes=2)

        conn = psycopg2.connect(DB_CONN)
        cur  = conn.cursor(cursor_factory=RealDictCursor)

        sql = """
        WITH ranked AS (
            SELECT
                ft.icao24, ft.callsign, ft.lat, ft.lon, ft.alt,
                ft.velocity, ft.heading, ft.category,
                EXTRACT(EPOCH FROM ft.time) AS timestamp,
                m.n_number, m.manufacturer, m.model, m.aircraft_type,
                m.aircraft_category, m.engine_type, m.weight_class, m.seat_count,
                row_number() OVER (
                    PARTITION BY ft.icao24 ORDER BY ft.time DESC
                ) AS rn
            FROM flight_tracks ft
            LEFT JOIN icao24_registry_map m ON m.icao24 = UPPER(ft.icao24)
            WHERE ft.time BETWEEN %s AND %s
              AND ST_DWithin(
                  ST_SetSRID(ST_MakePoint(ft.lon, ft.lat), 4326)::geography,
                  ST_SetSRID(ST_MakePoint(%s, %s), 4326)::geography,
                  64373
              )
        )
        SELECT icao24, callsign, lat, lon, alt, velocity, heading, category,
               timestamp, n_number, manufacturer, model, aircraft_type,
               aircraft_category, engine_type, weight_class, seat_count
        FROM ranked WHERE rn <= 2
        ORDER BY icao24, timestamp;
        """

        cur.execute(sql, (start_window, end_window, lon, lat))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        features = []
        for row in rows:
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [row["lon"], row["lat"]]},
                "properties": {
                    "icao24": row["icao24"], "callsign": row["callsign"],
                    "alt": row["alt"], "heading": row["heading"],
                    "velocity": row["velocity"], "category": row["category"],
                    "time": row["timestamp"],
                    "registry": {
                        "n_number": row["n_number"], "manufacturer": row["manufacturer"],
                        "model": row["model"], "aircraft_type": row["aircraft_type"],
                        "aircraft_category": row["aircraft_category"],
                        "engine_type": row["engine_type"],
                        "weight_class": row["weight_class"], "seat_count": row["seat_count"],
                    },
                },
            })

        print(f"Search at {lat},{lon} for {time} — {len(features)} points, "
              f"{len(set(r['icao24'] for r in rows))} aircraft.")

        return {"type": "FeatureCollection", "features": features}

    except HTTPException:
        raise
    except Exception as e:
        print(f"API Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Remote ID ingest — accepts raw payloads from feeder nodes, decodes server-side
# ---------------------------------------------------------------------------

class RIDEvent(BaseModel):
    node_id:              str
    observed_at:          str           # ISO 8601 UTC
    observed_monotonic:   float
    radio:                str           # "ble" | "wifi_nan" | "wifi_beacon"
    source_mac:           str
    source_name:          Optional[str] = None
    rssi:                 Optional[int] = None
    tx_power:             Optional[int] = None
    service_uuid:         str
    service_data_hex:     str
    service_data_len:     int
    rid_payload_hex:      str           # 25-byte ODID message, hex
    rid_payload_strategy: str
    adapter:              str


class RIDBatch(BaseModel):
    node_id:     str
    received_at: str                    # ISO 8601 UTC batch assembly time
    count:       int
    events:      List[RIDEvent]


def _insert_rid_row(cur, event: RIDEvent, decoded: dict, batch_received_at: str):
    """Insert one decoded ODID message as a row in rid_observations."""
    d        = decoded or {}
    msg_type = d.get("message_type", "Unknown")
    cur.execute(
        """
        INSERT INTO rid_observations
            (node_id, radio, mac, rssi, obs_time, msg_type,
             uas_id, ua_type, operator_id,
             lat, lon, alt_geo, ground_speed, heading,
             payload_hex, decoded)
        VALUES
            (%s, %s, %s, %s, %s::timestamptz, %s,
             %s, %s, %s,
             %s, %s, %s, %s, %s,
             %s, %s)
        """,
        (
            event.node_id,
            event.radio,
            event.source_mac,
            event.rssi,
            event.observed_at,
            msg_type,
            d.get("uas_id"),
            d.get("ua_type"),
            d.get("operator_id"),
            d.get("latitude"),
            d.get("longitude"),
            d.get("altitude_geo"),
            d.get("ground_speed"),
            d.get("heading"),
            event.rid_payload_hex,
            json.dumps(d),
        ),
    )


def _insert_suspicious_rid_event(
    cur,
    event: RIDEvent,
    batch_received_at: str,
    batch_node_id: str,
    reason: str,
    message: str,
    decoded: dict | None = None,
    feeder_location: tuple[float, float] | None = None,
    drone_lat=None,
    drone_lon=None,
    distance_m: float | None = None,
):
    """Track quarantined RID events for spoofing/anomaly review."""
    feeder_lat = feeder_location[0] if feeder_location else None
    feeder_lon = feeder_location[1] if feeder_location else None
    cur.execute(
        """
        INSERT INTO rid_suspicious_observations
            (received_at, node_id, event_node_id, radio, mac, rssi, obs_time,
             reason, message, distance_m, max_distance_m,
             feeder_lat, feeder_lon, drone_lat, drone_lon,
             payload_hex, decoded, event)
        VALUES
            (%s::timestamptz, %s, %s, %s, %s, %s, %s::timestamptz,
             %s, %s, %s, %s,
             %s, %s, %s, %s,
             %s, %s, %s)
        """,
        (
            batch_received_at,
            batch_node_id,
            event.node_id,
            event.radio,
            event.source_mac,
            event.rssi,
            event.observed_at,
            reason,
            message,
            distance_m,
            RID_MAX_FEEDER_DISTANCE_M,
            feeder_lat,
            feeder_lon,
            drone_lat,
            drone_lon,
            event.rid_payload_hex,
            json.dumps(decoded) if decoded is not None else None,
            json.dumps(event.dict()),
        ),
    )


@app.post("/api/ingest")
def ingest_rid(batch: RIDBatch):
    """
    Accept a batch of raw Remote ID observations from a feeder node.
    Decodes each rid_payload_hex server-side and stores the results.
    Message Packs are unpacked so each sub-message is its own row. Implausible
    detections are quarantined for spoofing analysis instead of being mapped.
    """
    if not batch.events:
        return {"accepted": 0, "suspicious": 0}

    conn = None
    cur = None
    try:
        conn = psycopg2.connect(DB_CONN)
        cur  = conn.cursor()
        accepted = 0
        suspicious = 0

        feeder_location = _lookup_node_location(cur, batch.node_id)
        if feeder_location is None:
            for event in batch.events:
                _insert_suspicious_rid_event(
                    cur,
                    event,
                    batch.received_at,
                    batch.node_id,
                    "node_location_unavailable",
                    "trusted feeder location unavailable for proximity validation",
                )
                suspicious += 1
            conn.commit()
            print(f"Ingest: 0 rows from node {batch.node_id} "
                  f"({batch.count} events in batch, {suspicious} suspicious)")
            return {"accepted": 0, "suspicious": suspicious}

        for event in batch.events:
            if event.node_id != batch.node_id:
                _insert_suspicious_rid_event(
                    cur,
                    event,
                    batch.received_at,
                    batch.node_id,
                    "node_id_mismatch",
                    f"batch node_id {batch.node_id} differs from event node_id {event.node_id}",
                    feeder_location=feeder_location,
                )
                suspicious += 1
                log.warning(
                    "Quarantined RID event with mismatched node_id: batch=%s event=%s",
                    batch.node_id,
                    event.node_id,
                )
                continue

            try:
                raw = bytes.fromhex(event.rid_payload_hex)
            except ValueError:
                _insert_suspicious_rid_event(
                    cur,
                    event,
                    batch.received_at,
                    batch.node_id,
                    "bad_payload_hex",
                    "rid_payload_hex is not valid hex",
                    feeder_location=feeder_location,
                )
                suspicious += 1
                log.warning("Bad RID hex from %s: %s", event.source_mac, event.rid_payload_hex)
                continue

            decoded = decode_rid_message(raw)
            if decoded is None:
                _insert_suspicious_rid_event(
                    cur,
                    event,
                    batch.received_at,
                    batch.node_id,
                    "undecodable_payload",
                    "RID payload could not be decoded",
                    feeder_location=feeder_location,
                )
                suspicious += 1
                continue

            anomaly = _proximity_anomaly(decoded, feeder_location)
            if anomaly:
                _insert_suspicious_rid_event(
                    cur,
                    event,
                    batch.received_at,
                    batch.node_id,
                    anomaly["reason"],
                    anomaly["message"],
                    decoded=decoded,
                    feeder_location=feeder_location,
                    drone_lat=anomaly.get("drone_lat"),
                    drone_lon=anomaly.get("drone_lon"),
                    distance_m=anomaly.get("distance_m"),
                )
                suspicious += 1
                log.warning(
                    "Quarantined RID event from node %s mac %s: %s",
                    batch.node_id,
                    event.source_mac,
                    anomaly["message"],
                )
                continue

            if decoded.get("message_type") == "Message Pack":
                for sub in decoded.get("messages", []):
                    _insert_rid_row(cur, event, sub, batch.received_at)
                    accepted += 1
            else:
                _insert_rid_row(cur, event, decoded, batch.received_at)
                accepted += 1

        conn.commit()

        print(f"Ingest: {accepted} rows from node {batch.node_id} "
              f"({batch.count} events in batch, {suspicious} suspicious)")
        return {"accepted": accepted, "suspicious": suspicious}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Ingest error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if cur is not None:
            cur.close()
        if conn is not None:
            conn.close()


# ---------------------------------------------------------------------------
# Remote ID search  (mirrors /api/search — returns GeoJSON FeatureCollection)
# ---------------------------------------------------------------------------

@app.get("/api/drone-search")
def search_drones(lat: float, lon: float, time: str):
    """
    Return the most recent drone position per MAC within ~40 miles of
    (lat, lon) and within ±2 minutes of the given time.
    """
    try:
        try:
            query_time = datetime.fromisoformat(time)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail='Invalid time format. Expected ISO 8601 like "2025-12-01T14:23:00".',
            )

        start_window = query_time - timedelta(minutes=2)
        end_window   = query_time + timedelta(minutes=2)

        conn = psycopg2.connect(DB_CONN)
        cur  = conn.cursor(cursor_factory=RealDictCursor)

        sql = """
        WITH latest_location AS (
            SELECT DISTINCT ON (mac)
                node_id, radio, mac, rssi,
                lat, lon, alt_geo, ground_speed, heading,
                EXTRACT(EPOCH FROM obs_time) AS timestamp
            FROM rid_observations
            WHERE msg_type  = 'Location/Vector'
              AND obs_time  BETWEEN %s AND %s
              AND lat IS NOT NULL AND lon IS NOT NULL
              AND ST_DWithin(
                  ST_SetSRID(ST_MakePoint(lon, lat), 4326)::geography,
                  ST_SetSRID(ST_MakePoint(%s, %s),  4326)::geography,
                  64373
              )
            ORDER BY mac, obs_time DESC
        ),
        latest_basic_id AS (
            SELECT DISTINCT ON (mac)
                mac, uas_id, ua_type
            FROM rid_observations
            WHERE msg_type    = 'Basic ID'
              AND received_at > NOW() - INTERVAL '10 minutes'
            ORDER BY mac, received_at DESC
        ),
        latest_operator AS (
            SELECT DISTINCT ON (mac)
                mac, operator_id
            FROM rid_observations
            WHERE msg_type    = 'Operator ID'
              AND received_at > NOW() - INTERVAL '10 minutes'
            ORDER BY mac, received_at DESC
        )
        SELECT ll.mac, ll.node_id, ll.radio, ll.rssi,
               ll.lat, ll.lon, ll.alt_geo, ll.ground_speed, ll.heading, ll.timestamp,
               bi.uas_id, bi.ua_type, op.operator_id
        FROM latest_location ll
        LEFT JOIN latest_basic_id bi ON bi.mac = ll.mac
        LEFT JOIN latest_operator op ON op.mac = ll.mac;
        """

        cur.execute(sql, (start_window, end_window, lon, lat))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        features = []
        for row in rows:
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [row["lon"], row["lat"]]},
                "properties": {
                    "mac":          row["mac"],
                    "uas_id":       row["uas_id"],
                    "ua_type":      row["ua_type"],
                    "operator_id":  row["operator_id"],
                    "radio":        row["radio"],
                    "node_id":      row["node_id"],
                    "rssi":         row["rssi"],
                    "alt_geo":      row["alt_geo"],
                    "ground_speed": row["ground_speed"],
                    "heading":      row["heading"],
                    "time":         row["timestamp"],
                },
            })

        print(f"Drone search at {lat},{lon} for {time} — {len(features)} drone(s).")
        return {"type": "FeatureCollection", "features": features}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Drone search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
