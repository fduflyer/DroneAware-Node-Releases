-- DroneAware Remote ID observations table
-- Run once on the flighttracker database:
--   psql -U fduflyer -d flighttracker -f rid_migration.sql

CREATE TABLE IF NOT EXISTS rid_observations (
    id           BIGSERIAL PRIMARY KEY,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    node_id      TEXT NOT NULL,
    radio        TEXT NOT NULL,          -- 'ble', 'wifi_beacon', 'wifi_nan'
    mac          TEXT NOT NULL,
    rssi         INTEGER,
    obs_time     TIMESTAMPTZ,            -- feeder-reported timestamp
    msg_type     TEXT,                   -- 'Basic ID', 'Location/Vector', etc.
    uas_id       TEXT,                   -- from Basic ID
    ua_type      TEXT,                   -- from Basic ID
    operator_id  TEXT,                   -- from Operator ID
    lat          DOUBLE PRECISION,       -- from Location/Vector
    lon          DOUBLE PRECISION,       -- from Location/Vector
    alt_geo      DOUBLE PRECISION,       -- geodetic altitude (m)
    ground_speed DOUBLE PRECISION,       -- m/s
    heading      DOUBLE PRECISION,       -- degrees
    payload_hex  TEXT,                   -- raw message hex
    decoded      JSONB                   -- full decoded object
);

CREATE INDEX IF NOT EXISTS rid_obs_received_at_idx  ON rid_observations(received_at DESC);
CREATE INDEX IF NOT EXISTS rid_obs_mac_time_idx     ON rid_observations(mac, obs_time DESC);
CREATE INDEX IF NOT EXISTS rid_obs_uas_id_idx       ON rid_observations(uas_id) WHERE uas_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS rid_obs_msg_type_idx     ON rid_observations(msg_type);

-- Quarantined Remote ID observations that should not appear on the normal map
-- but are useful for detecting spoofing or bad feeder behavior.
CREATE TABLE IF NOT EXISTS rid_suspicious_observations (
    id             BIGSERIAL PRIMARY KEY,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    node_id        TEXT NOT NULL,          -- node_id claimed by the batch
    event_node_id  TEXT,                   -- node_id claimed by the event
    radio          TEXT,
    mac            TEXT,
    rssi           INTEGER,
    obs_time       TIMESTAMPTZ,
    reason         TEXT NOT NULL,          -- e.g. drone_location_too_far
    message        TEXT,
    distance_m     DOUBLE PRECISION,
    max_distance_m DOUBLE PRECISION,
    feeder_lat     DOUBLE PRECISION,       -- trusted server-side feeder location
    feeder_lon     DOUBLE PRECISION,
    drone_lat      DOUBLE PRECISION,       -- decoded Remote ID location, if any
    drone_lon      DOUBLE PRECISION,
    payload_hex    TEXT,
    decoded        JSONB,
    event          JSONB                   -- raw feeder-submitted event
);

CREATE INDEX IF NOT EXISTS rid_suspicious_received_at_idx ON rid_suspicious_observations(received_at DESC);
CREATE INDEX IF NOT EXISTS rid_suspicious_node_idx        ON rid_suspicious_observations(node_id, received_at DESC);
CREATE INDEX IF NOT EXISTS rid_suspicious_mac_idx         ON rid_suspicious_observations(mac, received_at DESC);
CREATE INDEX IF NOT EXISTS rid_suspicious_reason_idx      ON rid_suspicious_observations(reason);
