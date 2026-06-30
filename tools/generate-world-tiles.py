#!/usr/bin/env python3
"""
Generate web_static/world-tiles.mbtiles for the Web UI's offline basemap.

The Web UI bundles this MBTiles file inside the web_ui PyInstaller binary
via build.sh's --add-data. At runtime, when the browser can't reach CartoDB
(operator offline, firewall, captive portal), Leaflet falls back to a local
/tiles/{z}/{x}/{y}.png route served by web_ui that reads from this file.
Without it, an offline operator sees drone markers floating on a blank
Leaflet background — the whole point of v1.4.5 is to give them a recognizable
world overview to plot against.

This script downloads CartoDB Dark Matter raster tiles at zoom 0-6
(~5,461 tiles, ~15 MB) and packages them into MBTiles SQLite format.

This is a MAINTAINER task — operators never run this script. The output
file (web_static/world-tiles.mbtiles) is committed to the repo just like
web_static/leaflet.js. CI's existing --add-data web_static:web_static
bundles it into the binary; every operator gets the basemap automatically
on `sudo droneaware update`.

Run once per release cycle (basemaps change slowly — OSM data updates are
the only real driver, and at zoom 0-6 those changes are imperceptible).
See docs/world-tiles-generation.md for the maintainer workflow.

Usage (from project root):

    python3 tools/generate-world-tiles.py

Options:

    --max-zoom 6          Maximum zoom level to download (default 6)
    --rate 2.0            Tiles per second (default 2 — well under any
                          fair-use threshold; takes ~45 min for zoom 0-6)
    --out PATH            Output path (default web_static/world-tiles.mbtiles)
    --force               Overwrite existing output

Attribution:
    Rendered output combines OpenStreetMap data (ODbL) with CartoDB's
    Dark Matter style. The Web UI surfaces both attributions in the
    bottom-right of the map at all times, both online (live CartoDB)
    and offline (bundled tiles — attribution text appended with
    "(offline bundle)"). A single low-rate archival download for a
    node's offline fallback is well within CartoDB's stated tile
    fair-use; we identify ourselves clearly in the User-Agent.
"""
import argparse
import os
import random
import sqlite3
import sys
import time
import urllib.error
import urllib.request


CARTODB_URL = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png"
SUBDOMAINS = ["a", "b", "c", "d"]
USER_AGENT = (
    "DroneAware-Node/world-tiles-generator "
    "(+https://github.com/fduflyer/DroneAware-Node-Releases)"
)


def init_mbtiles(path, max_zoom):
    """Create the MBTiles schema and write the standard metadata rows."""
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS tiles (
            zoom_level  INTEGER,
            tile_column INTEGER,
            tile_row    INTEGER,
            tile_data   BLOB,
            PRIMARY KEY (zoom_level, tile_column, tile_row)
        );
        """
    )
    metadata = [
        ("name",        "DroneAware World Overview"),
        ("type",        "baselayer"),
        ("format",      "png"),
        ("minzoom",     "0"),
        ("maxzoom",     str(max_zoom)),
        ("bounds",      "-180.0,-85.0511,180.0,85.0511"),
        ("attribution", "&copy; OpenStreetMap &copy; CARTO"),
        ("description", "Dark Matter style world overview for DroneAware Local Web UI offline fallback"),
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO metadata (name, value) VALUES (?, ?)",
        metadata,
    )
    conn.commit()
    return conn


def download_tile(z, x, y, timeout=30):
    """Fetch one tile from CartoDB. Returns the PNG bytes."""
    sub = random.choice(SUBDOMAINS)
    url = CARTODB_URL.format(s=sub, z=z, x=x, y=y)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def main():
    p = argparse.ArgumentParser(
        description="Build web_static/world-tiles.mbtiles for the Web UI offline basemap",
    )
    p.add_argument("--max-zoom", type=int, default=6,
                   help="Maximum zoom level to download (default 6)")
    p.add_argument("--rate", type=float, default=2.0,
                   help="Tiles per second (default 2.0)")
    p.add_argument("--out", default="web_static/world-tiles.mbtiles",
                   help="Output MBTiles path (default web_static/world-tiles.mbtiles)")
    p.add_argument("--force", action="store_true",
                   help="Overwrite existing output file")
    args = p.parse_args()

    if os.path.exists(args.out):
        if not args.force:
            print(f"ERROR: {args.out} already exists. Pass --force to overwrite.",
                  file=sys.stderr)
            sys.exit(1)
        os.remove(args.out)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    total = sum(4 ** z for z in range(args.max_zoom + 1))
    sleep_time = 1.0 / args.rate
    est_minutes = total / args.rate / 60

    print(f"Output:   {args.out}")
    print(f"Zoom:     0-{args.max_zoom}")
    print(f"Tiles:    {total} total")
    print(f"Rate:     {args.rate} tiles/sec")
    print(f"ETA:      {est_minutes:.0f} minutes")
    print(f"Source:   {CARTODB_URL}")
    print()

    conn = init_mbtiles(args.out, args.max_zoom)
    done = 0
    failed = 0
    started = time.time()

    for z in range(args.max_zoom + 1):
        max_xy = 2 ** z
        for x in range(max_xy):
            for y in range(max_xy):
                try:
                    data = download_tile(z, x, y)
                    # MBTiles uses TMS row indexing (y-axis flipped);
                    # CartoDB serves XYZ. Convert before storing so the
                    # web_ui /tiles route can do a direct lookup.
                    tms_y = (1 << z) - 1 - y
                    conn.execute(
                        "INSERT INTO tiles VALUES (?, ?, ?, ?)",
                        (z, x, tms_y, data),
                    )
                except urllib.error.HTTPError as e:
                    failed += 1
                    print(f"  warn: z{z}/x{x}/y{y} → HTTP {e.code}", file=sys.stderr)
                except Exception as e:
                    failed += 1
                    print(f"  warn: z{z}/x{x}/y{y} → {e}", file=sys.stderr)

                done += 1
                if done % 50 == 0:
                    conn.commit()
                    elapsed = time.time() - started
                    pct = done / total * 100
                    eta = (total - done) * sleep_time / 60
                    print(f"  {done}/{total} ({pct:5.1f}%)  "
                          f"elapsed {elapsed/60:.1f}m  eta {eta:.1f}m  "
                          f"failed {failed}")

                time.sleep(sleep_time)

    conn.commit()
    conn.execute("VACUUM")
    conn.close()

    size_mb = os.path.getsize(args.out) / 1e6
    elapsed_min = (time.time() - started) / 60

    print()
    print(f"Done. {args.out} = {size_mb:.1f} MB")
    print(f"Downloaded {done - failed} tiles in {elapsed_min:.1f} minutes "
          f"({failed} failed)")
    print()
    print("Next steps (maintainer):")
    print(f"  git add {args.out}")
    print(f"  git commit -m 'v1.4.x: refresh world-tile bundle'")
    print(f"  # CI bundles it into web_ui via build.sh --add-data on next release")


if __name__ == "__main__":
    main()
