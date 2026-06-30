# Maintainer guide — regenerating `web_static/world-tiles.mbtiles`

> **This is a maintainer task, not an operator task.** Operators never
> touch tiles. The MBTiles file is committed to the repo, bundled into
> the `web_ui` binary at CI build time, and shipped to every operator
> as part of `sudo droneaware update`. Operators see the offline basemap
> automatically — no script, no setup, no extra step.
>
> This doc exists so the next time the world-tile bundle needs refreshing
> (probably once a year or once per major release), you (or a future
> maintainer) know exactly how to regenerate the file.

## When to regenerate

Almost never. Zoom 0-6 basemap data — country boundaries, state outlines,
coastlines, major cities — barely moves over years. Reasonable cadences:

- **Once a year**, defensive refresh
- **Before a v2.0-class release**, when "everything's been refreshed" framing matters
- **Never**, also defensible — the world's coastlines aren't going anywhere

## How to regenerate

On your laptop (any Python 3 — Mac is fine, no Pi required), from the
project root:

```bash
python3 tools/generate-world-tiles.py
```

This downloads ~5,461 tiles from CartoDB Dark Matter at 2 tiles/sec
(default — well under any fair-use threshold) and packages them as
`web_static/world-tiles.mbtiles`. **Takes about 45 minutes.** Leave it
in a terminal.

When it finishes, commit and push:

```bash
git add web_static/world-tiles.mbtiles
git commit -m "v1.4.x: refresh world-tile bundle"
git push releases v1.4.x-dev
```

CI's existing `build.sh --add-data web_static:web_static` step bundles
the file into the `web_ui` binary automatically. No workflow changes
needed. After the next release, every operator running `droneaware update`
gets the refreshed basemap.

## What the operator actually sees (just so you know what shipping this gives them)

| Scenario | Without bundle (v1.4.4 and earlier) | With bundle (v1.4.5+) |
|---|---|---|
| Online | CartoDB Dark Matter | CartoDB Dark Matter (unchanged) |
| Offline / browser can't reach CartoDB | Blank Leaflet background, drone markers float in space | Bundled world-overview tiles — country boundaries, state outlines, major cities; drone markers placed correctly; max zoom 6 (tiles get blurry above that but stay positioned) |
| Online → offline mid-session | Map empties as cached tiles expire | First failed CartoDB tile triggers auto-swap to bundle; map stays usable |
| Truly air-gapped install | Same as offline (blank) | Recognizable world map immediately, no setup |

## Script options

```bash
python3 tools/generate-world-tiles.py [options]
```

| Flag | Default | Notes |
|---|---|---|
| `--max-zoom` | `6` | Higher = more detail but exponentially more tiles. Zoom 7 = ~22K tiles (~50 MB), Zoom 0-5 = ~1.4K tiles (~5 MB) |
| `--rate` | `2.0` | Tiles per second. Don't exceed ~10/sec — CartoDB will rate-limit and you'll get incomplete tiles |
| `--out` | `web_static/world-tiles.mbtiles` | Output path |
| `--force` | off | Overwrite existing file instead of erroring |

## Attribution

The output combines:

- **OpenStreetMap data** — licensed under [ODbL](https://www.openstreetmap.org/copyright), explicitly allows redistribution
- **CartoDB Dark Matter style** — CartoDB's open style sheets (BSD), applied at render time on their tile servers

The Web UI surfaces both attributions in the bottom-right of the map at
all times. Online mode displays "© OpenStreetMap © CARTO"; offline mode
appends "(offline bundle)" to make the source explicit. Satisfies both
ODbL and CartoDB's attribution requirements.

A one-time low-rate archival download of ~5,461 zoom-0-6 tiles for an
open-source project's offline fallback is consistent with CartoDB's
stated tile fair-use; the script identifies itself in the User-Agent and
defaults to a rate well below their throttling threshold.

## Verifying the output before committing

After generation:

```bash
# File size — should be 10-20 MB for zoom 0-6
ls -lh web_static/world-tiles.mbtiles

# Tile count by zoom level — should be 1, 4, 16, 64, 256, 1024, 4096
sqlite3 web_static/world-tiles.mbtiles \
    "SELECT zoom_level, COUNT(*) FROM tiles GROUP BY zoom_level"

# Metadata sanity check
sqlite3 web_static/world-tiles.mbtiles "SELECT * FROM metadata"
```

If counts look short (e.g., 4090 instead of 4096 at zoom 6), some tiles
failed during download. Re-run with `--force` to start fresh, or accept
the gaps if they're sparse — the Web UI's tile route returns 404 for
missing tiles and the map degrades gracefully (small dark squares where
the missing tile would be).

## Local end-to-end test before shipping

After the file is committed and you've built `web_ui` locally, test the
fallback path without actually disconnecting from the internet:

1. `sudo systemctl restart droneaware-web` (so the new binary loads)
2. Open the Web UI in a browser
3. Dev Tools → Network tab → check "Offline" (Chrome) or "Throttling: Offline" (Firefox)
4. Refresh the page

CartoDB requests should fail, the page should auto-swap to local tiles
within 1-2 seconds, map should render with the bundled basemap. Uncheck
"Offline" — CartoDB tiles return on the next zoom or pan event.
