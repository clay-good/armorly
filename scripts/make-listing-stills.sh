#!/bin/bash
# Extract Chrome Web Store listing stills from the @demo recording.
#
# The @demo test records at 1280x800, exactly the Chrome Web Store hero
# aspect, so the source webm can produce both the README GIF and the
# store listing screenshots without a re-record.
#
# Two stills per run:
#   docs/listing/before.png  — sponsored card visible, Armorly OFF
#                              (sampled ~1.5s in, mid-phase 1)
#   docs/listing/after.png   — sponsored card gone, Armorly ON
#                              (sampled ~5.0s in, mid-phase 2)
#
# Run `npm run demo` first to refresh the source webm.
set -euo pipefail

cd "$(dirname "$0")/.."

DEMO_DIR="test-results/demo"
OUT_DIR="docs/listing"

if [ ! -d "$DEMO_DIR" ] || ! ls "$DEMO_DIR"/*.webm >/dev/null 2>&1; then
  echo "❌ No webm in $DEMO_DIR. Run \`npm run demo\` first."
  exit 1
fi

# Pick the largest webm (Playwright sometimes writes a stub for the first
# new page; the real walkthrough is the bigger one).
SRC=$(ls -S "$DEMO_DIR"/*.webm | head -1)
echo "📹 Source: $SRC"

mkdir -p "$OUT_DIR"

# `-ss <time> -i <src>` (seek before input) is fast and frame-accurate
# enough for these stills. `-vframes 1` grabs a single frame at that
# timestamp; `-update 1` writes it as a static PNG, not an image sequence.
ffmpeg -y -loglevel error -ss 1.5 -i "$SRC" -vframes 1 -update 1 "$OUT_DIR/before.png"
ffmpeg -y -loglevel error -ss 5.0 -i "$SRC" -vframes 1 -update 1 "$OUT_DIR/after.png"

for f in before.png after.png; do
  SIZE=$(du -h "$OUT_DIR/$f" | cut -f1)
  DIM=$(ffprobe -v error -select_streams v:0 -show_entries stream=width,height \
         -of csv=p=0:s=x "$OUT_DIR/$f")
  echo "✅ $OUT_DIR/$f ($DIM, $SIZE)"
done
