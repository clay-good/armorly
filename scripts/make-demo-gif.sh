#!/bin/bash
# Convert the @demo Playwright recording into a GIF for the README hero.
#
# Pipeline:
#   1. Pick the largest webm Playwright wrote to test-results/demo/.
#   2. Generate a palette for the chosen frame range (gives much smaller GIFs
#      than ffmpeg's default global palette).
#   3. Encode at 12fps, 960px wide. ChatGPT-mock has very little motion, so
#      12fps stays smooth and keeps the file size down.
#   4. Run gifsicle -O3 to squeeze out final bytes.
#
# Target: <3 MB, plays in-line on github.com without preload-on-click.
set -euo pipefail

cd "$(dirname "$0")/.."

DEMO_DIR="test-results/demo"
OUT="docs/demo.gif"

if [ ! -d "$DEMO_DIR" ] || ! ls "$DEMO_DIR"/*.webm >/dev/null 2>&1; then
  echo "❌ No webm in $DEMO_DIR. Run \`npm run demo\` first."
  exit 1
fi

# Pick the largest webm — Playwright sometimes writes a stub video for the
# first new page; the real walkthrough is in the bigger one.
SRC=$(ls -S "$DEMO_DIR"/*.webm | head -1)
echo "📹 Source: $SRC"

# Probe duration so we can trim a couple of frames off the start if needed.
DURATION=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "$SRC")
echo "⏱  Duration: ${DURATION}s"

# Playwright starts recording the moment the page is created — there are
# ~0.5s of blank leading frames before navigation paints. Drop them with -ss.
SKIP=0.5

mkdir -p docs
PALETTE=$(mktemp -t armorly-palette).png

ffmpeg -y -loglevel error -ss "$SKIP" -i "$SRC" \
  -vf "fps=12,scale=960:-1:flags=lanczos,palettegen=stats_mode=diff" "$PALETTE"

ffmpeg -y -loglevel error -ss "$SKIP" -i "$SRC" -i "$PALETTE" \
  -lavfi "fps=12,scale=960:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=5" \
  "$OUT"

rm -f "$PALETTE"

# Final pass: gifsicle squeezes another ~30-40% out without visible loss.
gifsicle -O3 --lossy=80 -o "$OUT" "$OUT"

SIZE=$(du -h "$OUT" | cut -f1)
echo "✅ Wrote $OUT ($SIZE)"
