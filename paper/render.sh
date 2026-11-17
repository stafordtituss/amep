#!/bin/sh
# Render the preprint HTML to PDF with headless Chrome. Run from the repository root: sh paper/render.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$DIR/amep-preprint.pdf" "file://$DIR/amep-preprint.html" 2>/dev/null
ls -la "$DIR/amep-preprint.pdf"
