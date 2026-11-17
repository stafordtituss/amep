#!/bin/sh
# Render the preprint HTML to PDF (headless Chrome) and DOCX (macOS textutil).
# Run from anywhere: sh paper/render.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$DIR/amep-preprint.pdf" "file://$DIR/amep-preprint.html" 2>/dev/null
textutil -convert docx -format html "$DIR/amep-preprint.html" -output "$DIR/amep-preprint.docx"
ls -la "$DIR/amep-preprint.pdf" "$DIR/amep-preprint.docx"
