#!/usr/bin/env bash
# DocScrub macOS build — run this ON the Mac.
#   ./build_macos.sh            → dist/DocScrub/ + DocScrub-macos.zip
# Requires: Python 3.11+ (brew install python@3.12 works fine)
set -euo pipefail
cd "$(dirname "$0")"

PY=${PY:-python3}
echo "==> Using $($PY --version)"
$PY - <<'EOF'
import sys
assert sys.version_info >= (3, 11), "Python 3.11+ required (scoped regex flags)"
EOF

echo "==> Creating build venv"
$PY -m venv .buildvenv
source .buildvenv/bin/activate

echo "==> Installing dependencies"
pip -q install --upgrade pip
pip -q install presidio-analyzer presidio-anonymizer python-docx pypdf flask \
               openpyxl olefile \
               pyinstaller pywebview

echo "==> Installing spaCy NER model (bundled into the app; skip errors gracefully)"
python -m spacy download en_core_web_sm || echo "   (model download failed — app will run pattern-only)"

echo "==> Building"
pyinstaller docscrub.spec --noconfirm

VERSION=$(python -c "from docscrub import __version__; print(__version__)")

echo "==> Creating DMG installer"
rm -rf dist/dmg && mkdir -p dist/dmg
cp -R dist/DocScrub.app dist/dmg/
ln -s /Applications dist/dmg/Applications
hdiutil create -volname "DocScrub ${VERSION}" -srcfolder dist/dmg \
    -ov -format UDZO "DocScrub-${VERSION}.dmg" \
  && rm -rf dist/dmg \
  || echo "   (hdiutil failed — dist/DocScrub.app still works; drag it to /Applications manually)"

echo
echo "Done!"
echo "  Installer : DocScrub-${VERSION}.dmg  — open it, drag DocScrub into Applications"
echo "  App       : dist/DocScrub.app        — or use directly"
echo "  CLI       : dist/DocScrub.app/Contents/MacOS/DocScrub sanitize ticket.docx"
echo
echo "Note: unsigned build. Fine on the Mac that built it; on ANOTHER Mac:"
echo "  xattr -dr com.apple.quarantine /Applications/DocScrub.app"
