"""Rerun: python3 download_fonts.py (official pinned Latin WOFF2 + OFL only)."""
from pathlib import Path
import hashlib
import urllib.request
from datetime import date
ROOT = Path(__file__).resolve().parent / 'web' / 'fonts'
FILES = {
 'chakra-petch-500-latin.woff2': 'https://fonts.gstatic.com/s/chakrapetch/v13/cIflMapbsEk7TDLdtEz1BwkebIl1R5_F.woff2',
 'chakra-petch-600-latin.woff2': 'https://fonts.gstatic.com/s/chakrapetch/v13/cIflMapbsEk7TDLdtEz1BwkeQI51R5_F.woff2',
 'chakra-petch-700-latin.woff2': 'https://fonts.gstatic.com/s/chakrapetch/v13/cIflMapbsEk7TDLdtEz1BwkeJI91R5_F.woff2',
 'share-tech-mono-400-latin.woff2': 'https://fonts.gstatic.com/s/sharetechmono/v16/J7aHnp1uDWRBEqV98dVQztYldFcLowEF.woff2',
 'Chakra-Petch-OFL.txt': 'https://raw.githubusercontent.com/google/fonts/main/ofl/chakrapetch/OFL.txt',
 'Share-Tech-Mono-OFL.txt': 'https://raw.githubusercontent.com/google/fonts/main/ofl/sharetechmono/OFL.txt',
}
CSS = 'https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=Share+Tech+Mono&display=swap&subset=latin'
if __name__ == '__main__':
 ROOT.mkdir(exist_ok=True)
 rows = []
 for name, url in FILES.items():
  body = urllib.request.urlopen(url, timeout=30).read()
  if name.endswith('.woff2'):
   assert body[:4] == b'wOF2'
  else:
   assert b'SIL OPEN FONT LICENSE' in body
  (ROOT / name).write_bytes(body)
  rows.append(f'| {name} | {url} | {date.today()} | {hashlib.sha256(body).hexdigest()} |')
 (ROOT / 'SOURCES.md').write_text(chr(10).join(['# Official font sources', '', 'CSS manifest: ' + CSS, '', 'Latin subset includes U+2000-206F available glyphs.', 'Rerun: python3 download_fonts.py', '', '| File | Source | Download date | SHA256 |', '|---|---|---|---|', *rows, '']))
