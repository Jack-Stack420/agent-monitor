#!/usr/bin/env bash
# Credentials only in memory or private, temporary HTTP/cookie files; never argv.
set -euo pipefail
set +x
umask 077
base="${MONITOR_URL:-http://127.0.0.1:8787}"
path="${1:?Usage: api_get.sh /api/path}"
[[ "$path" == /api/* && "$path" != *$'\n'* && "$path" != *$'\r'* ]] || { echo 'Expected /api/path' >&2; exit 2; }
tmp=$(mktemp -d)
cleanup(){ curl -sS -b "$tmp/cookies" -o /dev/null -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "csrf@$tmp/csrf" "$base/logout" 2>/dev/null || true; unset password; rm -rf -- "$tmp"; }
trap cleanup EXIT HUP INT TERM
curl -fsS -c "$tmp/cookies" "$base/login" -o "$tmp/page"
python3 - "$tmp/page" "$tmp/csrf" <<'PY'
import re,sys
from pathlib import Path
s=Path(sys.argv[1]).read_text();Path(sys.argv[2]).write_text(re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"',s)[1])
PY
read -r -s -p 'Owner password: ' password; printf '\n' >&2
# Pipe URL-encoded password rather than passing it in process arguments or env.
status=$(printf '%s' "$password" | python3 -c 'import sys,urllib.parse;print("password="+urllib.parse.quote(sys.stdin.read(),safe=""),end="")' | curl -sS -o /dev/null -w '%{http_code}' -b "$tmp/cookies" -c "$tmp/cookies" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- --data-urlencode "csrf@$tmp/csrf" "$base/login")
unset password
[[ "$status" == 302 ]] || { echo 'Invalid credentials' >&2; exit 1; }
curl -fsS -b "$tmp/cookies" "$base/" -o "$tmp/page"
python3 - "$tmp/page" "$tmp/csrf" <<'PY'
import re,sys
from pathlib import Path
s=Path(sys.argv[1]).read_text();Path(sys.argv[2]).write_text(re.search(r'name="cp-csrf" content="([A-Za-z0-9_-]+)"',s)[1])
PY
curl -fsS -b "$tmp/cookies" "$base$path"
