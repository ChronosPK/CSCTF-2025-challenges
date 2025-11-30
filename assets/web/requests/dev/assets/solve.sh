#!/usr/bin/env bash
# Walk the Requests-only API to fetch the flag.
set -euo pipefail

HOST=${HOST:-localhost}
PORT=${PORT:-8000}
BASE="http://$HOST:$PORT"

echo "[+] Getting token" >&2
TOK=$(curl -s "$BASE/auth/token?flow=bootstrap" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

echo "[+] Creating ticket" >&2
resp=$(curl -s -i -H "Authorization: Bearer $TOK" \
  -H "Content-Type: application/json" \
  -d '{"component":"api","summary":"test"}' "$BASE/tickets")
TID=$(echo "$resp" | sed -n 's/.*"ticket_id":"\([^"]*\)".*/\1/p')
ETAG=$(echo "$resp" | awk '/ETag:/{gsub(/"/,"",$2);print $2}')

echo "[+] Reading requirements" >&2
req=$(curl -s -H "Authorization: Bearer $TOK" "$BASE/tickets/$TID/requirements")
NONCE=$(echo "$req" | sed -n 's/.*bytes_exact":"'"$TID"':\([0-9a-f]\{12\}\)".*/\1/p')
[ -n "$NONCE" ] || { echo "[-] nonce not found in requirements"; exit 1; }

echo -n "$TID:$NONCE" > artifact.txt
SHA=$(sha256sum artifact.txt | cut -d' ' -f1)
SZ=$(stat -c%s artifact.txt)
cat > manifest.txt <<EOF
ticket_id=$TID
artifact_sha256=$SHA
artifact_size=$SZ
EOF

echo "[+] Uploading" >&2
curl -s -i -H "Authorization: Bearer $TOK" \
  -H "If-Match: \"$ETAG\"" \
  -F "file=@artifact.txt;type=text/plain" \
  -F "manifest=@manifest.txt;type=text/plain; charset=utf-8" \
  "$BASE/upload/$TID" >&2

echo "[+] Fetching flag" >&2
curl -s -H "Authorization: Bearer $TOK" -H "Accept: application/json" "$BASE/flag?ticket=$TID"
