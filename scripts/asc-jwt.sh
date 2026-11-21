#!/usr/bin/env bash
# Prints a 10-minute App Store Connect API token (JWT, ES256) from ASC_KEY_P8 (base64),
# ASC_KEY_ID and ASC_ISSUER_ID. Uses only openssl and python3's standard library.
set -euo pipefail
umask 077
tmp="${RUNNER_TEMP:-/tmp}"
KEY="$tmp/k.p8"
printf '%s' "$ASC_KEY_P8" | base64 --decode > "$KEY"
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
header=$(printf '{"alg":"ES256","kid":"%s","typ":"JWT"}' "$ASC_KEY_ID" | b64url)
payload=$(printf '{"iss":"%s","iat":%d,"exp":%d,"aud":"appstoreconnect-v1"}' "$ASC_ISSUER_ID" "$now" "$((now + 600))" | b64url)
printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$KEY" -binary > "$tmp/sig.der"
rm -f "$KEY"
# DER ECDSA signature -> raw r||s, as JWT ES256 requires
sig=$(python3 -I -c '
import sys
d = open(sys.argv[1], "rb").read()
i = 2 if d[1] < 0x80 else 2 + (d[1] & 0x7f)
v = []
while i < len(d):
    n = d[i + 1]
    v.append(int.from_bytes(d[i + 2:i + 2 + n], "big"))
    i += 2 + n
sys.stdout.buffer.write(v[0].to_bytes(32, "big") + v[1].to_bytes(32, "big"))
' "$tmp/sig.der" | b64url)
rm -f "$tmp/sig.der"
printf '%s.%s.%s' "$header" "$payload" "$sig"
