#!/bin/bash
set -euo pipefail
CERT_OPTS=(ext_parse)
NAME_OPTS=(sep_multiline space_eq sname utf8)
CERT_OPTS="$(
  IFS=$','
  echo "${CERT_OPTS[*]}"
)"
NAME_OPTS="$(
  IFS=$','
  echo "${NAME_OPTS[*]}"
)"

FILES="$(grep -Zlnr 'BEGIN CERTIFICATE' certificates)"
TMPFILE="$(mktemp)"
for FILE in $FILES; do
  echo "Rebuild $FILE"
  openssl x509 -text \
    -certopt "$CERT_OPTS" \
    -nameopt "$NAME_OPTS" \
    -in "$FILE" \
    -out "$TMPFILE"
  cp "$TMPFILE" "$FILE"
done
