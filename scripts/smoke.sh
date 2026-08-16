#!/usr/bin/env sh
set -eu

BASE_URL="${ZCI_BASE_URL:-http://127.0.0.1:8080}"

printf 'health: '
curl -fsS "$BASE_URL/health" >/dev/null
echo ok

printf 'schema: '
curl -fsS "$BASE_URL/api/v1/schema" >/dev/null
echo ok

printf 'probe.js: '
curl -fsS "$BASE_URL/probe.js" >/dev/null
echo ok

printf 'inspect: '
curl -fsS "$BASE_URL/inspect" >/dev/null
echo ok
