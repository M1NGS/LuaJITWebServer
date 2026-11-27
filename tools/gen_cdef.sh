#!/usr/bin/env bash
# 从 src/httpd_config.h 的 CDEF-BEGIN..CDEF-END 标记段生成 LuaJIT ffi 用的
# src/config_cdef.lua。生成物不要手改，只改头文件。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HDR="$ROOT/src/httpd_config.h"
OUT="$ROOT/src/config_cdef.lua"

if [ ! -f "$HDR" ]; then
  echo "missing $HDR" >&2
  exit 1
fi

tmp="$OUT.tmp"
{
  printf -- '-- generated from src/httpd_config.h by tools/gen_cdef.sh; do not edit\n'
  printf -- 'return [[\n'
  sed -n '/^\/\* CDEF-BEGIN \*\/$/,/^\/\* CDEF-END \*\/$/p' "$HDR" \
    | sed '/^\/\* CDEF-BEGIN \*\/$/d;/^\/\* CDEF-END \*\/$/d'
  printf -- ']]\n'
} >"$tmp"
mv "$tmp" "$OUT"
echo "generated $OUT"
