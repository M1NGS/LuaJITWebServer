#!/usr/bin/env bash
# 把 Lua 基础设施库编译成 LuaJIT 字节码，并转成 C 头文件（构建产物，不要手改）。
#
# - 字节码用 luajit -b -s（strip 调试信息），不把源码嵌进二进制；
# - .o 方案只有 luaJIT_BC_<name> 符号、没有长度符号，因此这里生成 .h：
#   数组 + <name>_len，C 直接 luaL_loadbuffer 注入。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LUAJIT="${LUAJIT:-$ROOT/prefix/luajit/bin/luajit}"
SRC="$ROOT/src"

if [ ! -x "$LUAJIT" ]; then
  echo "missing $LUAJIT; build luajit first (bash bench/build.sh luajit)" >&2
  exit 1
fi

# luajit -b 通过 require("jit.bcsave") 工作，需要安装后的 jit 模块路径
export LUA_PATH="$ROOT/prefix/luajit/share/luajit-2.1/?.lua;;"

gen_one() {
  local lua="$1" name="$2"
  local bc="$SRC/$name.bc" hdr="$SRC/${name}_bc.h"
  "$LUAJIT" -b -s "$lua" "$bc"
  if command -v xxd >/dev/null 2>&1; then
    xxd -i -n "luaJIT_BC_$name" "$bc" \
      | sed 's/^unsigned char /static const unsigned char /; s/^unsigned int /static const unsigned int /' \
      >"$hdr"
  else
    {
      echo "static const unsigned char luaJIT_BC_$name[] = {"
      od -An -v -tx1 "$bc" | awk '{ for (i = 1; i <= NF; i++) printf "0x%s,", $i; print "" }'
      echo "};"
      echo "static const unsigned int luaJIT_BC_${name}_len = $(stat -c %s "$bc");"
    } >"$hdr"
  fi
  echo "generated $bc + $hdr"
}

gen_one "$SRC/config_cdef.lua" "config_cdef"
gen_one "$SRC/httpd_config.lua" "httpd_config"
