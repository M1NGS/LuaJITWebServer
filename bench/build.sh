#!/usr/bin/env bash
# 从源码构建 luajit-httpd（C + libuv + picohttpparser + LuaJIT + mbedTLS）及辅助工具（不使用 apt）。
# 用法：bash build.sh [luajit|luarocks|luv|wrk|libuv|pico|mbedtls|c-httpd] ...
# 不带参数时构建全部。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/src"; PREFIX="$ROOT/prefix"; LOGS="$ROOT/bench/logs"
JOBS="${JOBS:-$(nproc)}"
LUAJIT="$PREFIX/luajit"; LUAROCKS="$PREFIX/luarocks"
mkdir -p "$SRC" "$PREFIX" "$LOGS"

log() { printf '\n===== %s: %s =====\n' "$(date +%H:%M:%S)" "$*"; }

run() {
  local name="$1"; shift
  if "$@" >"$LOGS/$name.log" 2>&1; then
    log "OK $name"
  else
    local rc=$?
    log "FAILED $name (exit $rc)"; tail -40 "$LOGS/$name.log"; exit 1
  fi
}

clone() {
  local url="$1" dir="$2" ref="${3:-}"
  if [ -d "$dir/.git" ]; then
    git -C "$dir" fetch -q --tags --depth 1 origin || true
  elif [ -n "$ref" ]; then
    git clone -q --depth 1 --branch "$ref" "$url" "$dir"
  else
    git clone -q --depth 1 "$url" "$dir"
  fi
  [ -z "$ref" ] || git -C "$dir" checkout -q "$ref"
  log "$dir @ $(git -C "$dir" rev-parse --short HEAD)"
}

tarball() {
  local url="$1" dir="$2"
  if [ -d "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then
    log "$dir already present, skip download"
    return 0
  fi
  mkdir -p "$dir"
  curl -fsSL --max-time 300 -o "$dir/src.tar.gz" "$url"
  tar -xzf "$dir/src.tar.gz" -C "$dir" --strip-components=1
  rm -f "$dir/src.tar.gz"
  log "unpacked $url -> $dir"
}

rocks() { env PATH="$LUAJIT/bin:$PATH" "$LUAROCKS/bin/luarocks" "$@"; }

build_luajit() {
  clone https://github.com/LuaJIT/LuaJIT.git "$SRC/LuaJIT"
  run luajit make -C "$SRC/LuaJIT" -j"$JOBS"
  run luajit-install make -C "$SRC/LuaJIT" install PREFIX="$LUAJIT"
  "$LUAJIT/bin/luajit" -v
}

build_luarocks() {
  tarball https://github.com/luarocks/luarocks/archive/refs/tags/v3.13.0.tar.gz "$SRC/luarocks"
  run luarocks-configure bash -c 'cd "$1" && ./configure --prefix="$2" --force-config --lua-version=5.1 --with-lua="$3" --with-lua-bin="$3/bin" --with-lua-include="$3/include/luajit-2.1" --with-lua-lib="$3/lib" --with-lua-interpreter=luajit' _ \
    "$SRC/luarocks" "$LUAROCKS" "$LUAJIT"
  run luarocks-make make -C "$SRC/luarocks" build
  run luarocks-install make -C "$SRC/luarocks" install
  "$LUAROCKS/bin/luarocks" --version | head -1 || true
}

build_luv() {
  run luv-install rocks install luv
  rocks list luv
}

build_wrk() {
  tarball https://github.com/wg/wrk/archive/refs/tags/4.1.0.tar.gz "$SRC/wrk"
  local d="$SRC/wrk"
  rm -rf "$d/obj"
  mkdir -p "$d/obj"
  run wrk-bytecode env PATH="$LUAJIT/bin:$PATH" LUA_PATH="$LUAJIT/share/luajit-2.1/?.lua;;" luajit -b "$d/src/wrk.lua" "$d/obj/bytecode.o"
  run wrk-version bash -c 'printf "const char *VERSION=\"4.1.0\";\n" | gcc -xc -c -o "$1" -' _ "$d/obj/version.o"
  run wrk gcc -std=c99 -Wall -O2 -D_REENTRANT -D_POSIX_C_SOURCE=200112L -D_BSD_SOURCE -D_DEFAULT_SOURCE \
    -I"$LUAJIT/include/luajit-2.1" \
    "$d/src/wrk.c" "$d/src/net.c" "$d/src/ssl.c" "$d/src/aprintf.c" "$d/src/stats.c" \
    "$d/src/script.c" "$d/src/units.c" "$d/src/ae.c" "$d/src/zmalloc.c" "$d/src/http_parser.c" \
    "$d/obj/bytecode.o" "$d/obj/version.o" \
    -o "$d/wrk" -lpthread -lm -ldl -L"$LUAJIT/lib" -lluajit-5.1 -lssl -lcrypto
  env LD_LIBRARY_PATH="$LUAJIT/lib" "$d/wrk" --version 2>&1 | head -1 || true
}

build_libuv() {
  if [ ! -d "$SRC/libuv/.git" ]; then
    git clone -q --depth 1 --branch v1.53.0 https://github.com/libuv/libuv.git "$SRC/libuv"
  fi
  run libuv-cmake cmake -S "$SRC/libuv" -B "$SRC/libuv/build" \
    -DCMAKE_BUILD_TYPE=Release -DLIBUV_BUILD_TESTS=OFF -DLIBUV_BUILD_BENCH=OFF -DBUILD_SHARED_LIBS=OFF
  run libuv-build cmake --build "$SRC/libuv/build" -j"$JOBS"
  mkdir -p "$PREFIX/libuv/lib" "$PREFIX/libuv/include"
  cp "$SRC/libuv/build/libuv.a" "$PREFIX/libuv/lib/"
  cp "$SRC/libuv/include/uv.h" "$PREFIX/libuv/include/"
  cp -r "$SRC/libuv/include/uv" "$PREFIX/libuv/include/"
}

build_pico() {
  clone https://github.com/h2o/picohttpparser.git "$SRC/picohttpparser"
  mkdir -p "$PREFIX/pico/lib"
  run pico gcc -O2 -fPIC -shared "$SRC/picohttpparser/picohttpparser.c" \
    -o "$PREFIX/pico/lib/libpicohttpparser.so"
  cp "$SRC/picohttpparser/picohttpparser.h" "$PREFIX/pico/lib/"
}

build_mbedtls() {
  local d="$SRC/mbedtls"
  if [ ! -f "$d/CMakeLists.txt" ]; then
    mkdir -p "$d"
    curl -fsSL --max-time 300 -o "$d/src.tar.bz2" \
      "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.8/mbedtls-3.6.8.tar.bz2"
    tar -xjf "$d/src.tar.bz2" -C "$d" --strip-components=1
    rm -f "$d/src.tar.bz2"
    log "unpacked mbedtls-3.6.8 -> $d"
  fi
  run mbedtls-cmake cmake -S "$d" -B "$d/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF \
    -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
    -DCMAKE_INSTALL_PREFIX="$PREFIX/mbedtls"
  run mbedtls-build cmake --build "$d/build" -j"$JOBS"
  run mbedtls-install cmake --install "$d/build"
  ls "$PREFIX/mbedtls/lib"
}

build_c_httpd() {
  local out="$PREFIX/c-httpd/bin"
  mkdir -p "$out"
  if [ ! -f "$PREFIX/mbedtls/lib/libmbedtls.a" ]; then
    build_mbedtls
  fi
  run c-httpd gcc -O2 -DNDEBUG -o "$out/luajit-httpd" \
    "$ROOT/src/httpd.c" "$SRC/picohttpparser/picohttpparser.c" \
    -I"$SRC/picohttpparser" -I"$PREFIX/libuv/include" -I"$LUAJIT/include/luajit-2.1" \
    -I"$PREFIX/mbedtls/include" \
    -L"$PREFIX/libuv/lib" -L"$LUAJIT/lib" -L"$PREFIX/mbedtls/lib" \
    -lluajit-5.1 -luv -lmbedtls -lmbedx509 -lmbedcrypto -lm -ldl -lpthread -lrt
}

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(luajit luarocks luv wrk libuv pico mbedtls c-httpd)
fi
for t in "${targets[@]}"; do
  log ">>> build $t"
  "build_${t//-/_}"
done
log "done: ${targets[*]}"
