#!/usr/bin/env bash
# 基准驱动：启动 pico 服务器，用 wrk 压测，保存原始输出。
# 用法：bash run.sh [pico]
# 环境变量：BENCH_HOST/PORT/THREADS/CONNS/DURATION/REPEAT
#           BENCH_WRK_EXTRA（额外 wrk 参数，如 --latency）
#           BENCH_RESULTS（结果目录，默认 bench/results）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH="$ROOT/bench"; PREFIX="$ROOT/prefix"; SRC="$ROOT/src"
HOST="${BENCH_HOST:-127.0.0.1}"
PORT="${BENCH_PORT:-8080}"
THREADS="${BENCH_THREADS:-4}"
CONNS="${BENCH_CONNS:-100}"
DURATION="${BENCH_DURATION:-20s}"
REPEAT="${BENCH_REPEAT:-3}"
WRK_EXTRA="${BENCH_WRK_EXTRA:-}"
RESULTS="${BENCH_RESULTS:-$BENCH/results}"
LOGS="$BENCH/logs"
mkdir -p "$RESULTS" "$LOGS"

export PATH="$PREFIX/luajit/bin:$SRC/wrk:$PATH"
export LD_LIBRARY_PATH="$PREFIX/luajit/lib:${LD_LIBRARY_PATH:-}"
eval "$("$PREFIX/luarocks/bin/luarocks" path --bin)" 2>/dev/null || true
export LUA_PATH="${LUA_PATH:-;;};$PREFIX/luajit/share/luajit-2.1/?.lua;$SRC/wrk/src/?.lua"

server_cmd() {
  case "$1" in
    pico)    echo "env PICO_SO='$PREFIX/pico/lib/libpicohttpparser.so' luajit '$BENCH/servers/pico.lua'" ;;
    c-httpd) echo "'$PREFIX/c-httpd/bin/luajit-httpd' '$ROOT/src/app.lua' $PORT" ;;
    *) echo "" ;;
  esac
}

wait_port() {
  local i
  for i in $(seq 1 150); do
    if curl -s -o /dev/null -m 1 "http://$HOST:$PORT/" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(pico)
fi

for name in "${targets[@]}"; do
  cmd="$(server_cmd "$name")"
  if [ -z "$cmd" ]; then echo "unknown candidate: $name"; continue; fi
  for r in $(seq 1 "$REPEAT"); do
    out="$RESULTS/$name-run$r.txt"
    slog="$LOGS/$name-server.log"
    echo ">>> $name run $r: $cmd"
    bash -c "exec $cmd" >"$slog" 2>&1 &
    pid=$!
    if ! wait_port; then
      echo "!! $name failed to start; server log:"
      tail -20 "$slog"
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      continue 2
    fi
    wrk $WRK_EXTRA -t"$THREADS" -c"$CONNS" -d"$DURATION" -s "$BENCH/bench.lua" "http://$HOST:$PORT/" | tee "$out"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    sleep 0.5
  done
done
echo "results saved under $RESULTS"
