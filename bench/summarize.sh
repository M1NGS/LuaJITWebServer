#!/usr/bin/env bash
# 汇总 bench/results/*.txt 里的 wrk 输出，打印每次运行的 QPS 与延迟，
# 并在最后给出每个候选的 QPS 中位数（3 次运行取中位）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
R="$ROOT/bench/results"

printf "%-18s %-4s %10s %9s %9s %9s %9s\n" "candidate" "run" "req/sec" "avg" "p50" "p99" "max"
for f in "$R"/*.txt; do
  [ -e "$f" ] || continue
  base=$(basename "$f" .txt)
  name=${base%-run*}
  run=${base##*-run}
  qps=$(grep -m1 "Requests/sec:" "$f" | awk '{print $2}' || true)
  avg=$(grep -m1 -E "^    Latency" "$f" | awk '{print $2}' || true)
  p50=$(grep -m1 -E "^     50%" "$f" | awk '{print $2}' || true)
  p99=$(grep -m1 -E "^     99%" "$f" | awk '{print $2}' || true)
  max=$(grep -m1 -E "^    Latency" "$f" | awk '{print $4}' || true)
  printf "%-18s %-4s %10s %9s %9s %9s %9s\n" "$name" "$run" "$qps" "$avg" "$p50" "$p99" "$max"
  if grep -q "Socket errors" "$f"; then
    grep -m1 "Socket errors" "$f" | sed 's/^/    /'
  fi
done

echo
echo "== QPS median per candidate =="
for name in $(ls "$R"/*.txt 2>/dev/null | sed -E 's#.*/([^/]*)-run[0-9]+\.txt#\1#' | sort -u); do
  vals=$(grep -h -m1 "Requests/sec:" "$R/$name"-run*.txt 2>/dev/null | awk '{print $2}' | sort -n)
  n=$(printf '%s\n' "$vals" | wc -l)
  mid=$(( (n + 1) / 2 ))
  median=$(printf '%s\n' "$vals" | sed -n "${mid}p")
  printf "%-18s n=%s median=%s  (%s)\n" "$name" "$n" "$median" "$(printf '%s\n' "$vals" | tr '\n' ' ')"
done
