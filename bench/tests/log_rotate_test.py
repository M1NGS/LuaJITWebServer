#!/usr/bin/env python3
"""日志定时切分测试（线程池 rotate）。

用法：python3 log_rotate_test.py <http_port> <access_log>
"""
import http.client
import os
import sys
import time

PORT = int(sys.argv[1])
ACCESS = sys.argv[2]


def get():
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    c.request("GET", "/")
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return f.read().splitlines()


def main():
    print(f"target: {PORT}, access: {ACCESS}")

    # 3 条请求 -> 等一次 rotate（access -> .1）
    for _ in range(3):
        get()
        time.sleep(0.05)
    time.sleep(1.2)

    # 再 1 条 -> 等一次 rotate（.1(3 条) -> .2，access(1 条) -> .1）
    get()
    time.sleep(1.2)

    files = [ACCESS, ACCESS + ".1", ACCESS + ".2"]
    counts = {p: len(lines(p)) for p in files}
    total = sum(counts.values())
    ok = (total == 4 and counts.get(ACCESS + ".1", 0) == 1
          and counts.get(ACCESS + ".2", 0) == 3)
    print("lines per file:", counts)
    print("total lines:", total, "expected: 4 (1 in .1, 3 in .2)")
    for p in files:
        if os.path.exists(p):
            print(f"=== {p} ===")
            for ln in lines(p)[:2]:
                print(" ", ln)
    print("RESULT:", "PASS" if ok else "FAIL")


if __name__ == "__main__":
    main()
