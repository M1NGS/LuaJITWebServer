-- wrk 的 Lua 脚本：所有候选收到相同的请求形状。
wrk.method = "GET"
wrk.headers["Accept"] = "*/*"
wrk.headers["User-Agent"] = "bench-wrk"
