-- luajit-httpd 业务入口（流式版）。
--
-- handle(req, res)
--   req.method / req.path（已剥离 query）/ req.query / req.headers
--   req.has_body       是否有请求体
--   req.body_size      Content-Length 字节数（无 body 为 0）
--   req.streaming      body 超过自动缓冲阈值（此时 req.body 为 nil）
--   req.body           小 body（<= 1 MiB）为完整字符串；流式时为 nil
--   req:read()         协程式读取请求体，返回 chunk 或 nil
--   req:text(max?)     协程式聚合整个 body（小 body 直接返回 req.body）
--   res:write_head(status?, headers?, content_length?)
--   res:write(chunk) -> ok, queue_bytes
--   res:finish()
--   res:drain()        -- 协程式背压
--   res:queue_size(), res:header_sent()
--   res:set_timeout(sec) -- 本请求 idle 超时；0 = 取消
--
-- 也可以直接返回 { status, headers, body }（兼容旧写法）。

local function handle(req, res)
  if req.path == "/" then
    return {
      status = 200,
      headers = { { "Content-Type", "text/plain" } },
      body = "Hello, World!",
    }
  elseif req.path == "/utf8" then
    return {
      status = 200,
      headers = { { "Content-Type", "text/plain; charset=utf-8" } },
      body = "你好，世界！😀",
    }
  elseif req.path == "/echo" then
    if not req.has_body then
      return {
        status = 400,
        headers = { { "Content-Type", "text/plain" } },
        body = "no request body\n",
      }
    end
    -- 按 Bun 的语义：不区分大小，统一用 text() 消费；小 body 直接返回 req.body
    local body = req:text()
    return {
      status = 200,
      headers = { { "Content-Type", "text/plain; charset=utf-8" } },
      body = body,
    }
  elseif req.path == "/meta" then
    -- 显式三态：has_body / body_size / streaming
    local body = table.concat({
      "has_body=" .. tostring(req.has_body),
      "body_size=" .. tostring(req.body_size),
      "streaming=" .. tostring(req.streaming),
      "buffered=" .. tostring(req.body ~= nil),
    }, " ") .. "\n"
    return {
      status = 200,
      headers = { { "Content-Type", "text/plain" } },
      body = body,
    }
  elseif req.path == "/timeout" then
    -- 对齐 Bun.serve 的 server.timeout(req, sec)：0 = 本请求取消 idle 超时
    res:set_timeout(1)
    return {
      status = 200,
      headers = { { "Content-Type", "text/plain" } },
      body = "timeout set to 1s\n",
    }
  elseif req.path == "/upload" then
    -- 流式接收（小 body 也可以走 read，会从缓冲区交付）
    local n = 0
    while true do
      local chunk = req:read()
      if not chunk then break end
      n = n + #chunk
    end
    return {
      status = 200,
      headers = { { "Content-Type", "text/plain" } },
      body = "received " .. n .. " bytes",
    }
  elseif req.path == "/download" then
    -- 流式下载：未知总长 → HTTP/1.1 自动 chunked；HTTP/1.0 close 定界
    res:write_head(200, { { "Content-Type", "application/octet-stream" } })
    local piece = string.rep("x", 65536)
    for _ = 1, 160 do -- 10 MiB
      local ok = res:write(piece)
      if not ok then res:drain() end
    end
    res:finish()
    return
  elseif req.path == "/download-cl" then
    -- 已知总长：Content-Length 分块写
    local piece = string.rep("y", 65536)
    local n = 160
    res:write_head(200, { { "Content-Type", "application/octet-stream" } }, #piece * n)
    for _ = 1, n do
      local ok = res:write(piece)
      if not ok then res:drain() end
    end
    res:finish()
    return
  elseif req.path == "/events" then
    -- SSE：chunked 持续推送；长流取消 idle 超时（长时间没有新事件也不会被掐断）
    res:set_timeout(0)
    res:write_head(200, {
      { "Content-Type", "text/event-stream" },
      { "Cache-Control", "no-cache" },
    })
    for i = 1, 20 do
      res:write("data: tick " .. i .. "\n\n")
      res:drain()
    end
    res:finish()
    return
  else
    return {
      status = 404,
      headers = { { "Content-Type", "text/plain" } },
      body = "Not Found\n",
    }
  end
end

return { handle = handle }
