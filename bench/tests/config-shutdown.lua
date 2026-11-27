-- 优雅退出测试配置
local port = tonumber(os.getenv("TEST_HTTP_PORT") or "18087")

return {
  server = {
    listen = { { host = "127.0.0.1", port = port } },
    limits = {
      max_body = 64 * 1024 * 1024,
      idle_timeout = 30,
      shutdown_timeout = 2,   -- 秒；0 = 一直等
    },
  },
  app = "src/app.lua",
}
