-- 日志定时切分测试配置
local access = os.getenv("TEST_ACCESS_LOG") or "/tmp/httpd-logs-rotate/access.log"
local error_log = os.getenv("TEST_ERROR_LOG") or "/tmp/httpd-logs-rotate/error.log"
local port = tonumber(os.getenv("TEST_HTTP_PORT") or "18086")

return {
  server = {
    listen = { { host = "127.0.0.1", port = port } },
    limits = { max_body = 64 * 1024 * 1024, idle_timeout = 30 },
  },
  log = {
    access = access,
    error = error_log,
    level = "info",
    flush_interval = 0.1,
    max_buffer = 4 * 1024 * 1024,
    rotate_interval = 1,   -- 秒
    rotate_size = 0,
    rotate_keep = tonumber(os.getenv("TEST_ROTATE_KEEP") or "2"),  -- 0 = truncate
  },
  app = "src/app.lua",
}
