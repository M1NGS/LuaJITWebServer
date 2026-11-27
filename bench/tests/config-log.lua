-- 日志功能测试配置（固定 nginx 风格 access/error）
local cert = os.getenv("TEST_CERT") or "/tmp/httpd-certs/cert.pem"
local key  = os.getenv("TEST_KEY")  or "/tmp/httpd-certs/key.pem"
local http_port  = tonumber(os.getenv("TEST_HTTP_PORT") or "18085")
local https_port = tonumber(os.getenv("TEST_HTTPS_PORT") or "18447")
local access = os.getenv("TEST_ACCESS_LOG") or "/tmp/httpd-logs/access.log"
local error_log = os.getenv("TEST_ERROR_LOG") or "/tmp/httpd-logs/error.log"

return {
  server = {
    listen = {
      { host = "127.0.0.1", port = http_port },
      { host = "127.0.0.1", port = https_port, tls = true },
    },
    tls = { cert = cert, key = key, min_version = "1.2" },
    tcp = { nodelay = true, backlog = 1024 },
    limits = { max_body = 64 * 1024 * 1024, idle_timeout = 30 },
  },
  log = {
    access = access,
    error = error_log,
    level = "info",
    flush_interval = 0.1,
    max_buffer = 4 * 1024 * 1024,
  },
  app = "src/app.lua",
}
