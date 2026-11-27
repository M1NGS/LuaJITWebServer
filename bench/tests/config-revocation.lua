-- 吊销表 mock 测试配置（pgsql 配置形态，数据来自 mock_file）
local dir = os.getenv("TEST_MTLS_DIR") or "/tmp/httpd-mtls"
local revoked = os.getenv("TEST_REVOKED_FILE") or "/tmp/httpd-revoked.txt"
local http_port = tonumber(os.getenv("TEST_HTTP_PORT") or "18084")
local https_port = tonumber(os.getenv("TEST_HTTPS_PORT") or "18446")

local function p(name) return dir .. "/" .. name end

return {
  server = {
    listen = {
      { host = "127.0.0.1", port = http_port },
      { host = "127.0.0.1", port = https_port, tls = true },
    },
    tls = {
      cert = p("default-server.crt"),
      key = p("default-server.key"),
      ca = p("ca-a.crt"),
      client_auth = true,
      min_version = "1.2",
      sni = {
        { server_name = "a.example.test", cert = p("a-server.crt"), key = p("a-server.key"),
          ca = p("ca-a.crt"), client_auth = true },
        { server_name = "b.example.test", cert = p("b-server.crt"), key = p("b-server.key"),
          ca = p("ca-b.crt"), client_auth = true },
        { server_name = "public.example.test", cert = p("public-server.crt"),
          key = p("public-server.key"), client_auth = false },
        { server_name = "inherit.example.test", cert = p("a-server.crt"),
          key = p("a-server.key"), client_auth = true },
      },
    },
    tcp = { nodelay = true, keepalive = false, backlog = 1024 },
    limits = { max_body = 64 * 1024 * 1024, idle_timeout = 30 },
  },

  revocation = {
    enabled = true,
    key = "sha256",
    interval = 1,               -- 定时从 provider 拉取（秒）
    load_on_start = true,
    max_bytes = 64 * 1024 * 1024,
    max_entries = 500000,
    on_error = "keep",
    provider = {
      type = "pgsql",           -- 目标形态；P1 用 mock_file 代替直连
      dsn = "postgresql://mock/revoked",
      sql = "SELECT fingerprint_sha256 FROM revoked_client_certs",
      mock_file = revoked,
    },
  },

  app = "src/app.lua",
}
